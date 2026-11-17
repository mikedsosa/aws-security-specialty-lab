# Runbook: S3 Block Public Access disabled with a leaked access key

Study runbook for SCS-C03 Domain 2 (Skills 2.1.1, 2.2.1 to 2.2.5). It follows the phases in the
[AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
and maps to the Respond and Recover functions referenced by
[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). None of these commands were run
against AWS for this lab. Account IDs, names and keys are placeholders.

## Scenario

A long-lived access key for IAM user `example-dev` in member account 777788889999 is pasted into a
public repository. Within the hour, someone uses it from an unfamiliar IP address (203.0.113.10) to call
`DeleteBucketPublicAccessBlock` on `scs-lab-app-data`, then `PutBucketPolicy` to grant `s3:GetObject`
to `"Principal": "*"`.

Signals this lab is built to produce:

| Signal | Source |
| --- | --- |
| GuardDuty `Policy:S3/BucketBlockPublicAccessDisabled` (default severity Low per GuardDuty docs) | `terraform/detection.tf` |
| CloudTrail `DeleteBucketPublicAccessBlock` event routed by EventBridge | `terraform/event-patterns/s3-bpa-api-change.json` |
| Lambda log line `{"action": "restored", ...}` | `lambda/remediate_s3_bpa/handler.py` |
| Security Hub CSPM finding from the FSBP standard | `terraform/detection.tf` |

The Lambda turns bucket-level Block Public Access back on, which neutralizes a public bucket policy
(`RestrictPublicBuckets`) and public ACLs. It does not delete the attacker's bucket policy or disable the
key. Those are human steps below.

## Roles

| Role | Who |
| --- | --- |
| Incident lead | On-call security engineer |
| Account owner | Owner of account 777788889999 |
| Comms | Per the organization's IR plan |

Responders use `SecurityLogReader` (read) and `BreakGlassAdmin` (write, logged and alerted). Write steps
with `BreakGlassAdmin` are needed only where the SCP denies normal roles.

## 1. Detection and analysis

1. Confirm the finding and capture it as evidence.

   ```bash
   aws guardduty list-findings --detector-id <detector-id> \
     --finding-criteria '{"Criterion":{"type":{"Eq":["Policy:S3/BucketBlockPublicAccessDisabled"]}}}'
   aws guardduty get-findings --detector-id <detector-id> --finding-ids <id> > evidence/finding.json
   ```

2. Identify the access key and principal from the finding (`resource.accessKeyDetails`) or the CloudTrail
   event (`userIdentity.accessKeyId`).
3. Scope what the key did. Management events, last 90 days, in the affected Region:

   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key-id> \
     --max-results 50 > evidence/lookup-events.json
   ```

   For the full organization trail, query the logs in S3 with Athena (illustrative, adjust to your table):

   ```sql
   SELECT eventtime, eventsource, eventname, sourceipaddress, requestparameters
   FROM cloudtrail_logs
   WHERE useridentity.accesskeyid = '<key-id>'
   ORDER BY eventtime;
   ```

4. Check current exposure of the bucket.

   ```bash
   aws s3api get-public-access-block --bucket scs-lab-app-data
   aws s3api get-bucket-policy-status --bucket scs-lab-app-data
   aws s3api get-bucket-policy --bucket scs-lab-app-data > evidence/bucket-policy.json
   ```

5. Decide whether objects were read. Management events do not show `GetObject`. You need S3 data events
   (CloudTrail) or server access logs for the bucket. If neither was on, record that the read scope is
   unknown. Do not report "no data accessed".
6. Prove the logs you rely on were not altered:

   ```bash
   aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:111122223333:trail/scs-lab-org-trail \
     --start-time <iso-time> --verbose > evidence/validate-logs.txt
   ```

## 2. Containment

Order matters: stop the credential first, then close the exposure.

1. Deactivate (do not yet delete) the key, so it stays available for the investigation record.

   ```bash
   aws iam update-access-key --user-name example-dev --access-key-id <key-id> --status Inactive
   ```

2. If the attacker may have minted temporary credentials with that key (`GetSessionToken`,
   `AssumeRole`), attach an inline deny on the user and on any assumed roles for tokens issued before now,
   using the `aws:TokenIssueTime` condition key.
3. Confirm the Lambda restored Block Public Access (step 1.4 again). If it did not run, restore it by hand:

   ```bash
   aws s3api put-public-access-block --bucket scs-lab-app-data --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```

4. Remove the attacker's bucket policy statement. Keep the copy saved in evidence.

## 3. Eradication

1. Delete the leaked key after the evidence is captured. Remove it from the public repository and treat
   the repository history as exposed. Rotating the key is required; deleting the commit is not enough.
2. Look for persistence the key could have created: new IAM users, access keys, login profiles, roles,
   trust policy changes, Lambda functions, EventBridge rules, and changes to the remediation itself
   (`lookup-events` filtered on `iam.amazonaws.com` and `events.amazonaws.com`).
3. Replace the long-lived key with a role and short-lived credentials (IAM Identity Center or IAM Roles
   Anywhere) so there is no static key to leak.

## 4. Recovery

1. Confirm `get-bucket-policy-status` reports `IsPublic: false`.
2. If objects were changed or deleted, restore previous versions (the lab buckets use versioning).
3. Keep heightened monitoring on the account for 30 days: GuardDuty findings for the principal and IP.

## 5. Post-incident

- Was the Lambda's time to restore acceptable? Measure from the CloudTrail `eventTime` to the Lambda log.
- Would an SCP denying `s3:PutBucketPublicAccessBlock` for non-break-glass roles have prevented it? What
  would it break?
- Were S3 data events on for sensitive buckets? If not, decide whether the cost is worth the evidence.
- Test the runbook: replay `tests/events/*.json` through the handler (`pytest tests/test_remediation.py`),
  and, in a sandbox account you own, use GuardDuty sample findings.

# Exercises

Every exercise runs offline. "Expected" is what this repository produced when the command was run on
November 17, 2026; nothing here was checked against a real AWS account. Run commands from the repo
root after setup, with `PYTHONPATH=src`. The policy checker is a teaching tool that supports a subset
of IAM grammar (see `src/scs_lab/policy_eval.py`); it is not the AWS engine.

```bash
export PYTHONPATH=src
alias check='.venv/bin/python -m scs_lab check'
```

## 1. SCP guardrails (Skill 6.1.3)

Read `terraform/policies/scp-guardrails.json.tftpl`, predict each result, then run:

```bash
check --policy scp-guardrails --action cloudtrail:StopLogging \
  --context aws:PrincipalArn=arn:aws:iam::777788889999:role/Developer --context aws:RequestedRegion=us-east-1
check --policy scp-guardrails --action cloudtrail:StopLogging \
  --context aws:PrincipalArn=arn:aws:iam::777788889999:role/BreakGlassAdmin --context aws:RequestedRegion=us-east-1
check --policy scp-guardrails --action ec2:RunInstances \
  --context aws:PrincipalArn=arn:aws:iam::777788889999:role/Developer --context aws:RequestedRegion=eu-west-1
check --policy scp-guardrails --action iam:CreateRole \
  --context aws:PrincipalArn=arn:aws:iam::777788889999:role/Developer --context aws:RequestedRegion=eu-west-1
```

Expected: `explicit_deny` (ProtectSecurityTelemetry), `no_match`, `explicit_deny` (DenyUnapprovedRegions),
`no_match` (IAM is in the region statement's `NotAction` list).

Questions:

- `no_match` from an SCP is not "allow". What else must be true for the break-glass call to succeed?
  (An allow from an attached SCP such as FullAWSAccess, plus an identity policy allow.)
- Leave out `aws:RequestedRegion` and run the last command again. The result becomes `explicit_deny`,
  because a negated operator is true when the key is missing (IAM condition operator docs). Real requests
  carry this key; the point is to read negated conditions carefully.
- Why does this SCP not protect the organization trail itself? (SCPs do not affect users or roles in the
  management account, and the organization trail lives there.)

## 2. RCP data perimeter (Skills 6.1.3, 5.1.1)

```bash
check --policy rcp-data-perimeter --action s3:GetObject --resource arn:aws:s3:::scs-lab-app-data/report.csv \
  --principal-arn arn:aws:iam::777788889999:role/Developer \
  --context aws:SecureTransport=false --context aws:PrincipalOrgID=o-exampleorg1
check --policy rcp-data-perimeter --action s3:GetObject --resource arn:aws:s3:::scs-lab-app-data/report.csv \
  --context aws:SecureTransport=true
check --policy rcp-data-perimeter --action s3:PutObject --resource arn:aws:s3:::scs-lab-app-data/x \
  --principal-service cloudtrail.amazonaws.com \
  --context aws:SecureTransport=true --context aws:PrincipalIsAWSService=true
```

Expected: `explicit_deny` (EnforceSecureTransport), `explicit_deny` (EnforceOrgIdentitiesOnS3, an anonymous
caller has no `aws:PrincipalOrgID`), `no_match` (AWS service principals pass `BoolIfExists`).

Questions: RCPs do not affect resources in the management account, and do not apply to calls made by
service-linked roles (Organizations RCP docs). Where would you put the trail bucket so the RCP covers it?

## 3. Organization trail integrity (Skills 1.2.2, 5.2.2)

Break the configuration in a scratch copy and let the scanner catch it:

```bash
rm -rf /tmp/mut && mkdir /tmp/mut && cp terraform/*.tf /tmp/mut/ && cp -r terraform/policies terraform/event-patterns /tmp/mut/
sed -i 's/enable_log_file_validation    = true/enable_log_file_validation    = false/; s/enable_key_rotation     = true/enable_key_rotation     = false/' /tmp/mut/logging.tf
.venv/bin/checkov -d /tmp/mut --framework terraform --check CKV_AWS_36,CKV_AWS_7 --compact
```

Expected: `Passed checks: 0, Failed checks: 2` with CKV_AWS_7 on `aws_kms_key.cloudtrail` and CKV_AWS_36 on
`aws_cloudtrail.org`. The same command on `terraform/` gives `Passed checks: 2, Failed checks: 0`.

Question: log file validation writes hourly digest files. Which command proves a log was not changed
after delivery? (`aws cloudtrail validate-logs --trail-arn ... --start-time ...`, per the CloudTrail
"Validating CloudTrail log file integrity with the AWS CLI" page. Not run here.)

## 4. KMS key policy least privilege (Skills 5.2.1, 5.3.5)

```bash
check --policy kms-cloudtrail-key-policy --action kms:Decrypt --principal-arn arn:aws:iam::111122223333:role/KeyAdmin
check --policy kms-cloudtrail-key-policy --action kms:Decrypt \
  --principal-arn arn:aws:iam::444455556666:role/SecurityLogReader \
  --context kms:ViaService=s3.us-east-1.amazonaws.com \
  --context kms:EncryptionContext:aws:cloudtrail:arn=arn:aws:cloudtrail:us-east-1:111122223333:trail/scs-lab-org-trail
check --policy kms-cloudtrail-key-policy --action kms:Decrypt \
  --principal-arn arn:aws:iam::444455556666:role/SecurityLogReader \
  --context kms:EncryptionContext:aws:cloudtrail:arn=arn:aws:cloudtrail:us-east-1:111122223333:trail/scs-lab-org-trail
```

Expected: `no_match` (admins administer, they do not decrypt), `allow` (AllowLogReaderDecryptViaS3Only),
`no_match` (direct KMS call, not through S3).

Then add `"kms:Decrypt",` to the `KeyAdministrationWithoutUse` action list and run
`.venv/bin/pytest -q tests/test_policies.py -k kms`. Expected: `test_kms_admins_cannot_use_the_key` fails
(1 failed, 4 passed). Put the line back.

Question: this policy has no `arn:aws:iam::<account>:root` statement. What protects you from locking
yourself out? (The deployer role is a key administrator, and KMS's policy lockout safety check rejects a
`PutKeyPolicy` that would stop the caller from updating the policy, unless it is bypassed.)

## 5. Permission boundary delegation (Skills 4.2.3, 4.2.4)

```bash
check --policy iam-role-creator --action iam:CreateRole --resource arn:aws:iam::111122223333:role/app/orders-fn \
  --context iam:PermissionsBoundary=arn:aws:iam::111122223333:policy/scs-lab-workload-boundary
check --policy iam-role-creator --action iam:CreateRole --resource arn:aws:iam::111122223333:role/app/orders-fn
check --policy iam-role-creator --action iam:DeleteRolePermissionsBoundary --resource arn:aws:iam::111122223333:role/app/orders-fn
```

Expected: `allow`, `no_match`, `explicit_deny` (DenyBoundaryRemoval).

Delete the `DenyBoundaryRemoval` statement and run `.venv/bin/pytest -q tests/test_policies.py -k boundary`.
Expected: `test_role_creator_cannot_remove_or_edit_boundary` fails (1 failed, 3 passed). Restore it.

Question: the boundary denies `iam:*`. A role created with it also has `AdministratorAccess` attached.
Can it create users? (No. Effective permissions are the intersection of the identity policy and the boundary.)

## 6. Auto-remediation (Skills 2.1.4, 6.3.1)

```bash
.venv/bin/pytest -q tests/test_remediation.py
```

Expected: `17 passed`. The tests use moto, not a deployed Lambda.

Then delete the two lines in `remediate_bucket` that return `already_compliant` and rerun. Expected:
`test_own_remediation_event_is_a_no_op` fails (1 failed, 16 passed). Restore the lines.

Question: the remediation's own `PutBucketPublicAccessBlock` call produces a CloudTrail event that matches
its own rule. What stops an infinite loop? (The function reads the current state first and does nothing
when all four settings are already on.)

## 7. Detection routing (Skills 1.1.3, 1.1.4)

```bash
.venv/bin/pytest -q tests/test_event_patterns.py
```

Expected: `4 passed`. The CloudTrail pattern routes `DeleteBucketPublicAccessBlock` and
`PutBucketPublicAccessBlock` but not `PutBucketPolicy` or `PutAccountPublicAccessBlock`. The GuardDuty
pattern routes `Policy:S3/BucketBlockPublicAccessDisabled` only. This uses moto's matcher, which
approximates EventBridge.

Question: EventBridge only receives CloudTrail "AWS API Call via CloudTrail" events when a trail with
logging is enabled (EventBridge docs). Which resource in this lab satisfies that, and for which account?

## 8. IaC scanning (Skill 6.2.1)

```bash
.venv/bin/checkov -d terraform --framework terraform --compact
```

Expected: `Passed checks: 87, Failed checks: 4, Skipped checks: 6`. Decide for each failure (CKV2_AWS_3,
CKV2_AWS_62, CKV_AWS_18, CKV_AWS_144) whether to fix, skip with a reason, or accept. See the README's
results section for this repo's current answer.

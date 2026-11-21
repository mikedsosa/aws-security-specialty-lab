# AWS Security Specialty lab (SCS-C03)

An offline-first, hands-on lab for the AWS Certified Security - Specialty exam (SCS-C03). It has
Terraform for a small organization-level security setup, a Lambda auto-remediation with tests, a
policy checker for "predict the decision" drills, fifteen exercises with expected outcomes, and one
incident-response runbook.

Nothing here has been deployed. No command in this repository used real AWS credentials, created cloud
resources, or cost money. All account IDs (111122223333, 444455556666, 777788889999) and the
organization ID (o-exampleorg1) are documentation placeholders.

## Problem

Exam questions on SCPs, key policies, permission boundaries and event-driven remediation are mostly
"what happens when this request hits these policies". Reading about it is slow, and a real AWS
organization to practice in costs money and can break things. This lab makes those controls concrete
as code you can read, break and test on a laptop.

## Approach

The exam guide (SCS-C03 v1.0, published March 26, 2026, read November 17, 2026) has six domains:
Detection 16%, Incident Response 14%, Infrastructure Security 18%, Identity and Access Management 20%,
Data Protection 18%, and Security Foundations and Governance 14%. Source:
https://docs.aws.amazon.com/pdfs/aws-certification/latest/security-specialty-03/security-specialty-03.pdf (the PDF of https://docs.aws.amazon.com/aws-certification/latest/security-specialty-03/security-specialty-03.html , which is linked from https://aws.amazon.com/certification/certified-security-specialty/ ).
[docs/exam-domain-map.md](docs/exam-domain-map.md) maps each component to the guide's skill numbers and
lists what is not covered.

| Component | File | Domain |
| --- | --- | --- |
| SCP: deny leaving the org, root user actions, security telemetry tampering, account BPA changes, unapproved Regions (break-glass role exempt) | `terraform/governance.tf`, `terraform/policies/scp-guardrails.json.tftpl` | 6 |
| RCP: deny non-TLS requests and S3 access from outside the organization | `terraform/policies/rcp-data-perimeter.json.tftpl` | 5, 6 |
| Organization trail, multi-Region, log file validation, SSE-KMS, versioned bucket with BPA, ownership enforced, TLS-only and no-delete bucket policy, S3 access logging, EventBridge notifications, and cross-Region replication to us-west-2 | `terraform/logging.tf`, `terraform/log-archive.tf` | 1, 5 |
| KMS key policy: admins cannot use the key; CloudTrail encrypts only for this trail (`aws:SourceArn`); one reader decrypts only through S3 and only CloudTrail-encrypted data | `terraform/policies/kms-cloudtrail-key-policy.json.tftpl` | 5 |
| GuardDuty detector with S3 protection, org-wide auto-enable for all members, Security Hub CSPM with FSBP, delegated admin for both | `terraform/detection.tf` | 1, 6 |
| Permission boundary plus a role-creator role that can create `/app/` roles only with that boundary and cannot remove or edit it | `terraform/identity.tf` | 4 |
| EventBridge (CloudTrail BPA changes and the GuardDuty finding) to an idempotent Lambda that turns bucket BPA back on, with DLQ, retries and reserved concurrency | `terraform/remediation.tf`, `lambda/remediate_s3_bpa/handler.py` | 2, 6 |
| Incident runbook: leaked access key used to make a bucket public | [docs/runbook-s3-public-exposure.md](docs/runbook-s3-public-exposure.md) | 2 |
| Isolated study VPC: security groups, network ACLs, VPC flow logs, S3 gateway and SSM/Logs interface endpoints with endpoint policies | `terraform/network.tf` | 3, 5 |
| Launch template requiring IMDSv2, EBS encryption with a CMK, Session Manager instance profile and operator role, no SSH key; Inspector v2 enabler | `terraform/compute.tf` | 3, 5 |
| Regional WAF web ACL (Core Rule Set, Known Bad Inputs, rate limit). Not associated with a resource. Shield Standard is documented only | `terraform/edge.tf` | 3 |
| Fifteen exercises with expected outcomes | [docs/exercises.md](docs/exercises.md) | all |

Policies live as JSON templates loaded with `templatefile()`. The Python tests render the same
templates, and a plan-based test checks that Terraform's rendered policy equals what the tests check.

### Relation to aws-audit-baseline

[mikedsosa/aws-audit-baseline](https://github.com/mikedsosa/aws-audit-baseline) covers one account: a
single-account trail, per-bucket KMS keys, account BPA, MFA roles, and a plan-evidence checker. This lab
does not repeat it. It adds the organization layer (SCP, RCP, organization trail, delegated admins),
detection services, permission-boundary delegation, auto-remediation, and study material.

## Setup

Python 3.11 or newer, Terraform 1.6 or newer, and (optional) TFLint.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
make all   # lint, fmt, validate, tflint, policy lint, offline plan, tests, checkov
```

`scripts/offline-plan.sh` unsets ambient `AWS_*` variables, exports placeholder credentials for that
process only, disables the instance metadata service, points `AWS_ENDPOINT_URL` at a closed local port
(`127.0.0.1:9`) so any API call would fail locally, and runs `terraform plan -refresh=false -lock=false`
with no backend. The provider skips credential validation and account lookup while `offline_plan = true`.

Do not run `terraform apply`. See Limitations.

## Results

Run on November 21, 2026 on a Linux box with Python 3.13.5, Terraform 1.17.1, AWS provider 5.100.0,
archive provider 2.7.1, TFLint 0.66.0 with the AWS ruleset 0.40.0, checkov 3.1.47, parliament 1.6.4,
moto 5.2.5, boto3 1.44.4, pytest 9.2.0 and ruff 0.17.5.

| Command | Result |
| --- | --- |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 17 files already formatted |
| `terraform -chdir=terraform fmt -recursive -check` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| `tflint --format compact` (in `terraform/`) | no issues, exit 0 |
| `python scripts/lint_policies.py` (parliament) | 25 findings, all accepted below, 0 unexpected |
| `pytest -q` before the plan exists | 99 passed, 28 skipped (plan tests) |
| `./scripts/offline-plan.sh` | Plan: 140 to add, 0 to change, 0 to destroy |
| `pytest -q` after the plan | 127 passed |
| `checkov -d terraform --framework terraform` | Passed 339, Failed 0, Skipped 12 |
| `checkov -f build/plan.json --framework terraform_plan` | Passed 324, Failed 21, Skipped 0 |
| `gitleaks detect` (git history and working tree, 8.21.2 `--no-banner --redact`) | no leaks found |

What the tests cover: 17 remediation tests with moto S3 (restore after delete, partial put, GuardDuty
finding, loop guard, exemption list, dry run, failed API calls, malformed events, missing bucket); 4
EventBridge pattern tests through moto's matcher; 78 policy tests (rendering, Organizations size limits
of 10,240 characters for SCPs and 5,120 for RCPs, placeholder-only account IDs, and request decisions for
every policy, including the Domain 3 endpoint and Session Manager policies); 28 tests against the offline
plan JSON.

Accepted parliament findings: 25 findings, 0 unexpected. `RESOURCE_STAR` on the five KMS key policies
(in a key policy, `"Resource": "*"` means this key); `MISMATCHED_TYPE_BUT_USABLE` once on the role
creator (`StringEquals` on the ARN-typed `iam:PermissionsBoundary`, the form AWS's own boundary
delegation example uses); `MISMATCHED_TYPE` on the lab-logs and infra-logs key policies (`ArnEquals` on
`kms:EncryptionContext:aws:logs:arn` with a log group ARN; parliament types the slash in the log group
name as String. This is the condition shape in AWS's CloudWatch Logs key policy example);
`RESOURCE_STAR` on the SSM instance role (the same Resource `*` shape as AmazonSSMManagedInstanceCore);
`RESOURCE_STAR` on the S3 gateway endpoint policy (access is limited by organization ID; this lab has
no workload bucket to name); and `RESOURCE_STAR` on the Systems Manager interface endpoint policy
(the listed SSM, ssmmessages, and ec2messages APIs are not bucket-scoped); and `RESOURCE_STAR` on the CloudWatch Logs interface endpoint policy (access is limited by organization ID; later session logging does not have a fixed log group name).

Directory-mode checkov findings that were open on the first draft are now fixed:

| Check | What changed |
| --- | --- |
| CKV2_AWS_3 GuardDuty org config | Added `aws_guardduty_organization_configuration` with `auto_enable_organization_members = "ALL"`. The detector and this resource do not use `count`, because checkov 3.1.47's graph check does not connect counted resources (a counted pair still failed the scan). In a real organization this resource is created in the delegated admin account; the lab keeps it in the same root so the offline plan can include it. |
| CKV_AWS_18 access logging | Added `aws_s3_bucket.access_logs` (SSE-S3) as the trail bucket's log destination, and `aws_s3_bucket.replica_access_logs` (SSE-S3) as the replica bucket's destination in us-west-2. Neither destination logs to itself. AWS requires a log destination bucket to use SSE-S3 and recommends against a bucket logging to itself. Directory-mode checkov flags those destinations for missing access logging (CKV_AWS_18) and for not using KMS (CKV_AWS_145); both are skipped in the code as a deliberate exception that follows AWS guidance. Plan mode also flags CKV_AWS_145 (it ignores inline skips) and did not flag CKV_AWS_18. See Limitations. |
| CKV_AWS_144 cross-Region replication | Added a us-west-2 replica bucket, a replica-Region CMK, a replication role, and `aws_s3_bucket_replication_configuration.trail` with status Enabled. |
| CKV2_AWS_62 event notifications | Added `aws_s3_bucket_notification` with `eventbridge = true` on the trail, access-log, replica, and replica access-log buckets. |
| CKV_AWS_158 log group CMK | The remediation log group now uses `aws_kms_key.lab_logs`. This was previously an inline skip. |

The 12 directory-mode skips (with reasons in the code) are CKV2_AWS_10 and CKV_AWS_252 on the trail;
CKV_AWS_117, CKV_AWS_272 and CKV_AWS_173 on the Lambda; CKV_AWS_144 on the access-log, replica, and
replica access-log buckets (each would be a further copy of the data); and CKV_AWS_18 and CKV_AWS_145
on the two access-log destination buckets (SSE-S3 and no self-logging, following AWS guidance). Plan
mode ignores inline skips, so those reappear there, except CKV_AWS_173 (which does not), CKV_AWS_144
on the replica bucket (plan mode treats the destination bucket as connected to the replication
configuration and passes it), and CKV_AWS_18 on the access-log destinations (plan mode did not flag
them).

The 22 plan-mode failures, with why they were not changed:

| Check | Resource | Why it is documented, not changed |
| --- | --- | --- |
| CKV2_AWS_10 | `aws_cloudtrail.org` | CloudWatch Logs delivery is a paid add-on; EventBridge already receives management events for the remediation path. |
| CKV_AWS_252 | `aws_cloudtrail.org` | No SNS topic; delivery notifications are out of scope for this lab. |
| CKV_AWS_117 | `aws_lambda_function.remediation` | The function only calls the S3 control plane. Putting it in the study VPC would add endpoint or NAT cost without reducing that API exposure. |
| CKV_AWS_272 | `aws_lambda_function.remediation` | Code signing needs AWS Signer and a signing profile; out of scope for an offline lab. |
| CKV_AWS_144 | `aws_s3_bucket.access_logs`, `.replica_access_logs` | These are access-log destinations. A further replica would be another copy. The same skip is on the trail replica bucket in directory mode. |
| CKV_AWS_145 | `aws_s3_bucket.access_logs`, `.replica_access_logs` | AWS requires a server access log destination bucket to use SSE-S3, not SSE-KMS. Directory mode skips this check on those buckets for the same reason. |
| CKV_AWS_61 | `aws_iam_role.role_creator` | The trust policy allows the same-account root principal only when MFA is present. The check flags any account-root principal and does not read the MFA condition. Directory mode sees a data-source reference, not the rendered ARN, and passes. The lab keeps the stated trust design. |
| CKV_AWS_93 | `aws_s3_bucket_policy.trail`, `.access_logs`, `.trail_replica`, `.replica_access_logs` | `DenyLogDeletion` denies only `s3:DeleteObject` and `s3:DeleteObjectVersion` to `"Principal": "*"`, so object writes, reads and bucket policy updates still work. The check treats any unconditional Deny to `*` as a lockout. Directory mode does not parse `templatefile()` and passes. |
| CKV_AWS_300 | the four lifecycle configurations | Each rule sets `abort_incomplete_multipart_upload` to 7 days and uses an empty `filter {}` so the rule applies to all objects (the AWS provider requires `filter` or `prefix`). In plan JSON that empty filter becomes a truthy object with null/empty keys, and the check then skips the rule and fails. Directory mode sees `filter {}` as an empty object and passes. Removing the filter produces a provider warning that will become an error. |
| CKV_AWS_61 | `aws_iam_role.ssm_operator` | Same design as `role_creator`: same-account root principal only when MFA is present. The check flags any account-root principal and does not read the MFA condition. Directory mode sees a data-source reference and passes. |
| CKV_AWS_355, CKV_AWS_290, CKV_AWS_288 | `aws_iam_policy.ssm_instance` | The instance role follows the AmazonSSMManagedInstanceCore action set, which uses `Resource: "*"`. Directory mode does not parse `templatefile()` and passes. Tightening documents and parameter ARNs would go beyond what this lab verified against a live agent. |

The 17 plan-mode failures from November 17, 2026 are unchanged. The four new failures above appeared when Domain 3 IAM policies and the operator trust policy were added. Scoping `ssm:GetConnectionStatus` on the operator policy removed the earlier plan-mode CKV_AWS_355 finding on that policy; `DescribeInstanceInformation` and `DescribeSessions` still use `Resource: "*"`, which the check does not treat as restrictable.

## Limitations


- Never applied. Plan success does not prove apply success. Known apply-time needs: an existing
  organization with SCPs and RCPs enabled, trusted access for CloudTrail, GuardDuty and Security Hub,
  and existing `KeyAdmin`, `TerraformDeployer` and `SecurityLogReader` roles (KMS rejects key policies
  that name principals that do not exist).
- Compressed into one root module and one provider. A real layout splits management, security and
  member accounts and deploys the remediation per account and Region.
- SCPs and RCPs do not apply to the management account, where this lab puts the trail, key and bucket.
- `src/scs_lab/policy_eval.py` evaluates one policy at a time and supports a stated subset of IAM
  grammar. It refuses what it does not support instead of guessing. It does not combine SCPs, RCPs,
  boundaries, session policies and resource policies the way AWS does. Confirm real decisions with the
  IAM policy simulator or IAM Access Analyzer.
- The moto tests exercise the handler and moto's EventBridge matcher, not a deployed Lambda or real
  EventBridge. The sample events are synthetic and shaped after AWS documentation.
- parliament's bundled action database can lag new AWS actions.
- GuardDuty, Security Hub CSPM, CloudTrail data events, KMS and Lambda are billed services once
  deployed. With the Domain 3 defaults, an apply would also bill for Inspector (`enable_inspector`
  defaults to true and would start EC2, ECR, and Lambda scanning in the account, including any
  existing images or functions), interface VPC endpoints (Systems Manager, ssmmessages,
  ec2messages, and CloudWatch Logs, in two Availability Zones), an unassociated WAF web ACL and
  its managed and rate-based rules, and VPC flow logs to CloudWatch Logs. This lab did not price
  them, and Inspector was not run, so there are no scan findings.
- Domain 3 now has a study VPC, Session Manager access path, IMDSv2 launch template, EBS CMK,
  Inspector v2 enabler, and an unassociated WAF web ACL. Still not covered: Network Firewall,
  CloudFront, Shield Advanced, Image Builder, Patch Manager runs, GenAI guardrails, hybrid
  connectivity, and Verified Access. The WAF ACL would not inspect traffic unless associated. No
  instance is created, and Inspector was not run, so there are no scan findings. See the domain map.
- The S3 gateway path cannot look up the regional S3 managed prefix list offline, so the app
  security group and network ACL allow HTTPS (and ephemeral return ports, excluding 3389) to
  0.0.0.0/0 as a stand-in. A live account should use the prefix list instead.
- S3 server access log destination buckets use SSE-S3 (AES256) and do not log to themselves, as AWS
  requires and recommends. Directory-mode checkov flags those destinations for missing access logging
  (CKV_AWS_18) and for not using KMS encryption (CKV_AWS_145); both are skipped as a deliberate
  exception. Plan mode flags CKV_AWS_145 on those buckets and did not flag CKV_AWS_18.

## License

MIT. See [LICENSE](LICENSE). Third-party notices are in [NOTICE.md](NOTICE.md).

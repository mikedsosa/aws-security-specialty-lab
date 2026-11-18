# AWS Security Specialty lab (SCS-C03)

An offline-first, hands-on lab for the AWS Certified Security - Specialty exam (SCS-C03). It has
Terraform for a small organization-level security setup, a Lambda auto-remediation with tests, a
policy checker for "predict the decision" drills, eight exercises with expected outcomes, and one
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
https://docs.aws.amazon.com/pdfs/aws-certification/latest/security-specialty-03/security-specialty-03.pdf ,
linked from https://aws.amazon.com/certification/certified-security-specialty/ .
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
| Eight exercises with expected outcomes | [docs/exercises.md](docs/exercises.md) | all |

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

Run on November 17, 2026 on a Linux box with Python 3.13.5, Terraform 1.17.1, AWS provider 5.100.0,
archive provider 2.7.1, TFLint 0.66.0 with the AWS ruleset 0.40.0, checkov 3.1.47, parliament 1.6.4,
moto 5.2.5, boto3 1.44.4, pytest 9.2.0 and ruff 0.17.5.

| Command | Result |
| --- | --- |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 17 files already formatted |
| `terraform -chdir=terraform fmt -recursive -check` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| `tflint --format compact` (in `terraform/`) | no issues, exit 0 |
| `python scripts/lint_policies.py` (parliament) | 18 findings, all accepted below, 0 unexpected |
| `pytest -q` before the plan exists | 85 passed, 18 skipped (plan tests) |
| `./scripts/offline-plan.sh` | Plan: 63 to add, 0 to change, 0 to destroy |
| `pytest -q` after the plan | 103 passed |
| `checkov -d terraform --framework terraform` | Passed 152, Failed 0, Skipped 7 |
| `checkov -f build/plan.json --framework terraform_plan` | Passed 131, Failed 12, Skipped 0 |

What the tests cover: 17 remediation tests with moto S3 (restore after delete, partial put, GuardDuty
finding, loop guard, exemption list, dry run, failed API calls, malformed events, missing bucket); 4
EventBridge pattern tests through moto's matcher; 64 policy tests (rendering, Organizations size limits
of 10,240 characters for SCPs and 5,120 for RCPs, placeholder-only account IDs, and request decisions for
every policy); 18 tests against the offline plan JSON.

Accepted parliament findings: `RESOURCE_STAR` 16 times on the three KMS key policies (in a key policy,
`"Resource": "*"` means this key), `MISMATCHED_TYPE_BUT_USABLE` once on the role creator
(`StringEquals` on the ARN-typed `iam:PermissionsBoundary`, the form AWS's own boundary delegation example
uses), and `MISMATCHED_TYPE` once on the lab-logs key policy (`ArnEquals` on
`kms:EncryptionContext:aws:logs:arn` with a log group ARN; parliament types the slash in the log group
name as String. This is the condition shape in AWS's CloudWatch Logs key policy example).

Directory-mode checkov findings that were open on the first draft are now fixed:

| Check | What changed |
| --- | --- |
| CKV2_AWS_3 GuardDuty org config | Added `aws_guardduty_organization_configuration` with `auto_enable_organization_members = "ALL"`. The detector and this resource do not use `count`, because checkov 3.1.47's graph check does not connect counted resources (a counted pair still failed the scan). In a real organization this resource is created in the delegated admin account; the lab keeps it in the same root so the offline plan can include it. |
| CKV_AWS_18 access logging | Added `aws_s3_bucket.access_logs` and `aws_s3_bucket_logging.trail`. The access-log bucket logs to itself under the `access-logs/` prefix. |
| CKV_AWS_144 cross-Region replication | Added a us-west-2 replica bucket, a replica-Region CMK, a replication role, and `aws_s3_bucket_replication_configuration.trail` with status Enabled. |
| CKV2_AWS_62 event notifications | Added `aws_s3_bucket_notification` with `eventbridge = true` on the trail, access-log, and replica buckets. |
| CKV_AWS_158 log group CMK | The remediation log group now uses `aws_kms_key.lab_logs`. This was previously an inline skip. |

The seven directory-mode skips (with reasons in the code) are CKV2_AWS_10 and CKV_AWS_252 on the trail,
CKV_AWS_117, CKV_AWS_272 and CKV_AWS_173 on the Lambda, and CKV_AWS_144 on the access-log bucket and on
the replica bucket (each would be a third copy of the data). Plan mode ignores inline skips, so those
reappear there, except CKV_AWS_173 (which does not) and CKV_AWS_144 on the replica bucket (plan mode
treats the destination bucket as connected to the replication configuration and passes it).

The 12 plan-mode failures, with why they were not changed:

| Check | Resource | Why it is documented, not changed |
| --- | --- | --- |
| CKV2_AWS_10 | `aws_cloudtrail.org` | CloudWatch Logs delivery is a paid add-on; EventBridge already receives management events for the remediation path. |
| CKV_AWS_252 | `aws_cloudtrail.org` | No SNS topic; delivery notifications are out of scope for this lab. |
| CKV_AWS_117 | `aws_lambda_function.remediation` | The function only calls the S3 control plane. A VPC would add NAT or endpoint cost and is Domain 3 content, which is scheduled later. |
| CKV_AWS_272 | `aws_lambda_function.remediation` | Code signing needs AWS Signer and a signing profile; out of scope for an offline lab. |
| CKV_AWS_144 | `aws_s3_bucket.access_logs` | This is the access-log target. A further replica would be a third copy. The same skip is on the replica bucket in directory mode. |
| CKV_AWS_61 | `aws_iam_role.role_creator` | The trust policy allows the same-account root principal only when MFA is present. The check flags any account-root principal and does not read the MFA condition. Directory mode sees a data-source reference, not the rendered ARN, and passes. The lab keeps the stated trust design. |
| CKV_AWS_93 | `aws_s3_bucket_policy.trail`, `.access_logs`, `.trail_replica` | `DenyLogDeletion` denies only `s3:DeleteObject` and `s3:DeleteObjectVersion` to `"Principal": "*"`, so object writes, reads and bucket policy updates still work. The check treats any unconditional Deny to `*` as a lockout. Directory mode does not parse `templatefile()` and passes. |
| CKV_AWS_300 | the three lifecycle configurations | Each rule sets `abort_incomplete_multipart_upload` to 7 days and uses an empty `filter {}` so the rule applies to all objects (the AWS provider requires `filter` or `prefix`). In plan JSON that empty filter becomes a truthy object with null/empty keys, and the check then skips the rule and fails. Directory mode sees `filter {}` as an empty object and passes. Removing the filter produces a provider warning that will become an error. |

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
  deployed. This lab did not price them.
- Domain 3 coverage is thin; see the domain map.

## License

MIT. See [LICENSE](LICENSE). Third-party notices are in [NOTICE.md](NOTICE.md).

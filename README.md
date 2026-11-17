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
| Organization trail, multi-Region, log file validation, SSE-KMS, versioned bucket with BPA, ownership enforced, TLS-only and no-delete bucket policy | `terraform/logging.tf` | 1, 5 |
| KMS key policy: admins cannot use the key; CloudTrail encrypts only for this trail (`aws:SourceArn`); one reader decrypts only through S3 and only CloudTrail-encrypted data | `terraform/policies/kms-cloudtrail-key-policy.json.tftpl` | 5 |
| GuardDuty detector with S3 protection, Security Hub CSPM with FSBP, delegated admin for both | `terraform/detection.tf` | 1, 6 |
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
| `ruff format --check .` | 16 files already formatted |
| `terraform -chdir=terraform fmt -recursive -check` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| `tflint --format compact` (in `terraform/`) | no issues, exit 0 |
| `python scripts/lint_policies.py` (parliament) | 5 findings, all accepted below, 0 unexpected |
| `pytest -q` before the plan exists | 79 passed, 16 skipped (plan tests) |
| `./scripts/offline-plan.sh` | Plan: 35 to add, 0 to change, 0 to destroy |
| `pytest -q` after the plan | 95 passed |
| `checkov -d terraform --framework terraform` | Passed 87, Failed 4, Skipped 6 |
| `checkov -f build/plan.json --framework terraform_plan` | Passed 78, Failed 12, Skipped 0 |

What the tests cover: 17 remediation tests with moto S3 (restore after delete, partial put, GuardDuty
finding, loop guard, exemption list, dry run, failed API calls, malformed events, missing bucket); 4
EventBridge pattern tests through moto's matcher; 58 policy tests (rendering, Organizations size limits
of 10,240 characters for SCPs and 5,120 for RCPs, placeholder-only account IDs, and request decisions for
every policy); 16 tests against the offline plan JSON.

Accepted parliament findings: `RESOURCE_STAR` four times on the KMS key policy (in a key policy,
`"Resource": "*"` means this key) and `MISMATCHED_TYPE_BUT_USABLE` once on the role creator
(`StringEquals` on the ARN-typed `iam:PermissionsBoundary`, the form AWS's own boundary delegation example
uses).

Open checkov findings in the directory scan, left visible on purpose:

| Check | Resource | Why it is open |
| --- | --- | --- |
| CKV2_AWS_3 GuardDuty org config | `aws_guardduty_detector.this[0]` | Needs `aws_guardduty_organization_configuration` in the delegated admin account, which needs a second provider that assumes a role there. Not possible offline. |
| CKV_AWS_18 access logging | `aws_s3_bucket.trail` | Needs another log bucket; in practice this belongs in a log archive account. |
| CKV_AWS_144 cross-Region replication | `aws_s3_bucket.trail` | Cost and a second Region bucket; out of scope. |
| CKV2_AWS_62 event notifications | `aws_s3_bucket.trail` | No consumer for them in this lab. |

The six inline skips (with reasons in the code) are CKV2_AWS_10 and CKV_AWS_252 on the trail,
CKV_AWS_158 on the log group, and CKV_AWS_117, CKV_AWS_272 and CKV_AWS_173 on the Lambda. Plan mode
ignores inline skips, so those reappear there (CKV_AWS_173 does not), along with three checks that pass
in the directory scan: CKV_AWS_61 on the role creator's trust policy (same-account root principal with
MFA), CKV_AWS_93 on the trail bucket policy (the deny-delete statement for every principal), and
CKV_AWS_300 on the lifecycle rule, which does set `abort_incomplete_multipart_upload` to 7 days in the
plan JSON. That last one looks like a plan-mode false positive; it was not investigated further.

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

Not chosen yet. Third-party notices are in [NOTICE.md](NOTICE.md).

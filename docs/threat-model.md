# Threat model

Draft, pending independent fact-check. Written against the published tree at
[`d9fd76b`](https://github.com/mikedsosa/aws-security-specialty-lab/commit/d9fd76b0fc786deb5c5350cbaeac6c87f10fe3a3)
(the Domain 3 publish on main). It describes controls as they are written in
this repository. Nothing here has been applied, and nothing was observed in a
live AWS account. This is not an audit report and not a claim of compliance
with any standard.

The companion architecture write-up is [architecture.md](architecture.md).
The incident path this model uses as a worked example is
[runbook-s3-public-exposure.md](runbook-s3-public-exposure.md).

## 1. Purpose and scope

This repository is an offline study lab for the AWS Certified Security -
Specialty exam (SCS-C03). In scope: the Terraform under `terraform/`, the
remediation function in `lambda/remediate_s3_bpa/`, the local policy checker
in `src/scs_lab/`, the fifteen exercises, and the S3 public-exposure runbook.

Out of scope: any applied environment, paid AWS APIs, a real organization, and
the single-account baseline in
[mikedsosa/aws-audit-baseline](https://github.com/mikedsosa/aws-audit-baseline).
All account IDs (`111122223333`, `444455556666`, `777788889999`) and the
organization ID (`o-exampleorg1`) are documentation placeholders.

The lab is one Terraform root with two AWS providers (home Region `us-east-1`
and a `replica` alias for `us-west-2`). It is not a multi-account layout.
`guardrail_target_ids` defaults to an empty list, so the SCP and RCP are
created in the plan and attached to nothing unless that variable is set.

## 2. Assets

| ID | Asset | Where it is specified |
| --- | --- | --- |
| A1 | Organization trail, log file validation, and the trail's customer managed key | `terraform/logging.tf`, `terraform/policies/kms-cloudtrail-key-policy.json.tftpl` |
| A2 | Trail bucket, access-log bucket, us-west-2 replica, and replica access-log bucket | `terraform/logging.tf`, `terraform/log-archive.tf` |
| A3 | Service control policy and resource control policy templates | `terraform/governance.tf`, `terraform/policies/scp-guardrails.json.tftpl`, `terraform/policies/rcp-data-perimeter.json.tftpl` |
| A4 | GuardDuty detector (S3 protection, org auto-enable) and Security Hub CSPM with FSBP, plus delegated-admin assignments | `terraform/detection.tf` |
| A5 | Workload permission boundary and the `/app/` role-creator role | `terraform/identity.tf` |
| A6 | EventBridge rules, remediation Lambda, dead-letter queue, and Lambda log group | `terraform/remediation.tf`, `lambda/remediate_s3_bpa/handler.py` |
| A7 | Study VPC (`10.42.0.0/16` by default), isolated app and endpoint subnets, security groups, network ACLs, flow logs, and VPC endpoints | `terraform/network.tf` |
| A8 | Session Manager instance profile and operator role, IMDSv2 launch template, and EBS customer managed key | `terraform/compute.tf` |
| A9 | Inspector v2 enabler (`EC2`, `ECR`, `LAMBDA`) | `terraform/compute.tf` (`enable_inspector` defaults to true) |
| A10 | Unassociated regional WAF web ACL and its log group | `terraform/edge.tf` |
| A11 | Offline policy checker and rendered policy tests | `src/scs_lab/policy_eval.py`, `tests/test_policies.py` |

The study VPC is a teaching network. No `aws_instance` is created. The WAF web
ACL is not associated with a load balancer, API Gateway, or CloudFront
distribution. Inspector was not run, so there are no scan findings.

## 3. Actors

| Actor | Trust in this model | Notes |
| --- | --- | --- |
| External attacker with a leaked member-account access key | Untrusted | The runbook's placeholder is IAM user `example-dev` in account `777788889999`, used to weaken bucket-level Block Public Access and attach a public bucket policy. |
| Compromised instance profile or `/app/` workload role in the study VPC | Untrusted once credentials are stolen | The launch template would attach `scs-lab-ssm-instance`. No instance is created in this lab. |
| Operator who can assume `scs-lab-ssm-operator` or `scs-lab-role-creator` | Trusted but constrained by those policies | Both roles trust the management-account root principal only when `aws:MultiFactorAuthPresent` is true. |
| Principal who can run Terraform as `TerraformDeployer`, or `BreakGlassAdmin` | High | `KeyAdmin`, `TerraformDeployer`, `SecurityLogReader`, and `BreakGlassAdmin` are named in policies and variables. This root does not create them. |
| Administrator in the management account (`111122223333`) | Highest | SCPs and RCPs do not apply in the management account. This compressed lab places the trail, CloudTrail key, log buckets, detection resources, remediation Lambda, and study VPC there. |

## 4. Trust boundaries

- **TB1, management account vs member accounts.** In a real organization, SCPs
  and RCPs bind member accounts only. The lab writes those policies, then
  places the trail, keys, buckets, and compute in the same root that uses
  `management_account_id`.
- **TB2, study VPC vs AWS APIs.** App subnets have no internet gateway and no
  NAT gateway. Systems Manager and CloudWatch Logs are reached through
  interface endpoints. S3 is reached through a gateway endpoint. Endpoint
  policies further restrict those paths.
- **TB3, instance metadata.** The launch template sets `http_tokens =
  "required"` (IMDSv2), `http_put_response_hop_limit = 1`, and
  `instance_metadata_tags = "disabled"`. No instance is launched from it.
- **TB4, administrative access to compute.** The launch template does not set
  `key_name`. The operator policy allows Session Manager session APIs and does
  not include `ssm:SendCommand`.
- **TB5, WAF.** The web ACL exists and has logging configured, but it is not
  associated with a resource, so it inspects no traffic.
- **TB6, this laptop vs AWS.** `scripts/offline-plan.sh` unsets ambient
  `AWS_*` variables, points `AWS_ENDPOINT_URL` at a closed local port, and
  plans with `offline_plan = true`. No command in this repository used real
  AWS credentials.

## 5. How to read the STRIDE tables

Status is about the repository, not a live account.

| Status | Meaning |
| --- | --- |
| Specified | The control is written in Terraform or application code, and a listed test checks that code. It has not been applied. |
| Partial | A control is written, but the same files state a gap, or the tests only cover part of the path. |
| Accepted | The lab does not address the threat and says so, or the limit is a documented property of AWS. |
| Lab limit | The compressed, offline layout would not provide this control if the module were applied as written, or the control cannot be verified offline. |

Tests cited below are in this repository. Policy decisions come from
`src/scs_lab/policy_eval.py`, which evaluates one policy at a time and is not
the AWS policy engine.

### Spoofing

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| S1 | A leaked member-account access key is used to call APIs as that user | The org trail records management events. GuardDuty S3 protection and the EventBridge rule on `DeleteBucketPublicAccessBlock` / `PutBucketPublicAccessBlock` can start remediation. The SCP does not deny bucket-level Block Public Access changes (it denies `s3:PutAccountPublicAccessBlock`). | `tests/test_event_patterns.py`, `tests/test_remediation.py`, exercise 6, the runbook | Partial, and a lab limit for the runbook account: the Lambda identity policy allows `s3:GetBucketPublicAccessBlock` and `s3:PutBucketPublicAccessBlock` only when `aws:ResourceAccount` is the management account. The runbook's bucket is in placeholder member account `777788889999`. A production layout would deploy remediation per account, as the README states. |
| S2 | A caller forges a Session Manager or role-creator session without MFA | Trust policies on `scs-lab-ssm-operator` and `scs-lab-role-creator` require `aws:MultiFactorAuthPresent = true` for the same-account root principal. | Exercise 13 states the MFA requirement. The trust documents are in `terraform/compute.tf` and `terraform/identity.tf`. No unit test evaluates those trust policies. | Specified in the trust documents only. The roles have not been assumed. |
| S3 | An attacker uses stolen EC2 instance-profile credentials from IMDS | The launch template requires IMDSv2 and sets the PUT hop limit to 1. No instance is created, so there is no live IMDS endpoint in this lab. | Plan tests for the launch template in `tests/test_terraform_plan.py`; exercise 14 | Specified on the template. Lab limit: untested against a running instance. |

### Tampering

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| T1 | Someone tries to leave the organization, use the root user, or tamper with CloudTrail, GuardDuty, Security Hub, Config, or Access Analyzer | `scp-guardrails`: `DenyLeaveOrganization` (no break-glass exemption), `DenyRootUserActions`, and `ProtectSecurityTelemetry` (break-glass role exempt). | Exercises 1; policy tests for those statements | Specified for member accounts, and only if the SCP is attached (`guardrail_target_ids` defaults to empty). Lab limit: SCPs do not bind the management account, where this lab places the trail. |
| T2 | Someone turns off account-level S3 Block Public Access in a member account | `ProtectAccountPublicAccessBlock` in the SCP (break-glass exempt). The root also declares `aws_s3_account_public_access_block` for the account it would run in. | Policy tests; `terraform/logging.tf` | Specified for members if attached. The account-level resource would apply only to the account that ran the root. |
| T3 | Someone deletes or overwrites CloudTrail objects, or a different trail writes into the bucket | Trail bucket policy: `DenyLogDeletion` for `s3:DeleteObject` and `s3:DeleteObjectVersion`; CloudTrail `PutObject` allowed only for this trail ARN under the management-account and organization prefixes; versioning; cross-Region replication with delete-marker replication; TLS deny. | Policy tests for the trail bucket policy; exercise 3 | Specified in the templates. Not applied, so there are no delivered logs to validate. |
| T4 | A key administrator uses the CloudTrail CMK to decrypt logs, or a reader decrypts outside S3 | Key policy: administrators have administration actions and not use actions. The log-reader statement allows `kms:Decrypt` only with `kms:ViaService = s3.<region>.amazonaws.com` and a present `kms:EncryptionContext:aws:cloudtrail:arn`. CloudTrail `GenerateDataKey*` is limited by `aws:SourceArn` of this trail. There is no account-root `kms:*` statement. | Policy tests; exercise 4 | Specified in the key policy. The named `KeyAdmin`, `TerraformDeployer`, and `SecurityLogReader` roles are not created here. |
| T5 | The delegated role creator builds a role without the workload boundary, outside `/app/`, or later removes the boundary | Role-creator policy: create/attach/put actions on `role/app/*` require `iam:PermissionsBoundary` to equal the workload boundary ARN; `DenyBoundaryRemoval` and `DenyBoundaryPolicyEdits`; `PassRole` only to `lambda.amazonaws.com`. The boundary itself denies `iam:*`, `organizations:*`, and `sts:AssumeRole`. | Policy tests; exercise 5 | Specified for principals who only have this role-creator policy. It does not constrain an administrator who can create roles another way. |
| T6 | An operator or process edits the launch template or EBS encryption after the fact | The template sets encrypted `gp3` root volume with the EBS CMK, no public IP, and the app security group. The EBS key policy allows use and grants only via `ec2.<region>.amazonaws.com`, for the key admins and the instance role. This is documentation of the template, not a runtime guard. | Exercise 14; plan tests | Specified as written. Anyone who can change the template in an applied account could weaken it. The SCP does not deny `ec2:ModifyLaunchTemplate` or related actions. |

### Repudiation

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| R1 | An actor denies making a management-plane API call | Organization trail: multi-Region, global service events, log file validation, SSE-KMS, TLS-only bucket policy, versioning, access logging, EventBridge notifications on the log buckets, and replication to us-west-2. | Exercise 3; plan tests | Partial. CloudWatch Logs delivery for the trail is omitted on purpose (a paid add-on; EventBridge is used for the remediation path). The trail event selector includes management events only, so object-level reads such as `GetObject` would not appear. The runbook states that if data events and access logs for the workload bucket are both off, read scope is unknown. |
| R2 | Someone treats a `scs-lab check` decision as an AWS authorization result | The checker evaluates one rendered policy, supports a stated subset of IAM grammar, and raises `Unsupported` instead of guessing. It does not combine SCPs, RCPs, identity policies, boundaries, and resource policies. | `src/scs_lab/policy_eval.py` module docstring; exercises 1, 2, 4, 5, 10 | Accepted. The README tells the reader to confirm real decisions with the IAM policy simulator or IAM Access Analyzer. |
| R3 | Remediation actions leave no local record | The function logs a JSON result (`handled`, `dry_run`, per-bucket `action`). The log group has 365-day retention and uses `aws_kms_key.lab_logs`. | `tests/test_remediation.py` | Specified in code and moto tests. Not applied, so there is no live log group. |

### Information disclosure

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| I1 | A bucket is made public after Block Public Access is weakened | EventBridge plus an idempotent Lambda restores all four bucket-level Block Public Access flags. The runbook states that this neutralizes a public bucket policy (`RestrictPublicBuckets`) and public ACLs, and that it does not delete the attacker's bucket policy or disable the access key. | `tests/test_remediation.py` (17 cases, including the loop guard, exemptions, and dry run); exercise 6; the runbook | Partial, with the account-scope lab limit in S1. |
| I2 | An identity outside the organization reads S3, or a request is sent without TLS | RCP: deny listed data-plane actions when `aws:SecureTransport` is false, and deny `s3:*` when `aws:PrincipalOrgID` is not the placeholder org and the principal is not an AWS service. Trail and access-log bucket policies also deny insecure transport. | Exercise 2; policy tests | Specified for member accounts if the RCP is attached. Lab limit: RCPs do not bind the management account that would hold these buckets in the compressed layout. |
| I3 | A principal in the VPC reaches S3, Systems Manager, or Logs without the endpoint policy path, or uses SSH | Gateway and interface endpoint policies: S3 allow is `s3:GetObject`, `s3:GetObjectVersion`, and `s3:ListBucket` when `aws:PrincipalOrgID` matches; Systems Manager endpoints allow the instance-role agent APIs and the operator session APIs only; Logs allow a short list of `logs:*` actions for org principals. App security group: no inbound rules, HTTPS only to the endpoint security group and to `0.0.0.0/0` as an offline stand-in for the regional S3 prefix list. Network ACLs deny SSH and split ephemeral ingress so TCP 3389 is not allowed. | Exercises 9, 10, and 13; policy and plan tests | Partial. The S3 stand-in is documented in `terraform/network.tf` and the README: a live account should use the managed prefix list instead of `0.0.0.0/0`. The S3 endpoint policy does not allow `s3:PutObject`. Public subnets have an internet gateway and a NACL that allows HTTPS from `0.0.0.0/0`; no resource in this lab is placed there, and `map_public_ip_on_launch` is false. |
| I4 | Unencrypted EBS, or use of the EBS key other than through EC2 | Launch template: encrypted root volume with the EBS CMK. Key policy use and `CreateGrant` are conditioned on `kms:ViaService = ec2.<region>.amazonaws.com` (`CreateGrant` also requires `kms:GrantIsForAWSResource`). | Exercise 14 | Specified on the template and key policy. No volume is created. |

### Denial of service

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| D1 | The remediation function loops on its own `PutBucketPublicAccessBlock` call, or is overwhelmed | The handler reads the current configuration first and no-ops when all four flags are already true. Reserved concurrency is 5. EventBridge retry is 4 attempts over 3600 seconds, with a DLQ on the function and on the targets. | `tests/test_remediation.py` loop-guard case | Specified in code and moto tests. Not exercised on real EventBridge or Lambda. |
| D2 | Workloads are created in unapproved Regions | SCP `DenyUnapprovedRegions` (default allow list `us-east-1` and `us-west-2`), with a break-glass exemption and the usual global-service `NotAction` list. | Exercise 1 | Specified for members if the SCP is attached. Does not bind the management account. |
| D3 | Application-layer request floods | WAF web ACL: AWS Managed Rules Known Bad Inputs, Core Rule Set, and a rate-based rule that blocks at 1000 requests per IP. Default action is allow. | Exercise 12; plan tests | Lab limit. The ACL is not associated, so it would not inspect traffic. Shield Standard is documented only. Shield Advanced is not enabled. |

### Elevation of privilege

| ID | Threat | Control in this repo | Tests or exercises | Status |
| --- | --- | --- | --- | --- |
| E1 | A `/app/` role, or the instance profile, escalates into IAM or Organizations | The workload boundary denies `iam:*`, `organizations:*`, and `sts:AssumeRole`. The instance role is the Session Manager agent action set and does not include IAM administration. | Exercises 5 and 13; policy tests | Specified for principals that actually have the boundary attached, and for the instance role as written. |
| E2 | The role creator passes a role to a service other than Lambda, or edits the boundary policy | `PassRole` is limited to `lambda.amazonaws.com`. Boundary policy edits and `DeleteRolePermissionsBoundary` are denied. | Exercise 5; policy tests | Specified for that role's identity policy. |
| E3 | A management-account administrator bypasses the SCP and RCP | AWS does not apply SCPs or RCPs to the management account. This lab also compresses trail, keys, buckets, detection, remediation, and the study VPC into that account's placeholders. | README Limitations; `terraform/governance.tf` comments | Accepted. This is the main residual risk of the compressed layout. |
| E4 | `BreakGlassAdmin` is used to disable telemetry or change Regions | The SCP exempts `arn:aws:iam::*:role/BreakGlassAdmin` (the default name) from telemetry, account Block Public Access, and Region statements. `DenyLeaveOrganization` and `DenyRootUserActions` are not exempted. The lab does not create the role. | Exercise 1 | Accepted. The README and variable description say the role must exist in each member account and be tightly controlled. |
| E5 | Session Manager is used as a broader remote-execution path | The operator policy allows `StartSession`, `TerminateSession`, `ResumeSession`, and describe/status APIs. It does not allow `ssm:SendCommand`. Interface endpoint policies name those session APIs for the operator role only. | Exercise 13; policy tests | Specified in the identity and endpoint policies. `StartSession` is allowed on instances and on `document/*` in the account, not only on `SSM-SessionManagerRunShell`. |

## 6. Limitations the model must state plainly

These are already in the README, domain map, or Terraform comments. They are
repeated here because they change how much of the STRIDE table would hold in
a live organization.

- Plan success is not apply success. An apply would need an existing
  organization with SCPs and RCPs enabled, trusted access for CloudTrail,
  GuardDuty, and Security Hub, and existing `KeyAdmin`, `TerraformDeployer`,
  and `SecurityLogReader` roles (KMS rejects key policies that name principals
  that do not exist).
- `guardrail_target_ids` defaults to `[]`, so the plan creates the SCP and RCP
  and attaches them to no root, OU, or account.
- SCPs and RCPs do not apply to the management account, where this lab places
  the trail, CloudTrail key, and log buckets.
- The policy checker evaluates one policy at a time.
- `aws_guardduty_organization_configuration` is in the same root so the
  offline plan and scanners can see `auto_enable_organization_members = "ALL"`.
  The comment in `terraform/detection.tf` states that applying it from the
  management account would not work. There is no
  `aws_securityhub_organization_configuration` resource. Security Hub in this
  lab is an account-level CSPM enable, the FSBP standard subscription, and a
  delegated-admin assignment.
- Inspector was not run, so there are no scan findings. `enable_inspector`
  defaults to true and would start EC2, ECR, and Lambda scanning in the
  account that applied the root, including existing images or functions.
- The WAF web ACL is unassociated.
- The S3 gateway path cannot resolve the regional managed prefix list
  offline, so the app security group and network ACL temporarily allow HTTPS
  (and, on the NACL, ephemeral return ports excluding 3389) to `0.0.0.0/0`.
- No Network Firewall, CloudFront, Shield Advanced, Image Builder, Patch
  Manager runs, GenAI guardrails, hybrid connectivity, or Verified Access.
- Remediation identity policy is scoped to the management account, as in S1.
- The moto tests exercise the handler and moto's EventBridge matcher, not a
  deployed Lambda or real EventBridge. Sample events are synthetic.

## 7. Residual risk

This section is a reading of the files above. It is not a remediation backlog
for a deployed system, and it does not invent findings from a live account.

The controls that are specified are still useful as study material: member
account guardrails, a locked-down organization trail design, delegated
role-creation with a boundary, an idempotent Block Public Access restorer,
and a Session Manager path that does not issue an SSH key. The residual risk
that a reviewer should not miss is the compression. If this root were applied
as written, SCPs and RCPs would not protect the account that held the trail
and the keys; the GuardDuty organization configuration would be in the wrong
account; the Lambda could not restore Block Public Access on a bucket in a
different account; and the WAF ACL, Inspector enabler, and prefix-list
stand-in would not mean what their names suggest.

Do not apply this lab as-is.

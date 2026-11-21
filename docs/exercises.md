# Exercises

Every exercise runs offline. "Expected" is what this repository produced when the command was run on
November 21, 2026; nothing here was checked against a real AWS account. Run commands from the repo
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
- Run the third command again with `--context aws:RequestedRegion=us-east-1`; the result is `no_match`. Then leave out `aws:RequestedRegion` entirely. The result becomes `explicit_deny` (DenyUnapprovedRegions), because a negated operator is true when the key is missing (IAM condition operator docs). Real requests carry this key; the point is to read negated conditions carefully. The last command stays `no_match` either way, because `iam:*` is in the statement's `NotAction` list.
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

Expected: `Passed checks: 4, Failed checks: 2`, with CKV_AWS_7 failing on `aws_kms_key.cloudtrail` and CKV_AWS_36 on `aws_cloudtrail.org`. The `lab_logs`, `lab_logs_replica`, `ebs`, and `infra_logs` keys still pass CKV_AWS_7. The same command on `terraform/` gives `Passed checks: 6, Failed checks: 0`.

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
(1 failed, 7 passed). Put the line back.

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

Expected: `Passed checks: 339, Failed checks: 0, Skipped checks: 12`. The four directory-mode
failures from the first draft (CKV2_AWS_3, CKV2_AWS_62, CKV_AWS_18, CKV_AWS_144 on the trail bucket)
are fixed. The remaining skips and the 22 plan-mode failures are explained in the README results
section. Optionally run:

```bash
.venv/bin/checkov -f build/plan.json --framework terraform_plan --compact
```

Expected: `Passed checks: 323, Failed checks: 22, Skipped checks: 0` after `./scripts/offline-plan.sh`.
Plan mode ignores the inline skips. Pick one of those 22 and decide whether you agree with the README's
reason for leaving it.

## 9. Security groups and network ACLs (Skills 3.3.1, 3.3.4)

Read `terraform/network.tf`. The study VPC has public, app, and endpoint subnet tiers in two
Availability Zones. App subnets have no route to the internet gateway. The default security group
has no rules. The app security group has no inbound rules and no SSH. The app network ACL has
explicit deny rules for TCP 22 and TCP 3389.

```bash
.venv/bin/pytest -q tests/test_terraform_plan.py -k "security_group or network_acl or workload_vpc"
```

Expected: `4 passed` after `./scripts/offline-plan.sh` (the test file is skipped until the plan exists).

Questions:

- Security groups are stateful and network ACLs are stateless (VPC User Guide, "Control traffic to
  your AWS resources using security groups" and "Control subnet traffic with network access control
  lists"). Why does the app NACL allow inbound TCP 1024-3388 and 3390-65535 from the endpoint
  subnets if the app security group has no inbound rules? (Return traffic for outbound HTTPS to the
  interface endpoints must be allowed at the NACL, because the NACL does not track the connection.
  The security group does, so it does not need a matching inbound rule.)
- Network ACL rules are evaluated when traffic enters or leaves a subnet, not for traffic that stays
  inside one subnet (same NACL page). Why are the interface endpoints in their own subnets?

## 10. VPC endpoints and endpoint policies (Skills 5.1.2, 3.2.5)

The S3 endpoint is a gateway endpoint. Interface endpoints for `ssm`, `ssmmessages`,
`ec2messages`, and `logs` sit in the endpoint subnets with private DNS enabled. The S3 policy uses
`"Principal": "*"` and an `aws:PrincipalOrgID` condition; gateway endpoint policies require a
wildcard principal and restrict callers in `Condition` (VPC endpoint policy docs).

```bash
check --policy vpce-s3 --action s3:GetObject --resource arn:aws:s3:::any-bucket/object \
  --principal-arn arn:aws:iam::111122223333:role/scs-lab-ssm-instance \
  --context aws:PrincipalOrgID=o-exampleorg1
check --policy vpce-s3 --action s3:GetObject --resource arn:aws:s3:::any-bucket/object \
  --principal-arn arn:aws:iam::111122223333:role/scs-lab-ssm-instance
check --policy vpce-ssm --action ssm:UpdateInstanceInformation \
  --principal-arn arn:aws:iam::111122223333:role/scs-lab-ssm-instance
check --policy vpce-ssm --action ssm:StartSession \
  --principal-arn arn:aws:iam::111122223333:role/Developer
```

Expected: `allow` (AllowOrgPrincipalsToS3), `no_match`, `allow` (AllowInstanceRoleAgentApis),
`no_match`.

Question: us-east-1 launched before 2024, so this lab still creates the `ec2messages` endpoint as a
fallback. The Systems Manager "Reference: ec2messages, ssmmessages, and other API operations" page
says that starting with SSM Agent 3.3.40.0 the agent prefers `ssmmessages`, and that Regions
launched in 2024 or later do not support `ec2messages`. What would you drop if this VPC were in a
newer Region?

## 11. VPC flow logs (Task 3.3, not a numbered skill in the guide)

The exam guide does not list VPC flow logs as a numbered skill. They are still the usual way to
investigate whether security groups or network ACLs are allowing or denying traffic (Task 3.3).

```bash
.venv/bin/pytest -q tests/test_terraform_plan.py -k workload_vpc
```

Expected: `1 passed` after the plan exists. The flow log captures `ALL` traffic on the VPC, writes
to a KMS-encrypted CloudWatch log group, and uses a 60-second aggregation interval.

Question: if two ENIs are in the same subnet, will a network ACL show up in the flow logs for
traffic between them? (No. Network ACL rules are not evaluated for intra-subnet traffic, so there
is no NACL accept or reject to record. Security group evaluation still happens at the ENI; this lab
did not capture live flow records, so look at the VPC flow log documentation for how those
accept and reject records are represented.)

## 12. WAF and Shield Standard (Skills 3.1.2, 3.1.3)

```bash
.venv/bin/pytest -q tests/test_terraform_plan.py -k waf_has_managed
```

Expected: `1 passed` after the plan exists. The regional web ACL has
`AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesCommonRuleSet`, and a rate-based rule that
blocks a source IP at 1000 requests in the default five-minute window. It is not associated with an
Application Load Balancer, API Gateway, or CloudFront distribution.

Questions:

- If this lab were applied, would the web ACL inspect any traffic? (No. A web ACL only inspects
  requests after it is associated with a resource.)
- AWS Shield Standard is automatically enabled at no additional charge and defends against common
  network and transport layer DDoS events (Shield Standard overview). Shield Advanced is a paid
  subscription and is not enabled here. Which class of attack is WAF aimed at that Shield Standard
  is not? (Application-layer, layer 7, requests such as the OWASP-style rules in the Core Rule Set
  and the Log4j rules in Known Bad Inputs.)

## 13. Session Manager instead of SSH (Skills 3.2.5, 3.2.2)

The launch template does not set `key_name`. The app security group and network ACL do not allow
TCP 22. The instance profile can create Session Manager channels; it cannot call `ssm:StartSession`.
The operator role can start and terminate sessions, with MFA on the trust policy, and cannot call
`ssm:SendCommand`.

```bash
check --policy iam-ssm-operator --action ssm:StartSession \
  --resource arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0
check --policy iam-ssm-operator --action ssm:SendCommand \
  --resource arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0
check --policy iam-ssm-instance --action ssm:StartSession
check --policy iam-ssm-instance --action ssmmessages:CreateControlChannel
```

Expected: `allow` (StartSessionOnInstances), `no_match`, `no_match`, `allow` (SsmMessagesChannels).

Question: the isolated app subnet has no NAT gateway. What three things in this lab still have to
be true for Session Manager to work without internet access? (Interface endpoints for Systems
Manager, HTTPS from the app security group to those endpoints, and the instance profile
permissions. The `logs` endpoint would also be needed if you added CloudWatch session logging later.)

## 14. IMDSv2 and EBS encryption (Skills 3.2.1, 5.2.1)

```bash
rm -rf /tmp/mut && mkdir /tmp/mut && cp terraform/*.tf /tmp/mut/ && cp -r terraform/policies terraform/event-patterns /tmp/mut/
sed -i 's/http_tokens                 = "required"/http_tokens                 = "optional"/' /tmp/mut/compute.tf
.venv/bin/checkov -d /tmp/mut --framework terraform --check CKV_AWS_79 --compact
```

Expected: `Passed checks: 0, Failed checks: 1` on `aws_launch_template.workload`. The same command
on `terraform/` gives `Passed checks: 1, Failed checks: 0`. The launch template also encrypts the
root volume with `aws_kms_key.ebs`, sets `ebs_optimized`, and does not associate a public IP. No
`aws_instance` is created.

Question: the hop limit is 1. The EC2 "Configure instance metadata options for new instances" page
recommends a hop limit of 2 in a container environment. Why?

## 15. Inspector scanning (Skills 3.2.3, 3.2.4)

```bash
.venv/bin/pytest -q tests/test_terraform_plan.py -k inspector
```

Expected: `1 passed` after the plan exists. `aws_inspector2_enabler.this` is created when
`enable_inspector` is true (the default) and enables `EC2`, `ECR`, and `LAMBDA` scans for the
placeholder management account. Lambda code scanning (`LAMBDA_CODE`) is not enabled. Inspector is a
paid service after any trial period, and this lab did not run a scan, so there are no findings to
report.

Question: Skill 3.3.5 mentions Inspector network reachability findings. What would still be missing
here even after a successful apply? (No instance is launched from the template, so there is no EC2
resource for Inspector to assess.)

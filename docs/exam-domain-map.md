# SCS-C03 exam domain map

Source: AWS Certified Security - Specialty Exam Guide (SCS-C03), version 1.0, published March 26, 2026,
https://docs.aws.amazon.com/pdfs/aws-certification/latest/security-specialty-03/security-specialty-03.pdf (the PDF of https://docs.aws.amazon.com/aws-certification/latest/security-specialty-03/security-specialty-03.html , which is linked from https://aws.amazon.com/certification/certified-security-specialty/ ). Both were read on
November 17, 2026. The guide says SCS-C03 replaced SCS-C02 on December 2, 2025. Skill numbers below are
the guide's. The guide says it "does not provide a comprehensive list of the content on the exam".

| Domain (weight) | Skills this lab touches | Where |
| --- | --- | --- |
| 1 Detection (16%) | 1.1.3 aggregate security events; 1.1.4 GuardDuty and Security Hub alerts; 1.2.2 organization trail | `terraform/detection.tf`, `terraform/logging.tf`, `terraform/log-archive.tf`, exercises 3 and 7 |
| 2 Incident Response (14%) | 2.1.1 runbook; 2.1.4 automatic remediation with Lambda; 2.2.2 search and correlate logs; 2.2.4 contain and recover | `terraform/remediation.tf`, `lambda/`, `docs/runbook-s3-public-exposure.md`, exercise 6 |
| 3 Infrastructure Security (18%) | 3.1.2 and 3.1.3 WAF managed rules and rate limiting (Shield Standard is documented only); 3.2.1 hardened launch template (IMDSv2); 3.2.2 instance profile and operator role; 3.2.3 and 3.2.4 Inspector v2 enabler; 3.2.5 Session Manager instead of SSH; 3.3.1 and 3.3.4 security groups, network ACLs, and isolated subnets | `terraform/network.tf`, `terraform/compute.tf`, `terraform/edge.tf`, exercises 9 to 15 |
| 4 Identity and Access Management (20%) | 4.2.1 role trust policies; 4.2.3 least privilege with permission boundaries; 4.2.4 analyze authorization failures | `terraform/identity.tf`, `src/scs_lab/policy_eval.py`, exercise 5 |
| 5 Data Protection (18%) | 5.1.1 require TLS; 5.1.2 VPC endpoints and endpoint policies; 5.2.1 SSE-KMS and EBS encryption with a customer managed key; 5.2.2 integrity (versioning, log file validation); 5.2.3 lifecycle; 5.3.5 customer managed keys | `terraform/logging.tf`, `terraform/log-archive.tf`, `terraform/network.tf`, `terraform/compute.tf`, `terraform/policies/kms-cloudtrail-key-policy.json.tftpl`, exercises 2 to 4, 10 and 14 |
| 6 Security Foundations and Governance (14%) | 6.1.3 SCPs and RCPs; 6.1.4 delegated administrators; 6.2.1 IaC with scanners; 6.2.2 tags; 6.3.1 detect and remediate noncompliance | `terraform/governance.tf`, `terraform/detection.tf`, `.tflint.hcl`, exercises 1, 2 and 8 |

## Not covered

Domain 3 still does not cover Network Firewall, CloudFront, Shield Advanced, Image Builder AMI
pipelines, Patch Manager runs, GenAI guardrails, hybrid connectivity (Site-to-Site VPN, Direct
Connect, MACsec), or AWS Verified Access. The WAF web ACL is not associated with a load balancer
or distribution, so it would not inspect traffic. No EC2 instance is created, and Inspector was
not run against a live account, so there are no scan or network-reachability findings. Also not
covered: IAM Identity Center, Cognito, Secrets Manager rotation, imported key material and
external key stores, Macie, Security Lake, Detective, AWS Config conformance packs, Control Tower,
Audit Manager and Artifact.
The single-account CloudTrail, KMS, S3 and auditor-role baseline lives in
[mikedsosa/aws-audit-baseline](https://github.com/mikedsosa/aws-audit-baseline) and is not repeated here.

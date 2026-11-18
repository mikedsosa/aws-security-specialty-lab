# SCS-C03 exam domain map

Source: AWS Certified Security - Specialty Exam Guide (SCS-C03), version 1.0, published March 26, 2026,
https://docs.aws.amazon.com/pdfs/aws-certification/latest/security-specialty-03/security-specialty-03.pdf (the PDF of https://docs.aws.amazon.com/aws-certification/latest/security-specialty-03/security-specialty-03.html , which is linked from https://aws.amazon.com/certification/certified-security-specialty/ ). Both were read on
November 17, 2026. The guide says SCS-C03 replaced SCS-C02 on December 2, 2025. Skill numbers below are
the guide's. The guide says it "does not provide a comprehensive list of the content on the exam".

| Domain (weight) | Skills this lab touches | Where |
| --- | --- | --- |
| 1 Detection (16%) | 1.1.3 aggregate security events; 1.1.4 GuardDuty and Security Hub alerts; 1.2.2 organization trail | `terraform/detection.tf`, `terraform/logging.tf`, `terraform/log-archive.tf`, exercises 3 and 7 |
| 2 Incident Response (14%) | 2.1.1 runbook; 2.1.4 automatic remediation with Lambda; 2.2.2 search and correlate logs; 2.2.4 contain and recover | `terraform/remediation.tf`, `lambda/`, `docs/runbook-s3-public-exposure.md`, exercise 6 |
| 3 Infrastructure Security (18%) | 3.2.2 execution roles (the remediation role only) | `terraform/remediation.tf` |
| 4 Identity and Access Management (20%) | 4.2.1 role trust policies; 4.2.3 least privilege with permission boundaries; 4.2.4 analyze authorization failures | `terraform/identity.tf`, `src/scs_lab/policy_eval.py`, exercise 5 |
| 5 Data Protection (18%) | 5.1.1 require TLS; 5.2.1 SSE-KMS; 5.2.2 integrity (versioning, log file validation); 5.2.3 lifecycle; 5.3.5 customer managed keys | `terraform/logging.tf`, `terraform/log-archive.tf`, `terraform/policies/kms-cloudtrail-key-policy.json.tftpl`, exercises 2 to 4 |
| 6 Security Foundations and Governance (14%) | 6.1.3 SCPs and RCPs; 6.1.4 delegated administrators; 6.2.1 IaC with scanners; 6.2.2 tags; 6.3.1 detect and remediate noncompliance | `terraform/governance.tf`, `terraform/detection.tf`, `.tflint.hcl`, exercises 1, 2 and 8 |

## Not covered

Domain 3 is the thinnest: there is no network edge (WAF, CloudFront, Shield), VPC, Network Firewall,
EC2 hardening, Inspector, Systems Manager or GenAI guardrail content. Also not covered: IAM Identity
Center, Cognito, Secrets Manager rotation, imported key material and external key stores, Macie,
Security Lake, Detective, AWS Config conformance packs, Control Tower, Audit Manager and Artifact.
The single-account CloudTrail, KMS, S3 and auditor-role baseline lives in
[mikedsosa/aws-audit-baseline](https://github.com/mikedsosa/aws-audit-baseline) and is not repeated here.

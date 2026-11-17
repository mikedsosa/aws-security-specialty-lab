# Notices

- The `NotAction` list in the `DenyUnapprovedRegions` statement of
  `terraform/policies/scp-guardrails.json.tftpl`, and the action list pattern of the
  `ProtectSecurityTelemetry` statement, are adapted from
  [aws-samples/service-control-policy-examples](https://github.com/aws-samples/service-control-policy-examples)
  (commit 088df0b0812c55bb0b90824c155776dfdf690404), sample code under the MIT-0 license.
- The `EnforceSecureTransport` statement in `terraform/policies/rcp-data-perimeter.json.tftpl` is adapted
  (with a shorter service list) from
  [aws-samples/resource-control-policy-examples](https://github.com/aws-samples/resource-control-policy-examples)
  (commit f0d069806abfdfb37d5543a742ef7a5a9dfdf554), sample code under the MIT-0 license.
- The CloudTrail KMS key policy and bucket policy statements follow the examples on the AWS CloudTrail
  pages "Configure AWS KMS key policies for CloudTrail" and "Amazon S3 bucket policy for CloudTrail",
  read on November 17, 2026.

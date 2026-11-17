# Domain 6 (Security Foundations and Governance): organization policies.
# Assumes an existing organization with SCPs and RCPs enabled. SCPs and RCPs
# do not apply to the management account, so the protections here are for
# member accounts only.

resource "aws_organizations_policy" "guardrails" {
  name        = "${var.name_prefix}-guardrails"
  description = "Deny leaving the org, root user actions, security telemetry tampering, account BPA changes and unapproved Regions."
  type        = "SERVICE_CONTROL_POLICY"
  content = templatefile("${path.module}/policies/scp-guardrails.json.tftpl", {
    break_glass_role_name = var.break_glass_role_name
    allowed_regions       = var.allowed_regions
  })
}

resource "aws_organizations_policy" "data_perimeter" {
  name        = "${var.name_prefix}-data-perimeter"
  description = "Deny non-TLS requests and S3 access from identities outside the organization."
  type        = "RESOURCE_CONTROL_POLICY"
  content = templatefile("${path.module}/policies/rcp-data-perimeter.json.tftpl", {
    organization_id = var.organization_id
  })
}

resource "aws_organizations_policy_attachment" "guardrails" {
  for_each  = toset(var.guardrail_target_ids)
  policy_id = aws_organizations_policy.guardrails.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "data_perimeter" {
  for_each  = toset(var.guardrail_target_ids)
  policy_id = aws_organizations_policy.data_perimeter.id
  target_id = each.value
}

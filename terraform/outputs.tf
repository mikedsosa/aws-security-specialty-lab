output "guardrail_scp_id" {
  value = aws_organizations_policy.guardrails.id
}

output "data_perimeter_rcp_id" {
  value = aws_organizations_policy.data_perimeter.id
}

output "trail_arn" {
  value = local.trail_arn
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.bucket
}

output "workload_boundary_arn" {
  value = local.boundary_policy_arn
}

output "remediation_function" {
  value = local.remediation_function_name
}

output "workload_vpc_id" {
  value = aws_vpc.workload.id
}

output "workload_launch_template_name_prefix" {
  value = aws_launch_template.workload.name_prefix
}

output "waf_web_acl_arn" {
  value = aws_wafv2_web_acl.edge.arn
}

output "ssm_operator_role_arn" {
  value = local.ssm_operator_role_arn
}

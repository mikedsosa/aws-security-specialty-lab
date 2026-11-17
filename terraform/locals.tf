locals {
  partition = "aws"

  trail_arn         = "arn:${local.partition}:cloudtrail:${var.region}:${var.management_account_id}:trail/${var.trail_name}"
  trail_bucket_name = "${var.name_prefix}-org-trail-${var.management_account_id}"

  key_admin_arns = [
    "arn:${local.partition}:iam::${var.management_account_id}:role/${var.key_admin_role_name}",
    "arn:${local.partition}:iam::${var.management_account_id}:role/${var.deployer_role_name}",
  ]
  log_reader_arn = "arn:${local.partition}:iam::${var.security_account_id}:role/${var.log_reader_role_name}"

  boundary_policy_name = "${var.name_prefix}-workload-boundary"
  boundary_policy_arn  = "arn:${local.partition}:iam::${var.management_account_id}:policy/${local.boundary_policy_name}"
  workload_role_path   = "/app/"

  remediation_function_name = "${var.name_prefix}-remediate-s3-bpa"
}

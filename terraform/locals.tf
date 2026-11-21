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

  access_logs_bucket_name         = "${var.name_prefix}-org-trail-access-logs-${var.management_account_id}"
  trail_replica_bucket_name       = "${var.name_prefix}-org-trail-replica-${var.management_account_id}"
  replica_access_logs_bucket_name = "${var.name_prefix}-org-trail-replica-access-logs-${var.management_account_id}"
  replication_role_name           = "${var.name_prefix}-s3-replication"
  replication_role_arn            = "arn:${local.partition}:iam::${var.management_account_id}:role/${local.replication_role_name}"
  remediation_log_group_name      = "/aws/lambda/${local.remediation_function_name}"
  remediation_log_group_arn       = "arn:${local.partition}:logs:${var.region}:${var.management_account_id}:log-group:${local.remediation_log_group_name}"

  # Two Availability Zones, named directly so the plan does not look up AZs.
  workload_azs = ["${var.region}a", "${var.region}b"]

  public_subnet_cidrs   = [cidrsubnet(var.workload_vpc_cidr, 8, 0), cidrsubnet(var.workload_vpc_cidr, 8, 1)]
  app_subnet_cidrs      = [cidrsubnet(var.workload_vpc_cidr, 8, 10), cidrsubnet(var.workload_vpc_cidr, 8, 11)]
  endpoint_subnet_cidrs = [cidrsubnet(var.workload_vpc_cidr, 8, 20), cidrsubnet(var.workload_vpc_cidr, 8, 21)]

  ssm_instance_role_name = "${var.name_prefix}-ssm-instance"
  ssm_instance_role_arn  = "arn:${local.partition}:iam::${var.management_account_id}:role/${local.ssm_instance_role_name}"
  ssm_operator_role_name = "${var.name_prefix}-ssm-operator"
  ssm_operator_role_arn  = "arn:${local.partition}:iam::${var.management_account_id}:role/${local.ssm_operator_role_name}"

  flow_logs_log_group_name = "/aws/vpc/${var.name_prefix}-flow-logs"
  flow_logs_log_group_arn  = "arn:${local.partition}:logs:${var.region}:${var.management_account_id}:log-group:${local.flow_logs_log_group_name}"
  waf_log_group_name       = "aws-waf-logs-${var.name_prefix}"
  waf_log_group_arn        = "arn:${local.partition}:logs:${var.region}:${var.management_account_id}:log-group:${local.waf_log_group_name}"

  ssm_interface_endpoint_services = ["ssm", "ssmmessages", "ec2messages"]
}

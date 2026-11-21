# Domain 3 (Infrastructure Security) and Skill 5.1.2 (private access with
# VPC endpoints): a study VPC with isolated application subnets, a dedicated
# endpoint subnet tier, security groups, network ACLs, VPC flow logs, and
# interface plus gateway endpoints. Nothing here has been applied. In a real
# organization this VPC would live in a workload account, not the management
# account this compressed lab uses.

resource "aws_vpc" "workload" {
  cidr_block           = var.workload_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-workload"
  }
}

# Remove the default security group's allow-all-inside / allow-all-out rules.
# Workload resources use the named security groups below, not this one.
resource "aws_default_security_group" "workload" {
  vpc_id = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-default-unused"
  }
}

resource "aws_internet_gateway" "workload" {
  vpc_id = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  for_each = {
    for idx, cidr in local.public_subnet_cidrs :
    idx => { cidr = cidr, az = local.workload_azs[idx] }
  }

  vpc_id                  = aws_vpc.workload.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-public-${each.value.az}"
    Tier = "public"
  }
}

resource "aws_subnet" "app" {
  for_each = {
    for idx, cidr in local.app_subnet_cidrs :
    idx => { cidr = cidr, az = local.workload_azs[idx] }
  }

  vpc_id                  = aws_vpc.workload.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-app-${each.value.az}"
    Tier = "app"
  }
}

resource "aws_subnet" "endpoint" {
  for_each = {
    for idx, cidr in local.endpoint_subnet_cidrs :
    idx => { cidr = cidr, az = local.workload_azs[idx] }
  }

  vpc_id                  = aws_vpc.workload.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-endpoint-${each.value.az}"
    Tier = "endpoint"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_route" "public_ipv4_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.workload.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Isolated private route tables: no internet gateway and no NAT gateway.
# Systems Manager and CloudWatch Logs are reached through interface endpoints.
# S3 is reached through the gateway endpoint associated below.
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-app"
  }
}

resource "aws_route_table_association" "app" {
  for_each       = aws_subnet.app
  subnet_id      = each.value.id
  route_table_id = aws_route_table.app.id
}

resource "aws_route_table" "endpoint" {
  vpc_id = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-endpoint"
  }
}

resource "aws_route_table_association" "endpoint" {
  for_each       = aws_subnet.endpoint
  subnet_id      = each.value.id
  route_table_id = aws_route_table.endpoint.id
}

# --- Security groups -----------------------------------------------------------
# AWS adds an ALLOW ALL egress rule when it creates a VPC security group. The
# AWS provider 5.100.0 revokes that default IPv4 (and IPv6, if present) rule
# during create, then keeps only rules we define. This lab uses standalone
# aws_vpc_security_group_*_rule resources (no inline ingress/egress blocks, which
# would conflict). The offline plan cannot show the revoke (egress is unknown
# until apply). See the provider aws_security_group docs, "NOTE on Egress rules."

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-vpce"
  description = "Inbound HTTPS from the app security group to interface VPC endpoints. No egress rules; return traffic is stateful."
  vpc_id      = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-vpce"
  }
}

resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app"
  description = "Workload ENIs: no inbound paths, HTTPS only to VPC endpoints, no SSH."
  vpc_id      = aws_vpc.workload.id

  tags = {
    Name = "${var.name_prefix}-app"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_app" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from app instances to interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_egress_rule" "app_https_to_endpoints" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTPS to Systems Manager and Logs interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints.id
}

# S3 gateway endpoints resolve to public S3 prefix-list addresses, not to the
# endpoint security group. The AWS-managed prefix list ID cannot be looked up
# offline, so this rule allows 443/tcp to 0.0.0.0/0. A live account would use
# the com.amazonaws.<region>.s3 prefix list instead of 0.0.0.0/0.
resource "aws_vpc_security_group_egress_rule" "app_https_to_s3_standin" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to S3 via the gateway endpoint; 0.0.0.0/0 stands in for the regional S3 prefix list, which cannot be looked up offline"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Network ACLs --------------------------------------------------------------
# Security groups are stateful; network ACLs are stateless (VPC User Guide).
# Traffic that stays inside one subnet is not evaluated by a NACL, which is why
# interface endpoints are placed in their own subnets.

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.workload.id
  subnet_ids = [for s in aws_subnet.public : s.id]

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_network_acl_rule" "public_ingress_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_ingress_deny_ssh" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "public_egress_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_egress_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl" "app" {
  vpc_id     = aws_vpc.workload.id
  subnet_ids = [for s in aws_subnet.app : s.id]

  tags = {
    Name = "${var.name_prefix}-app"
  }
}

resource "aws_network_acl_rule" "app_egress_https_to_endpoints" {
  count          = length(local.endpoint_subnet_cidrs)
  network_acl_id = aws_network_acl.app.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.endpoint_subnet_cidrs[count.index]
  from_port      = 443
  to_port        = 443
}

# S3 gateway destinations are public S3 addresses. Without an offline prefix
# list lookup, 443/tcp to 0.0.0.0/0 is the honest stand-in; a live account
# would use the regional S3 prefix list.
resource "aws_network_acl_rule" "app_egress_https_to_s3_standin" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 120
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "app_egress_deny_ssh" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 200
  egress         = true
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "app_ingress_ephemeral_from_endpoints" {
  count          = length(local.endpoint_subnet_cidrs)
  network_acl_id = aws_network_acl.app.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.endpoint_subnet_cidrs[count.index]
  from_port      = 1024
  to_port        = 65535
}

# Return traffic for the S3 gateway stand-in. The range is split so it does
# not include TCP 3389 (RDP). A live account would use the S3 prefix list
# instead of 0.0.0.0/0.
resource "aws_network_acl_rule" "app_ingress_ephemeral_from_s3_standin_low" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 3388
}

resource "aws_network_acl_rule" "app_ingress_ephemeral_from_s3_standin_high" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 130
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3390
  to_port        = 65535
}

resource "aws_network_acl_rule" "app_ingress_deny_ssh" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "app_ingress_deny_rdp" {
  network_acl_id = aws_network_acl.app.id
  rule_number    = 210
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}

resource "aws_network_acl" "endpoint" {
  vpc_id     = aws_vpc.workload.id
  subnet_ids = [for s in aws_subnet.endpoint : s.id]

  tags = {
    Name = "${var.name_prefix}-endpoint"
  }
}

resource "aws_network_acl_rule" "endpoint_ingress_https_from_app" {
  count          = length(local.app_subnet_cidrs)
  network_acl_id = aws_network_acl.endpoint.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_subnet_cidrs[count.index]
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "endpoint_egress_ephemeral_to_app" {
  count          = length(local.app_subnet_cidrs)
  network_acl_id = aws_network_acl.endpoint.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_subnet_cidrs[count.index]
  from_port      = 1024
  to_port        = 65535
}

# --- VPC endpoints -------------------------------------------------------------

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.workload.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app.id, aws_route_table.endpoint.id]
  policy = templatefile("${path.module}/policies/vpce-s3.json.tftpl", {
    organization_id = var.organization_id
  })

  tags = {
    Name = "${var.name_prefix}-s3"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(local.ssm_interface_endpoint_services)

  vpc_id              = aws_vpc.workload.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.endpoint : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy = templatefile("${path.module}/policies/vpce-ssm.json.tftpl", {
    instance_role_arn = local.ssm_instance_role_arn
    operator_role_arn = local.ssm_operator_role_arn
  })

  tags = {
    Name = "${var.name_prefix}-${each.value}"
  }
}

# CloudWatch Logs honors endpoint policies. The SSM policy must not be attached
# here, because it would implicitly deny logs:* (CloudWatch Logs VPC endpoint docs).
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.workload.id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.endpoint : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy = templatefile("${path.module}/policies/vpce-logs.json.tftpl", {
    organization_id = var.organization_id
  })

  tags = {
    Name = "${var.name_prefix}-logs"
  }
}

# --- VPC flow logs -------------------------------------------------------------

resource "aws_kms_key" "infra_logs" {
  description             = "${var.name_prefix} VPC flow logs and WAF logs"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/policies/kms-infra-logs-key-policy.json.tftpl", {
    key_admin_arns        = local.key_admin_arns
    region                = var.region
    management_account_id = var.management_account_id
    log_group_arns        = [local.flow_logs_log_group_arn, local.waf_log_group_arn]
  })
}

resource "aws_kms_alias" "infra_logs" {
  name          = "alias/${var.name_prefix}-infra-logs"
  target_key_id = aws_kms_key.infra_logs.key_id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = local.flow_logs_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.infra_logs.arn
}

data "aws_iam_policy_document" "flow_logs_trust" {
  statement {
    sid     = "VpcFlowLogsAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name_prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_trust.json
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs"
  role = aws_iam_role.flow_logs.id
  policy = templatefile("${path.module}/policies/iam-vpc-flow-logs.json.tftpl", {
    log_group_arn = local.flow_logs_log_group_arn
  })
}

resource "aws_flow_log" "workload" {
  vpc_id                   = aws_vpc.workload.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
}

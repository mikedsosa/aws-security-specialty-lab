# Domain 3 compute controls (Skills 3.2.1, 3.2.2, 3.2.3, 3.2.4, 3.2.5) and
# Skill 5.2.1 (EBS encryption). A launch template requires IMDSv2, encrypts
# the root volume with a customer managed key, attaches an instance profile
# for Systems Manager Session Manager, and does not set a key pair. No
# aws_instance is created, so a later apply of this module would not start a
# billed instance by itself. Inspector v2 is gated because it is a paid
# service after any trial period.

resource "aws_kms_key" "ebs" {
  description             = "${var.name_prefix} EBS volume encryption"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/policies/kms-ebs-key-policy.json.tftpl", {
    key_admin_arns = local.key_admin_arns
    ebs_user_arns = concat(local.key_admin_arns, [
      local.ssm_instance_role_arn,
    ])
    region = var.region
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

data "aws_iam_policy_document" "ssm_instance_trust" {
  statement {
    sid     = "Ec2Assume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "ssm_instance" {
  name        = local.ssm_instance_role_name
  description = "SSM Agent permissions for Session Manager in an isolated subnet."
  policy      = templatefile("${path.module}/policies/iam-ssm-instance.json.tftpl", {})
}

resource "aws_iam_role" "ssm_instance" {
  name               = local.ssm_instance_role_name
  assume_role_policy = data.aws_iam_policy_document.ssm_instance_trust.json
}

resource "aws_iam_role_policy_attachment" "ssm_instance" {
  role       = aws_iam_role.ssm_instance.name
  policy_arn = aws_iam_policy.ssm_instance.arn
}

resource "aws_iam_instance_profile" "ssm" {
  name = local.ssm_instance_role_name
  role = aws_iam_role.ssm_instance.name
}

data "aws_iam_policy_document" "ssm_operator_trust" {
  statement {
    sid     = "SameAccountWithMfa"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.management_account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "ssm_operator" {
  name        = local.ssm_operator_role_name
  description = "Start and manage Session Manager sessions. No SSH or SSM SendCommand."
  policy = templatefile("${path.module}/policies/iam-ssm-operator.json.tftpl", {
    region     = var.region
    account_id = var.management_account_id
  })
}

resource "aws_iam_role" "ssm_operator" {
  name                 = local.ssm_operator_role_name
  assume_role_policy   = data.aws_iam_policy_document.ssm_operator_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "ssm_operator" {
  role       = aws_iam_role.ssm_operator.name
  policy_arn = aws_iam_policy.ssm_operator.arn
}

resource "aws_launch_template" "workload" {
  name_prefix   = "${var.name_prefix}-workload-"
  description   = "Study launch template: IMDSv2 required, EBS encrypted, Session Manager, no SSH key."
  image_id      = var.workload_ami_id
  instance_type = "t3.micro"

  iam_instance_profile {
    name = aws_iam_instance_profile.ssm.name
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  monitoring {
    enabled = true
  }

  ebs_optimized = true

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 8
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
      delete_on_termination = true
    }
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.app.id]
    delete_on_termination       = true
  }

  # No key_name: administrative access is Session Manager, not SSH.

  tags = {
    Name = "${var.name_prefix}-workload"
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.name_prefix}-workload"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.name_prefix}-workload"
    }
  }
}

resource "aws_inspector2_enabler" "this" {
  count          = var.enable_inspector ? 1 : 0
  account_ids    = [var.management_account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

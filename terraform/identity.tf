# Domain 4 (Identity and Access Management): delegated role creation that
# is only allowed when the new role carries the workload permission boundary.

resource "aws_iam_policy" "workload_boundary" {
  name        = local.boundary_policy_name
  description = "Maximum permissions for roles created by the delegated role creator."
  policy = templatefile("${path.module}/policies/iam-workload-boundary.json.tftpl", {
    name_prefix = var.name_prefix
    region      = var.region
    account_id  = var.management_account_id
  })
}

resource "aws_iam_policy" "role_creator" {
  name        = "${var.name_prefix}-role-creator"
  description = "Create and manage /app/ roles only when they carry the workload boundary."
  policy = templatefile("${path.module}/policies/iam-role-creator.json.tftpl", {
    account_id          = var.management_account_id
    workload_role_path  = local.workload_role_path
    boundary_policy_arn = local.boundary_policy_arn
  })
}

data "aws_iam_policy_document" "role_creator_trust" {
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

resource "aws_iam_role" "role_creator" {
  name                 = "${var.name_prefix}-role-creator"
  assume_role_policy   = data.aws_iam_policy_document.role_creator_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "role_creator" {
  role       = aws_iam_role.role_creator.name
  policy_arn = aws_iam_policy.role_creator.arn
}

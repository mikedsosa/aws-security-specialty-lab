# Domain 2 (Incident Response, Skill 2.1.4) and Domain 6 (Skill 6.3.1):
# EventBridge sends S3 Block Public Access changes (from CloudTrail) and the
# matching GuardDuty finding to a Lambda function that turns bucket-level
# Block Public Access back on. The function is idempotent, so its own
# PutBucketPublicAccessBlock call does not cause a remediation loop.

data "archive_file" "remediation" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediate_s3_bpa/handler.py"
  output_path = "${path.module}/../build/remediate_s3_bpa.zip"
}

resource "aws_sqs_queue" "remediation_dlq" {
  name                      = "${var.name_prefix}-remediation-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_cloudwatch_log_group" "remediation" {
  name              = local.remediation_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lab_logs.arn
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.management_account_id]
    }
  }
}

resource "aws_iam_role" "remediation" {
  name               = "${local.remediation_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "remediation" {
  name = "remediate-s3-bpa"
  role = aws_iam_role.remediation.id
  policy = templatefile("${path.module}/policies/lambda-remediation-role.json.tftpl", {
    account_id    = var.management_account_id
    region        = var.region
    function_name = local.remediation_function_name
    dlq_arn       = aws_sqs_queue.remediation_dlq.arn
  })
}

resource "aws_lambda_function" "remediation" {
  #checkov:skip=CKV_AWS_117:The function only calls the S3 control plane; a VPC adds NAT or endpoint cost without reducing exposure here.
  #checkov:skip=CKV_AWS_272:Code signing needs AWS Signer and a signing profile; out of scope for an offline lab.
  #checkov:skip=CKV_AWS_173:Environment variables hold bucket names and a dry-run flag, not secrets.
  function_name                  = local.remediation_function_name
  role                           = aws_iam_role.remediation.arn
  runtime                        = "python3.12"
  handler                        = "handler.lambda_handler"
  filename                       = data.archive_file.remediation.output_path
  source_code_hash               = data.archive_file.remediation.output_base64sha256
  timeout                        = 30
  memory_size                    = 128
  reserved_concurrent_executions = 5

  environment {
    variables = {
      EXEMPT_BUCKETS = join(",", var.remediation_exempt_buckets)
      DRY_RUN        = var.remediation_dry_run ? "true" : "false"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.remediation_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.remediation, aws_iam_role_policy.remediation]
}

locals {
  remediation_rules = {
    s3-bpa-api-change         = "${path.module}/event-patterns/s3-bpa-api-change.json"
    guardduty-s3-bpa-disabled = "${path.module}/event-patterns/guardduty-s3-bpa-disabled.json"
  }
}

resource "aws_cloudwatch_event_rule" "remediation" {
  for_each      = local.remediation_rules
  name          = "${var.name_prefix}-${each.key}"
  description   = "Route ${each.key} events to the S3 Block Public Access remediation function."
  event_pattern = file(each.value)
}

resource "aws_cloudwatch_event_target" "remediation" {
  for_each = local.remediation_rules
  rule     = aws_cloudwatch_event_rule.remediation[each.key].name
  arn      = aws_lambda_function.remediation.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 4
  }

  dead_letter_config {
    arn = aws_sqs_queue.remediation_dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  for_each      = local.remediation_rules
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation[each.key].arn
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid     = "AllowEventBridgeTargetDlq"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.remediation_dlq.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for r in aws_cloudwatch_event_rule.remediation : r.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "remediation_dlq" {
  queue_url = aws_sqs_queue.remediation_dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

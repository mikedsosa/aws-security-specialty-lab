# Domain 1 (Detection) and Domain 6 (central management of security
# services). In a real organization the delegated-admin resources run in the
# management account and the detector settings in the security account; this
# lab keeps them in one root so the plan is easy to read. Both services are
# billed after their trial periods.

resource "aws_guardduty_detector" "this" {
  count                        = var.enable_detection_services ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  count       = var.enable_detection_services ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_organization_admin_account" "security" {
  count            = var.enable_detection_services ? 1 : 0
  admin_account_id = var.security_account_id
}

resource "aws_securityhub_account" "this" {
  count                    = var.enable_detection_services ? 1 : 0
  enable_default_standards = false
  auto_enable_controls     = true
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_detection_services ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_organization_admin_account" "security" {
  count            = var.enable_detection_services ? 1 : 0
  admin_account_id = var.security_account_id
  depends_on       = [aws_securityhub_account.this]
}

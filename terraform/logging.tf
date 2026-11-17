# Domain 1 (Detection) and Domain 5 (Data Protection): organization trail
# with log file integrity validation, a customer managed key, and a locked
# down log bucket. aws-audit-baseline covers the single-account version.

resource "aws_kms_key" "cloudtrail" {
  description             = "${var.name_prefix} organization trail logs"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/policies/kms-cloudtrail-key-policy.json.tftpl", {
    key_admin_arns        = local.key_admin_arns
    trail_arn             = local.trail_arn
    management_account_id = var.management_account_id
    log_reader_arn        = local.log_reader_arn
    region                = var.region
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.name_prefix}-org-trail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

resource "aws_s3_bucket" "trail" {
  bucket = local.trail_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "archive-logs"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = templatefile("${path.module}/policies/s3-trail-bucket-policy.json.tftpl", {
    bucket_name           = aws_s3_bucket.trail.bucket
    trail_arn             = local.trail_arn
    management_account_id = var.management_account_id
    organization_id       = var.organization_id
    log_reader_arn        = local.log_reader_arn
  })

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "org" {
  #checkov:skip=CKV2_AWS_10:CloudWatch Logs delivery is a paid add-on; EventBridge already receives management events for the remediation path.
  #checkov:skip=CKV_AWS_252:No SNS topic; delivery notifications are out of scope for this lab.
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# Account-level S3 Block Public Access for the account this root runs in.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

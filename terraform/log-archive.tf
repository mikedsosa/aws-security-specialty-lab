# Access logging, EventBridge notifications, and cross-Region replication
# for the organization trail bucket (checkov CKV_AWS_18, CKV2_AWS_62,
# CKV_AWS_144). Access-log destination buckets use SSE-S3, as AWS requires,
# and do not log to themselves. In a real organization the access-log
# bucket, replica bucket and replica key usually live in a log-archive
# account in a second Region. This lab keeps them in one root so the
# offline plan stays readable. Nothing here has been applied.

resource "aws_kms_key" "lab_logs" {
  description             = "${var.name_prefix} Lambda log group"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/policies/kms-lab-logs-key-policy.json.tftpl", {
    key_admin_arns        = local.key_admin_arns
    region                = var.region
    management_account_id = var.management_account_id
    log_group_arn         = local.remediation_log_group_arn
  })
}

resource "aws_kms_alias" "lab_logs" {
  name          = "alias/${var.name_prefix}-lab-logs"
  target_key_id = aws_kms_key.lab_logs.key_id
}

resource "aws_kms_key" "lab_logs_replica" {
  provider                = aws.replica
  description             = "${var.name_prefix} trail bucket replica encryption"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/policies/kms-lab-logs-replica-key-policy.json.tftpl", {
    key_admin_arns       = local.key_admin_arns
    replica_region       = var.replica_region
    replication_role_arn = local.replication_role_arn
    log_reader_arn       = local.log_reader_arn
  })
}

resource "aws_kms_alias" "lab_logs_replica" {
  provider      = aws.replica
  name          = "alias/${var.name_prefix}-lab-logs-replica"
  target_key_id = aws_kms_key.lab_logs_replica.key_id
}

# --- access-log bucket (home Region) -----------------------------------------

resource "aws_s3_bucket" "access_logs" {
  bucket = local.access_logs_bucket_name

  #checkov:skip=CKV_AWS_144:This is the access-log target for the trail bucket. A further replica would be a third copy and is out of scope for this lab.
  #checkov:skip=CKV_AWS_18:AWS recommends against a server access log destination logging to itself. This bucket is the destination for the trail bucket.
  #checkov:skip=CKV_AWS_145:AWS requires a server access log destination bucket to use SSE-S3, not SSE-KMS.
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "archive-access-logs"
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

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = templatefile("${path.module}/policies/s3-access-logs-bucket-policy.json.tftpl", {
    bucket_name           = aws_s3_bucket.access_logs.bucket
    trail_bucket_name     = aws_s3_bucket.trail.bucket
    management_account_id = var.management_account_id
    log_reader_arn        = local.log_reader_arn
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

# This bucket is the server access log destination for the trail bucket.
# AWS recommends against a destination logging to itself, so there is no
# aws_s3_bucket_logging resource on it.

resource "aws_s3_bucket_notification" "access_logs" {
  bucket      = aws_s3_bucket.access_logs.id
  eventbridge = true
}

# --- trail bucket: access logging and EventBridge ----------------------------

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "org-trail/"
}

resource "aws_s3_bucket_notification" "trail" {
  bucket      = aws_s3_bucket.trail.id
  eventbridge = true
}

# --- replica bucket (second Region) ------------------------------------------

resource "aws_s3_bucket" "trail_replica" {
  provider = aws.replica
  bucket   = local.trail_replica_bucket_name

  #checkov:skip=CKV_AWS_144:This bucket is the replication destination. Bidirectional replication is not added, so a second hop would be a third copy.
}

resource "aws_s3_bucket_ownership_controls" "trail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.trail_replica.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.trail_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.trail_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.trail_replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lab_logs_replica.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.trail_replica.id

  rule {
    id     = "archive-replica-logs"
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

  depends_on = [aws_s3_bucket_versioning.trail_replica]
}

resource "aws_s3_bucket_policy" "trail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.trail_replica.id
  policy = templatefile("${path.module}/policies/s3-trail-replica-bucket-policy.json.tftpl", {
    bucket_name           = aws_s3_bucket.trail_replica.bucket
    replication_role_arn  = local.replication_role_arn
    management_account_id = var.management_account_id
    log_reader_arn        = local.log_reader_arn
  })

  depends_on = [aws_s3_bucket_public_access_block.trail_replica]
}

resource "aws_s3_bucket_logging" "trail_replica" {
  provider      = aws.replica
  bucket        = aws_s3_bucket.trail_replica.id
  target_bucket = aws_s3_bucket.replica_access_logs.id
  target_prefix = "org-trail-replica/"
}

resource "aws_s3_bucket_notification" "trail_replica" {
  provider    = aws.replica
  bucket      = aws_s3_bucket.trail_replica.id
  eventbridge = true
}

# --- replica-Region access-log destination (SSE-S3, no self-logging) ---------

resource "aws_s3_bucket" "replica_access_logs" {
  provider = aws.replica
  bucket   = local.replica_access_logs_bucket_name

  #checkov:skip=CKV_AWS_144:This is the access-log target for the replica bucket. A further replica would be another copy and is out of scope for this lab.
  #checkov:skip=CKV_AWS_18:AWS recommends against a server access log destination logging to itself. This bucket is the destination for the trail replica bucket.
  #checkov:skip=CKV_AWS_145:AWS requires a server access log destination bucket to use SSE-S3, not SSE-KMS.
}

resource "aws_s3_bucket_ownership_controls" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "replica_access_logs" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.replica_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  rule {
    id     = "archive-replica-access-logs"
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

  depends_on = [aws_s3_bucket_versioning.replica_access_logs]
}

resource "aws_s3_bucket_policy" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  policy = templatefile("${path.module}/policies/s3-replica-access-logs-bucket-policy.json.tftpl", {
    bucket_name           = aws_s3_bucket.replica_access_logs.bucket
    source_bucket_name    = aws_s3_bucket.trail_replica.bucket
    management_account_id = var.management_account_id
    log_reader_arn        = local.log_reader_arn
  })

  depends_on = [aws_s3_bucket_public_access_block.replica_access_logs]
}

resource "aws_s3_bucket_notification" "replica_access_logs" {
  provider    = aws.replica
  bucket      = aws_s3_bucket.replica_access_logs.id
  eventbridge = true
}

# --- replication role and configuration --------------------------------------

data "aws_iam_policy_document" "replication_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.management_account_id]
    }
  }
}

resource "aws_iam_role" "replication" {
  name               = local.replication_role_name
  assume_role_policy = data.aws_iam_policy_document.replication_trust.json
}

resource "aws_iam_role_policy" "replication" {
  name = "s3-trail-replication"
  role = aws_iam_role.replication.id
  policy = templatefile("${path.module}/policies/iam-s3-replication.json.tftpl", {
    source_bucket_name      = aws_s3_bucket.trail.bucket
    destination_bucket_name = aws_s3_bucket.trail_replica.bucket
    source_key_arn          = aws_kms_key.cloudtrail.arn
    destination_key_arn     = aws_kms_key.lab_logs_replica.arn
    region                  = var.region
    replica_region          = var.replica_region
  })
}

resource "aws_s3_bucket_replication_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "to-replica-region"
    status = "Enabled"

    filter {}

    destination {
      bucket        = aws_s3_bucket.trail_replica.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.lab_logs_replica.arn
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.trail,
    aws_s3_bucket_versioning.trail_replica,
    aws_iam_role_policy.replication,
  ]
}

# F-012 T-12 (F-012-AC-15; design §3.5): one S3 bucket the way every bucket
# of the platform is made: KMS encryption under the caller's key, versioned,
# no public access, owner-enforced objects, TLS 1.2 or later only, uploads
# that name another encryption refused, optional Object Lock and access
# logging, optional replication to another region (F-012 T-13: the
# instances' audit and store buckets). Every other module creates its
# buckets through this one.
locals {
  arn = "arn:${var.partition}:s3:::${var.name}"

  # Statements every bucket carries, then the caller's (service principals
  # that deliver logs, for example).
  baseline_statements = [
    {
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.arn, "${local.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    },
    {
      Sid       = "DenyTLSBelow12"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.arn, "${local.arn}/*"]
      Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
    },
    {
      # An upload may leave the header out (the bucket's KMS default
      # applies) but never ask for another kind of encryption.
      Sid       = "DenyOtherEncryption"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${local.arn}/*"
      Condition = {
        Null            = { "s3:x-amz-server-side-encryption" = "false" }
        StringNotEquals = { "s3:x-amz-server-side-encryption" = ["aws:kms", "aws:kms:dsse"] }
      }
    },
  ]

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.baseline_statements, var.policy_statements)
  })
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_144:Replication is the caller's choice (var.replication, aws_s3_bucket_replication_configuration below): the instances' audit WORM, audit store and report store replicate to the second GovCloud region (T-13); the core accounts' buckets, access-log buckets and the replicas themselves do not (S3 keeps them across three Availability Zones, Object Lock keeps the evidence).
  #checkov:skip=CKV2_AWS_62:No consumer of object events: reads and writes are recorded by the organization trail and the server access logs.
  bucket              = var.name
  object_lock_enabled = var.object_lock != null || var.object_lock_enabled
  force_destroy       = false
  tags                = var.tags

  # No code path removes a bucket of this module (state, evidence, logs,
  # the instances' stores: decommissioning keeps them, F-012 T-14).
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock == null ? 0 : 1
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = var.object_lock.mode
      days = var.object_lock.days
    }
  }
  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.access_log_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.access_log_bucket
  target_prefix = "${var.name}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "housekeeping"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.noncurrent_days == null ? [] : [var.noncurrent_days]
      content {
        noncurrent_days = noncurrent_version_expiration.value
      }
    }

    # Replicas only: the source's deletes of named versions do not
    # replicate, so a replica ages its copies out itself (never before
    # Object Lock's retention: S3 refuses to remove a locked version).
    dynamic "expiration" {
      for_each = var.expiration_days == null ? [] : [var.expiration_days]
      content {
        days = expiration.value
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Every new object version is copied to the destination bucket (another
# region, same account) under the destination's key; deletes are not
# replicated (delete markers off; deletes of versions never replicate).
resource "aws_s3_bucket_replication_configuration" "this" {
  count  = var.replication == null ? 0 : 1
  bucket = aws_s3_bucket.this.id
  role   = var.replication.role_arn

  rule {
    id     = "replica"
    status = "Enabled"
    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = var.replication.destination_bucket_arn
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = var.replication.destination_kms_key_arn
      }
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_policy" "this" {
  bucket     = aws_s3_bucket.this.id
  policy     = local.policy
  depends_on = [aws_s3_bucket_public_access_block.this]
}

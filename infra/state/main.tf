# F-012 T-12 (F-012-AC-14, AC-16; design §3.5, §4): the OpenTofu state of
# every root, in the management account: one S3 bucket, versioned, with
# Object Lock (governance mode, bypass denied to everyone) so no state version
# is lost or rewritten within the retention, under its own KMS key; locking by
# S3 conditional writes (use_lockfile, no DynamoDB table).
#
# Bootstrap (once): apply this root with a local state, then
# `tofu init -migrate-state` with the backend configuration below, so the
# bucket keeps its own state too.
locals {
  bucket = "fair-tofu-state-${var.account_id}"
  tags   = merge(var.tags, { "fair:root" = "state" })
}

resource "aws_kms_key" "state" {
  description             = "FAIR OpenTofu state encryption"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:${var.partition}:iam::${var.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  tags = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "state" {
  name          = "alias/fair-tofu-state"
  target_key_id = aws_kms_key.state.key_id
}

module "access_logs" {
  source          = "../modules/secure-bucket"
  name            = "fair-tofu-state-access-${var.account_id}"
  partition       = var.partition
  kms_key_arn     = aws_kms_key.state.arn
  noncurrent_days = 30
  policy_statements = [{
    Sid       = "ServerAccessLogs"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:${var.partition}:s3:::fair-tofu-state-access-${var.account_id}/*"
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
  }]
  tags = local.tags
}

module "state" {
  source            = "../modules/secure-bucket"
  name              = local.bucket
  partition         = var.partition
  kms_key_arn       = aws_kms_key.state.arn
  object_lock       = { mode = "GOVERNANCE", days = var.retention_days }
  noncurrent_days   = max(var.retention_days, 365)
  access_log_bucket = module.access_logs.id
  policy_statements = [{
    # Governance mode, but nobody may bypass it: a state version stays
    # until its retention ends.
    Sid       = "DenyRetentionBypass"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:BypassGovernanceRetention"
    Resource  = ["arn:${var.partition}:s3:::${local.bucket}", "arn:${var.partition}:s3:::${local.bucket}/*"]
  }]
  tags = local.tags
}


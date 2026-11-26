# F-012 T-12 (F-012-AC-15, AC-16; design §3.5): the security account, the
# delegated administrator for CloudTrail, GuardDuty and Config:
#   - the log archive: a bucket with Object Lock in compliance mode under its
#     own KMS key, receiving the organization trail and every account's
#     Config deliveries (nobody, root included, shortens or deletes a locked
#     object before its retention ends);
#   - the organization trail (every account, every region, log file
#     validation, KMS);
#   - GuardDuty for every member, enabled automatically;
#   - an organization-wide Config aggregator.
# An organization trail made by the delegated administrator belongs to the
# management account, so the trail's ARN names that account.
locals {
  trail_arn    = "arn:${var.partition}:cloudtrail:${var.home_region}:${var.management_account_id}:trail/${var.trail_name}"
  archive_name = "fair-log-archive-${var.account_id}"
  archive_arn  = "arn:${var.partition}:s3:::${local.archive_name}"

  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${var.partition}:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncrypts"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${var.partition}:cloudtrail:*:${var.management_account_id}:trail/*" }
        }
      },
      {
        Sid       = "CloudTrailDescribes"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "ConfigEncrypts"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceOrgID" = var.organization_id } }
      },
    ]
  })

  archive_statements = [
    {
      Sid       = "CloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = local.archive_arn
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    },
    {
      Sid       = "CloudTrailWrites"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource = [
        "${local.archive_arn}/cloudtrail/AWSLogs/${var.management_account_id}/*",
        "${local.archive_arn}/cloudtrail/AWSLogs/${var.organization_id}/*",
      ]
      Condition = {
        StringEquals = {
          "aws:SourceArn" = local.trail_arn
          "s3:x-amz-acl"  = "bucket-owner-full-control"
        }
      }
    },
    {
      Sid       = "ConfigAclCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
      Resource  = local.archive_arn
      Condition = { StringEquals = { "aws:SourceOrgID" = var.organization_id } }
    },
    {
      Sid       = "ConfigWrites"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.archive_arn}/config/AWSLogs/*"
      Condition = {
        StringEquals = {
          "aws:SourceOrgID" = var.organization_id
          "s3:x-amz-acl"    = "bucket-owner-full-control"
        }
      }
    },
  ]
}

resource "aws_kms_key" "archive" {
  description             = "FAIR log archive (CloudTrail, Config) encryption"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = local.key_policy
  tags                    = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "archive" {
  name          = "alias/fair-log-archive"
  target_key_id = aws_kms_key.archive.key_id
}

module "access_logs" {
  source      = "../secure-bucket"
  name        = "fair-log-archive-access-${var.account_id}"
  partition   = var.partition
  kms_key_arn = aws_kms_key.archive.arn
  object_lock = { mode = "COMPLIANCE", days = var.retention_days }
  policy_statements = [{
    Sid       = "ServerAccessLogs"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:${var.partition}:s3:::fair-log-archive-access-${var.account_id}/*"
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
  }]
  tags = var.tags
}

module "archive" {
  source            = "../secure-bucket"
  name              = local.archive_name
  partition         = var.partition
  kms_key_arn       = aws_kms_key.archive.arn
  object_lock       = { mode = "COMPLIANCE", days = var.retention_days }
  access_log_bucket = module.access_logs.id
  policy_statements = local.archive_statements
  tags              = var.tags
}

resource "aws_cloudtrail" "organization" {
  #checkov:skip=CKV_AWS_252:No SNS consumer of log file deliveries; the trail's integrity is checked by log file validation and its stopping is denied by the guardrails.
  #checkov:skip=CKV2_AWS_10:An organization trail made by the delegated administrator delivers to CloudWatch Logs in the management account only; the trail is kept in the Object Lock archive and threats are raised by GuardDuty.
  name                          = var.trail_name
  s3_bucket_name                = module.archive.id
  s3_key_prefix                 = "cloudtrail"
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.archive.arn
  tags                          = var.tags

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each    = toset(var.guardduty_features)
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  auto_enable = "ALL"
}

resource "aws_iam_role" "aggregator" {
  name = "fair-config-aggregator"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "aggregator" {
  role       = aws_iam_role.aggregator.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_aggregator" "organization" {
  name = "fair-organization"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.aggregator.arn
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.aggregator]
}

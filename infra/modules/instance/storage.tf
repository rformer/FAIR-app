# The instance's object storage (design §3.5; F-002, F-010), each bucket
# under its own key and replicated to the second region:
#   - audit-worm: the checkpoint copies (FAIR_AUDIT_WORM_*): Object Lock in
#     compliance mode with a default retention (CheckBucket);
#   - audit-store: exports and archives (FAIR_AUDIT_STORE_*): Object Lock
#     enabled, each write locked until its own date (CheckBucket);
#   - report-store: report files (FAIR_REPORT_STORE_*): versioned, purged by
#     version (CheckVersioned);
#   - access: the server access logs of the three.
# Bucket policies add, to secure-bucket's TLS and encryption rules: nothing
# from another account, and object reads and writes only by the bucket's
# service role (and the replication role), so an operator role cannot read
# the stores (design §3.9).
locals {
  data_bucket_roles = {
    "audit-worm"   = [local.role_arn["audit"], local.role_arn["replication"]]
    "audit-store"  = [local.role_arn["audit"], local.role_arn["replication"]]
    "report-store" = [local.role_arn["risk"], local.role_arn["replication"]]
  }

  object_actions = ["s3:GetObject*", "s3:PutObject*", "s3:DeleteObject*", "s3:RestoreObject", "s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]

  outside_deny = { for name in concat(values(local.bucket), values(local.replica_bucket)) : name => {
    Sid       = "DenyOutsideTheInstance"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource  = ["arn:${local.p}:s3:::${name}", "arn:${local.p}:s3:::${name}/*"]
    Condition = {
      StringNotEquals = { "aws:PrincipalAccount" = local.acct }
      Bool            = { "aws:PrincipalIsAWSService" = "false" }
    }
  } }

  home_statements = { for b, roles in local.data_bucket_roles : b => [
    local.outside_deny[local.bucket[b]],
    {
      Sid       = "OnlyTheServiceTouchesObjects"
      Effect    = "Deny"
      Principal = "*"
      Action    = local.object_actions
      Resource  = "${local.s3_arn[b]}/*"
      Condition = { ArnNotEquals = { "aws:PrincipalArn" = roles } }
    },
  ] }

  replica_statements = { for b, _ in local.data_bucket_roles : b => [
    local.outside_deny[local.replica_bucket[b]],
    {
      Sid       = "OnlyReplicationTouchesObjects"
      Effect    = "Deny"
      Principal = "*"
      Action    = local.object_actions
      Resource  = "${local.s3_replica_arn[b]}/*"
      Condition = { ArnNotEquals = { "aws:PrincipalArn" = [local.role_arn["replication"]] } }
    },
  ] }

  access_log_statements = { for region, name in { (var.region) = local.bucket["access"], (var.replica_region) = local.replica_bucket["access"] } : region => [
    local.outside_deny[name],
    {
      Sid       = "ServerAccessLogs"
      Effect    = "Allow"
      Principal = { Service = "logging.s3.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "arn:${local.p}:s3:::${name}/*"
      Condition = { StringEquals = { "aws:SourceAccount" = local.acct } }
    },
  ] }
}

# Home region.
module "access" {
  source            = "../secure-bucket"
  name              = local.bucket["access"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.home["logs"].arn
  noncurrent_days   = 30
  policy_statements = local.access_log_statements[var.region]
  tags              = local.tags
}

module "audit_worm" {
  source            = "../secure-bucket"
  name              = local.bucket["audit-worm"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.home["audit-worm"].arn
  object_lock       = { mode = "COMPLIANCE", days = var.audit_worm_retention_days }
  access_log_bucket = module.access.id
  policy_statements = local.home_statements["audit-worm"]
  replication = {
    role_arn                = aws_iam_role.service["replication"].arn
    destination_bucket_arn  = module.audit_worm_replica.arn
    destination_kms_key_arn = aws_kms_key.replica["audit-worm"].arn
  }
  tags = local.tags
}

module "audit_store" {
  source              = "../secure-bucket"
  name                = local.bucket["audit-store"]
  partition           = local.p
  kms_key_arn         = aws_kms_key.home["audit-store"].arn
  object_lock_enabled = true
  access_log_bucket   = module.access.id
  policy_statements   = local.home_statements["audit-store"]
  replication = {
    role_arn                = aws_iam_role.service["replication"].arn
    destination_bucket_arn  = module.audit_store_replica.arn
    destination_kms_key_arn = aws_kms_key.replica["audit-store"].arn
  }
  tags = local.tags
}

module "report_store" {
  source            = "../secure-bucket"
  name              = local.bucket["report-store"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.home["report-store"].arn
  access_log_bucket = module.access.id
  policy_statements = local.home_statements["report-store"]
  replication = {
    role_arn                = aws_iam_role.service["replication"].arn
    destination_bucket_arn  = module.report_store_replica.arn
    destination_kms_key_arn = aws_kms_key.replica["report-store"].arn
  }
  tags = local.tags
}

# Second region: the replicas. They age their copies out themselves (the
# source's deletes do not replicate), never before Object Lock allows.
module "access_replica" {
  source            = "../secure-bucket"
  providers         = { aws = aws.replica }
  name              = local.replica_bucket["access"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.replica["logs"].arn
  noncurrent_days   = 30
  policy_statements = local.access_log_statements[var.replica_region]
  tags              = local.tags
}

module "audit_worm_replica" {
  source            = "../secure-bucket"
  providers         = { aws = aws.replica }
  name              = local.replica_bucket["audit-worm"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.replica["audit-worm"].arn
  object_lock       = { mode = "COMPLIANCE", days = var.audit_worm_retention_days }
  expiration_days   = var.audit_retention_days
  noncurrent_days   = 1
  access_log_bucket = module.access_replica.id
  policy_statements = local.replica_statements["audit-worm"]
  tags              = local.tags
}

module "audit_store_replica" {
  source              = "../secure-bucket"
  providers           = { aws = aws.replica }
  name                = local.replica_bucket["audit-store"]
  partition           = local.p
  kms_key_arn         = aws_kms_key.replica["audit-store"].arn
  object_lock_enabled = true
  expiration_days     = var.audit_retention_days
  noncurrent_days     = 1
  access_log_bucket   = module.access_replica.id
  policy_statements   = local.replica_statements["audit-store"]
  tags                = local.tags
}

module "report_store_replica" {
  source            = "../secure-bucket"
  providers         = { aws = aws.replica }
  name              = local.replica_bucket["report-store"]
  partition         = local.p
  kms_key_arn       = aws_kms_key.replica["report-store"].arn
  expiration_days   = var.report_replica_days
  noncurrent_days   = 1
  access_log_bucket = module.access_replica.id
  policy_statements = local.replica_statements["report-store"]
  tags              = local.tags
}

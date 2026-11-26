# One customer-managed key per purpose (design §3.5; AC-15: keys specific
# to the instance), and the replicas' keys in the second region. Each key's
# policy names this account only: its administration (IAM policies in the
# account decide who uses it), the AWS services that encrypt for it, and
# an explicit deny to any principal of another account.
locals {
  home_key_purposes = {
    database       = "the database: storage, Performance Insights"
    "audit-worm"   = "the audit WORM bucket (checkpoint copies)"
    "audit-store"  = "the audit store (exports, archives)"
    "report-store" = "the report store"
    secrets        = "Secrets Manager: the key files and the database passwords"
    eks            = "EKS: envelope encryption of Kubernetes Secrets"
    nodes          = "the nodes' EBS volumes"
    logs           = "CloudWatch Logs (flow, cluster, database, WAF, DNS) and the access-log bucket"
  }
  replica_key_purposes = {
    database       = "the database's backup copies"
    "audit-worm"   = "the audit WORM replica"
    "audit-store"  = "the audit store replica"
    "report-store" = "the report store replica"
    logs           = "the replica access-log bucket"
  }

  key_admin_statements = [
    {
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = local.account_root }
      Action    = "kms:*"
      Resource  = "*"
    },
    {
      # Grants or key policy mistakes can never open a key to another
      # account; AWS services acting for the account are not principals of
      # an account and stay allowed by the statements below.
      Sid       = "DenyOutsideTheInstance"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "kms:*"
      Resource  = "*"
      Condition = {
        StringNotEquals = { "aws:PrincipalAccount" = local.acct }
        Bool            = { "aws:PrincipalIsAWSService" = "false" }
      }
    },
  ]

  key_use_actions = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"]

  logs_statements = { for region in [var.region, var.replica_region] : region => [
    {
      Sid       = "CloudWatchLogs"
      Effect    = "Allow"
      Principal = { Service = "logs.${region}.amazonaws.com" }
      Action    = local.key_use_actions
      Resource  = "*"
      Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:${local.p}:logs:${region}:${local.acct}:log-group:*" } }
    },
    {
      Sid       = "ServerAccessLogs"
      Effect    = "Allow"
      Principal = { Service = "logging.s3.amazonaws.com" }
      Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
      Resource  = "*"
      Condition = { StringEquals = { "aws:SourceAccount" = local.acct } }
    },
  ] }

  autoscaling_role = "arn:${local.p}:iam::${local.acct}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  nodes_statements = [
    {
      Sid       = "NodeGroupVolumes"
      Effect    = "Allow"
      Principal = { AWS = local.autoscaling_role }
      Action    = local.key_use_actions
      Resource  = "*"
    },
    {
      Sid       = "NodeGroupVolumeGrants"
      Effect    = "Allow"
      Principal = { AWS = local.autoscaling_role }
      Action    = "kms:CreateGrant"
      Resource  = "*"
      Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
    },
  ]

  home_key_policy = { for k, _ in local.home_key_purposes : k => jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.key_admin_statements,
      flatten([for _ in(k == "logs" ? [1] : []) : local.logs_statements[var.region]]),
    flatten([for _ in(k == "nodes" ? [1] : []) : local.nodes_statements]))
  }) }
  replica_key_policy = { for k, _ in local.replica_key_purposes : k => jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.key_admin_statements, flatten([for _ in(k == "logs" ? [1] : []) : local.logs_statements[var.replica_region]]))
  }) }
}

resource "aws_kms_key" "home" {
  for_each                = local.home_key_purposes
  description             = "FAIR ${var.instance}: ${each.value}"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  multi_region            = false
  policy                  = local.home_key_policy[each.key]
  tags                    = merge(local.tags, { "fair:purpose" = each.key })
}

resource "aws_kms_alias" "home" {
  for_each      = local.home_key_purposes
  name          = "alias/${local.name}-${each.key}"
  target_key_id = aws_kms_key.home[each.key].key_id
}

resource "aws_kms_key" "replica" {
  provider                = aws.replica
  for_each                = local.replica_key_purposes
  description             = "FAIR ${var.instance}: ${each.value}"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  multi_region            = false
  policy                  = local.replica_key_policy[each.key]
  tags                    = merge(local.tags, { "fair:purpose" = each.key })
}

resource "aws_kms_alias" "replica" {
  provider      = aws.replica
  for_each      = local.replica_key_purposes
  name          = "alias/${local.name}-${each.key}"
  target_key_id = aws_kms_key.replica[each.key].key_id
}

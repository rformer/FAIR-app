# F-012 T-12 (F-012-AC-15, AC-24, AC-26; design §3.5, §3.7, §3.8, §4): the
# operations account's storage.
#   - evidence: Flux deployment events and the change-evidence exports
#     (cmd/evidence, T-17), Object Lock in compliance mode for 7 years;
#   - loki, tempo: the log and trace stores of the self-run Loki and Tempo
#     (D-OQ2), which hold operational telemetry only (ADR-017: no risk data).
#
# Stubbed for later tasks: the ops EKS cluster that runs Prometheus, Loki,
# Tempo, Grafana and the Flux notification receiver is built with the
# cluster module of T-13; their IRSA roles bind to these buckets then
# (var.workload_role_arns), and the instances' Collectors reach the ops
# account over PrivateLink (endpoint service with T-13's network module).
locals {
  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${var.partition}:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      ], length(var.workload_role_arns) == 0 ? [] : [{
        Sid       = "WorkloadsUseTheKey"
        Effect    = "Allow"
        Principal = { AWS = var.workload_role_arns }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
    }])
  })

  workload_statements = { for b in ["loki", "tempo", "evidence"] : b => length(var.workload_role_arns) == 0 ? [] : [{
    Sid       = "WorkloadsReadWrite"
    Effect    = "Allow"
    Principal = { AWS = var.workload_role_arns }
    Action    = b == "evidence" ? ["s3:GetObject", "s3:ListBucket", "s3:PutObject"] : ["s3:DeleteObject", "s3:GetObject", "s3:ListBucket", "s3:PutObject"]
    Resource  = ["arn:${var.partition}:s3:::fair-${b}-${var.account_id}", "arn:${var.partition}:s3:::fair-${b}-${var.account_id}/*"]
  }] }
}

resource "aws_kms_key" "ops" {
  description             = "FAIR operations storage (evidence, logs, traces) encryption"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = local.key_policy
  tags                    = var.tags
}

resource "aws_kms_alias" "ops" {
  name          = "alias/fair-ops"
  target_key_id = aws_kms_key.ops.key_id
}

module "access_logs" {
  source          = "../secure-bucket"
  name            = "fair-ops-access-${var.account_id}"
  partition       = var.partition
  kms_key_arn     = aws_kms_key.ops.arn
  noncurrent_days = 30
  policy_statements = [{
    Sid       = "ServerAccessLogs"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:${var.partition}:s3:::fair-ops-access-${var.account_id}/*"
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
  }]
  tags = var.tags
}

module "evidence" {
  source            = "../secure-bucket"
  name              = "fair-evidence-${var.account_id}"
  partition         = var.partition
  kms_key_arn       = aws_kms_key.ops.arn
  object_lock       = { mode = "COMPLIANCE", days = var.evidence_retention_days }
  access_log_bucket = module.access_logs.id
  policy_statements = local.workload_statements["evidence"]
  tags              = var.tags
}

module "loki" {
  source            = "../secure-bucket"
  name              = "fair-loki-${var.account_id}"
  partition         = var.partition
  kms_key_arn       = aws_kms_key.ops.arn
  noncurrent_days   = 7
  access_log_bucket = module.access_logs.id
  policy_statements = local.workload_statements["loki"]
  tags              = var.tags
}

module "tempo" {
  source            = "../secure-bucket"
  name              = "fair-tempo-${var.account_id}"
  partition         = var.partition
  kms_key_arn       = aws_kms_key.ops.arn
  noncurrent_days   = 7
  access_log_bucket = module.access_logs.id
  policy_statements = local.workload_statements["tempo"]
  tags              = var.tags
}

# F-012 T-14 (F-012-AC-14, AC-15, AC-16, AC-17; design §3.5; ADR-016): one
# customer instance's stack in its own account, driven by its spec
# infra/instances/<name>.tfvars (a pull request: planned in the pull
# request, applied after approval by .github/workflows/infra-instances.yml
# through scripts/infra-instance.sh; state instances/<name>/terraform.tfstate):
#
#   - modules/account-baseline: Config to the log archive, EBS encryption by
#     default, the account-wide S3 public access block;
#   - modules/instance: the network, cluster, database, stores, keys,
#     secrets, DNS, certificates and WAF (T-13), and its decommissioning
#     (var.status, docs/operations/decommissioning.md);
#   - the zone's delegation in the SaaS parent zone (NS and DS records,
#     through the shared account's delegation role): no manual DNS step;
#   - fair-instance-plan: the read-only role the pull requests' plans and the
#     daily drift job use in this account (AWS ReadOnlyAccess, with every
#     data read denied), trusted only by the management account's
#     fair-instances-plan.
#
# Applies run as the account's infrastructure role (the guardrails'
# exception), assumed from the management account's fair-instances-apply,
# which reaches only accounts of the instances OU; plans and drift as
# fair-instance-plan. Every provider is limited to this account (and the
# parent zone's provider to the shared account).
locals {
  p    = "aws-us-gov"
  name = "fair-${var.instance}"
  tags = merge(var.tags, { "fair:root" = "instance", "fair:instance" = var.instance })
  live = var.status != "retired"

  plan_role_name = "fair-instance-plan"
  role_arn = {
    plan  = "arn:${local.p}:iam::${var.account_id}:role/${local.plan_role_name}"
    apply = "arn:${local.p}:iam::${var.account_id}:role/${var.infrastructure_role_name}"
  }
  dns_role_arn = { plan = var.dns.read_role_arn, apply = var.dns.delegate_role_arn }

  # The management account's plan role (infra/modules/instance-pipeline).
  pipeline_plan_role_arn = "arn:${local.p}:iam::${var.management_account_id}:role/fair-instances-plan"

  # Reads of data the plan role never needs (tofu plan reads configuration
  # only): objects, secret values, keys' plaintext, database and cluster
  # sessions, log contents, parameters, console output; and no hop onward.
  plan_denied_actions = [
    "s3:GetObject*",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
    "rds-db:connect",
    "rds-data:*",
    "eks:AccessKubernetesApi",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "logs:StartQuery",
    "logs:GetQueryResults",
    "logs:StartLiveTail",
    "logs:GetLogRecord",
    "ssm:GetParameter*",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
    "ec2:GetPasswordData",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "sts:AssumeRole*",
  ]

  plan_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ManagementPlanRole"
      Effect    = "Allow"
      Principal = { AWS = local.pipeline_plan_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
  plan_deny = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "NoDataReads"
      Effect   = "Deny"
      Action   = local.plan_denied_actions
      Resource = "*"
    }]
  })
}

module "baseline" {
  source             = "../modules/account-baseline"
  account_id         = var.account_id
  partition          = local.p
  config_bucket      = var.log_archive.bucket
  config_kms_key_arn = var.log_archive.kms_key_arn
}

module "instance" {
  source    = "../modules/instance"
  providers = { aws = aws, aws.replica = aws.replica }

  instance                  = var.instance
  account_id                = var.account_id
  region                    = var.region
  replica_region            = var.replica_region
  availability_zones        = var.availability_zones
  vpc_cidr                  = var.vpc_cidr
  domain                    = var.domain
  node_instance_types       = var.node_instance_types
  node_count                = var.node_count
  db_instance_class         = var.db_instance_class
  audit_worm_retention_days = var.audit_worm_retention_days
  audit_retention_days      = var.audit_retention_days
  ops_telemetry             = var.ops_telemetry
  status                    = var.status
  tags                      = local.tags
}

# The zone's delegation (the instance module's dns output). The DS record
# waits for the whole module, so the zone signs before resolvers expect it.
resource "aws_route53_record" "delegation_ns" {
  count    = local.live ? 1 : 0
  provider = aws.dns
  zone_id  = var.dns.zone_id
  name     = var.domain
  type     = "NS"
  ttl      = 3600
  records  = module.instance.dns.name_servers
}

resource "aws_route53_record" "delegation_ds" {
  count      = local.live ? 1 : 0
  provider   = aws.dns
  zone_id    = var.dns.zone_id
  name       = var.domain
  type       = "DS"
  ttl        = 3600
  records    = [module.instance.dns.ds_record]
  depends_on = [module.instance]
}

resource "aws_iam_role" "plan" {
  name                 = local.plan_role_name
  description          = "FAIR ${var.instance}: read-only plans and drift (infra-instances.yml through the management account, F-012 T-14)"
  assume_role_policy   = local.plan_trust
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "plan" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:${local.p}:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "plan" {
  name   = "no-data-reads"
  role   = aws_iam_role.plan.id
  policy = local.plan_deny
}

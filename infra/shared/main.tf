# F-012 T-12 (F-012-AC-08, AC-15, AC-19; design §3.3, §3.5; ADR-016, ADR-018):
# the shared-services account: the KMS release key and its sign-only role
# (release-sign.yml's FAIR_RELEASE_KMS_KEY, FAIR_RELEASE_ROLE_ARN,
# FAIR_RELEASE_REGION), the ECR release mirror, and the account's baseline;
# F-012 T-14: the SaaS parent zone and its delegation roles (once
# var.parent_zone is set).
locals {
  tags                    = merge(var.tags, { "fair:root" = "shared" })
  infrastructure_role_arn = "arn:${var.partition}:iam::${var.account_id}:role/${var.infrastructure_role_name}"
}

module "release_signing" {
  source                  = "../modules/release-signing"
  account_id              = var.account_id
  partition               = var.partition
  infrastructure_role_arn = local.infrastructure_role_arn
  key_admin_trusted_arns  = var.key_admin_trusted_arns
  tags                    = local.tags
}

module "mirror" {
  source              = "../modules/ecr-mirror"
  account_id          = var.account_id
  partition           = var.partition
  organization_id     = var.organization_id
  pull_org_paths      = var.pull_org_paths
  publisher_role_arns = var.publisher_role_arns
  tags                = local.tags
}

module "baseline" {
  source             = "../modules/account-baseline"
  account_id         = var.account_id
  partition          = var.partition
  config_bucket      = var.log_archive.bucket
  config_kms_key_arn = var.log_archive.kms_key_arn
}

module "parent_zone" {
  count          = var.parent_zone == null ? 0 : 1
  source         = "../modules/parent-zone"
  account_id     = var.account_id
  partition      = var.partition
  region         = var.region
  domain         = var.parent_zone.domain
  plan_role_arn  = var.parent_zone.plan_role_arn
  apply_role_arn = var.parent_zone.apply_role_arn
  tags           = local.tags
}

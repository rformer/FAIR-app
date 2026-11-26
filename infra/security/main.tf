# F-012 T-12 (F-012-AC-15, AC-16; design §3.5): the security account: the
# log archive, the organization trail, GuardDuty and Config for the
# organization (modules/org-security), and the account's own baseline.
locals {
  tags = merge(var.tags, { "fair:root" = "security" })
}

module "org_security" {
  source                = "../modules/org-security"
  account_id            = var.account_id
  management_account_id = var.management_account_id
  organization_id       = var.organization_id
  home_region           = var.region
  partition             = var.partition
  retention_days        = var.log_retention_days
  tags                  = local.tags
}

module "baseline" {
  source             = "../modules/account-baseline"
  account_id         = var.account_id
  partition          = var.partition
  config_bucket      = module.org_security.archive_bucket
  config_kms_key_arn = module.org_security.archive_kms_key_arn
}

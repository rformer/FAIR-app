# F-012 T-12 (F-012-AC-15, AC-24, AC-26; design §3.5, §3.7, §3.8): the
# operations account: the observability and evidence storage
# (modules/observability; the ops cluster that runs Prometheus, Loki, Tempo,
# Grafana and fleet automation comes with T-13's cluster module), and the
# account's baseline.
locals {
  tags = merge(var.tags, { "fair:root" = "ops" })
}

module "observability" {
  source             = "../modules/observability"
  account_id         = var.account_id
  partition          = var.partition
  workload_role_arns = var.workload_role_arns
  tags               = local.tags
}

module "baseline" {
  source             = "../modules/account-baseline"
  account_id         = var.account_id
  partition          = var.partition
  config_bucket      = var.log_archive.bucket
  config_kms_key_arn = var.log_archive.kms_key_arn
}

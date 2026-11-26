# F-012 T-12 (F-012-AC-14, AC-15; design §3.5; ADR-016): the GovCloud (US)
# organization, applied in its management account.
#
#   - the organization (all features, service control policies, trusted
#     access for CloudTrail, Config and GuardDuty);
#   - OUs: core (security, shared, ops) and instances (one account per
#     customer instance: T-13, T-14; empty here);
#   - the guardrails (SCPs) on the root: they bind every member account;
#   - the security account as delegated administrator of CloudTrail, Config
#     and GuardDuty;
#   - the management account's own baseline (Config to the log archive,
#     no public S3, EBS encryption), once the log archive exists.
#
# Accounts: GovCloud accounts are created from the paired commercial
# management account (CreateGovCloudAccount; create_govcloud below, through
# the aws.commercial provider) and then join this organization by
# invitation. Once a GovCloud account id is known it is listed in
# govcloud_account_ids: the account is imported and placed under its OU. The invitation and its acceptance are the one step
# outside OpenTofu for the core accounts (README "Bootstrap"); instance
# accounts are created, invited, accepted and placed by the instance
# pipeline (infra/instance-account, scripts/infra-instance.sh, T-14), whose
# roles are module.instance_pipeline below.
locals {
  tags = merge(var.tags, { "fair:root" = "organization" })

  service_principals = [
    "cloudtrail.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
  ]

  # Delegated to the security account (once it has joined).
  delegated_services = contains(keys(var.govcloud_account_ids), "security") ? toset([
    "cloudtrail.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "config.amazonaws.com",
  ]) : toset([])
}

resource "aws_organizations_organization" "this" {
  feature_set                   = "ALL"
  aws_service_access_principals = local.service_principals
  enabled_policy_types          = ["SERVICE_CONTROL_POLICY"]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "core" {
  name      = "core"
  parent_id = aws_organizations_organization.this.roots[0].id
  tags      = local.tags
}

# The customer instances' accounts (T-13, T-14: infra/instances/*.tfvars).
resource "aws_organizations_organizational_unit" "instances" {
  name      = "instances"
  parent_id = aws_organizations_organization.this.roots[0].id
  tags      = local.tags
}

module "guardrails" {
  source                    = "../modules/guardrails"
  target_ids                = [aws_organizations_organization.this.roots[0].id]
  allowed_regions           = var.allowed_regions
  infrastructure_role_names = [var.infrastructure_role_name]
  partition                 = var.partition
  tags                      = local.tags
}

# The core accounts, created through the commercial management account with
# their GovCloud pair.
resource "aws_organizations_account" "commercial" {
  provider                   = aws.commercial
  for_each                   = var.core_accounts
  name                       = "fair-${each.key}"
  email                      = each.value.email
  create_govcloud            = true
  iam_user_access_to_billing = "DENY"
  role_name                  = var.infrastructure_role_name
  close_on_deletion          = false
  tags                       = local.tags

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [role_name]
  }
}

# The same accounts as members of this organization, under core. A joined
# account is imported once (README "Bootstrap"):
#   tofu import 'aws_organizations_account.member["security"]' <id>
# (OpenTofu's test framework cannot run import blocks, so the step is a
# command, recorded with the bootstrap.)

resource "aws_organizations_account" "member" {
  for_each          = var.govcloud_account_ids
  name              = "fair-${each.key}"
  email             = var.core_accounts[each.key].email
  parent_id         = aws_organizations_organizational_unit.core.id
  close_on_deletion = false
  tags              = local.tags

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [role_name, iam_user_access_to_billing, create_govcloud]
  }
}

resource "aws_organizations_delegated_administrator" "security" {
  for_each          = local.delegated_services
  account_id        = var.govcloud_account_ids["security"]
  service_principal = each.key
  depends_on        = [aws_organizations_account.member]
}

resource "aws_guardduty_detector" "management" {
  #checkov:skip=CKV2_AWS_3:The management account's own detector; the organization configuration (every member, auto-enabled) is set by the delegated administrator in the security account (modules/org-security).
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = local.tags
}

resource "aws_guardduty_organization_admin_account" "security" {
  count            = contains(keys(var.govcloud_account_ids), "security") ? 1 : 0
  admin_account_id = var.govcloud_account_ids["security"]
  depends_on       = [aws_organizations_organization.this, aws_guardduty_detector.management]
}

module "baseline" {
  count              = var.log_archive == null ? 0 : 1
  source             = "../modules/account-baseline"
  account_id         = var.account_id
  partition          = var.partition
  config_bucket      = var.log_archive.bucket
  config_kms_key_arn = var.log_archive.kms_key_arn
}

# F-012 T-14: the instance pipeline's roles in both management accounts
# (infra-instances.yml; docs/operations/onboarding.md).
module "instance_pipeline" {
  source                = "../modules/instance-pipeline"
  providers             = { aws = aws, aws.commercial = aws.commercial }
  account_id            = var.account_id
  commercial_account_id = var.commercial_account_id
  partition             = var.partition
  organization_id       = aws_organizations_organization.this.id
  instances_ou_path     = "${aws_organizations_organization.this.id}/${aws_organizations_organization.this.roots[0].id}/${aws_organizations_organizational_unit.instances.id}/"
  protected_account_ids = values(var.govcloud_account_ids)
  repository            = var.repository
  state_bucket          = "fair-tofu-state-${var.account_id}"
  dns_read_role_arn     = try(var.dns_delegation.read_role_arn, null)
  dns_delegate_role_arn = try(var.dns_delegation.delegate_role_arn, null)
  tags                  = local.tags
}

# F-012 T-14 (F-012-AC-14, AC-17; design §3.5; ADR-016): one instance's
# account, applied by the instance pipeline in the two management accounts
# (scripts/infra-instance.sh; state instances/<name>/account.tfstate).
#
#   1. aws_organizations_account.commercial: created through the paired
#      commercial management account with its GovCloud account
#      (CreateGovCloudAccount); its govcloud_id is the instance's account.
#   2. The pipeline invites that account into the GovCloud organization and
#      accepts the invitation inside it, as its infrastructure role
#      (InviteAccountToOrganization, AcceptHandshake: OpenTofu has no
#      resource for either; ADR-016 "Account joining").
#   3. aws_organizations_account.member: the joined account, imported once
#      (var.joined) and placed under the instances OU (MoveAccount), where
#      the guardrails and the pipeline's instance-only conditions apply.
#
# The instance's spec is its tfvars file, infra/instances/<name>.tfvars
# (the same file infra/instance plans); this root reads account_email from
# it. No path closes an account or removes it from the organization: a
# decommissioned instance's account keeps its retained stores
# (docs/operations/decommissioning.md).
locals {
  spec  = try(provider::terraform::decode_tfvars(file("${local.instances_dir}/${var.instance}.tfvars")), {})
  email = try(local.spec.account_email, "")
  name  = "fair-${var.instance}"
  tags  = merge(var.tags, { "fair:instance" = var.instance })

  instances_dir = coalesce(var.instances_dir, "${path.module}/../instances")
}

resource "aws_organizations_account" "commercial" {
  provider                   = aws.commercial
  name                       = local.name
  email                      = local.email
  create_govcloud            = true
  iam_user_access_to_billing = "DENY"
  role_name                  = var.infrastructure_role_name
  close_on_deletion          = false
  tags                       = local.tags

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [role_name]

    precondition {
      condition     = try(local.spec.instance, null) == var.instance
      error_message = "infra/instances/<instance>.tfvars must exist and name the same instance."
    }
    precondition {
      condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", local.email))
      error_message = "account_email must be an address (the account's owner: a distribution list)."
    }
  }
}

# The joined account under the instances OU. Imported by the pipeline once
# the invitation is accepted:
#   tofu import -var joined=true 'aws_organizations_account.member[0]' <govcloud id>
resource "aws_organizations_account" "member" {
  count             = var.joined ? 1 : 0
  name              = local.name
  email             = local.email
  parent_id         = var.instances_ou_id
  close_on_deletion = false
  tags              = local.tags

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [role_name, iam_user_access_to_billing, create_govcloud]
  }
}

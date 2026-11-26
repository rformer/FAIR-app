output "organization_id" {
  description = "The organization id."
  value       = aws_organizations_organization.this.id
}

output "root_id" {
  description = "The organization root."
  value       = aws_organizations_organization.this.roots[0].id
}

output "ou_ids" {
  description = "The OUs."
  value = {
    core      = aws_organizations_organizational_unit.core.id
    instances = aws_organizations_organizational_unit.instances.id
  }
}

output "govcloud_account_ids" {
  description = "The GovCloud ids of the created core accounts (to invite, then list in govcloud_account_ids)."
  value       = { for k, a in aws_organizations_account.commercial : k => a.govcloud_id }
}

output "guardrails" {
  description = "The guardrail policies' ids."
  value       = module.guardrails.policy_ids
}

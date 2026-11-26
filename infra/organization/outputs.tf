output "organization_id" {
  description = "The organization id."
  value       = aws_organizations_organization.this.id
}

output "root_id" {
  description = "The organization root."
  value       = aws_organizations_organization.this.roots[0].id
}

output "instances_ou_path" {
  description = "The instances OU's organization path (infra/ops operator_access.instances_ou_path: accessctl reaches only these accounts)."
  value       = "${aws_organizations_organization.this.id}/${aws_organizations_organization.this.roots[0].id}/${aws_organizations_organizational_unit.instances.id}/"
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

output "instances_pipeline" {
  description = "The instance pipeline's roles and the organization's ids (repository variables of infra-instances.yml, docs/operations/onboarding.md)."
  value = merge(module.instance_pipeline.roles, {
    organization_id = aws_organizations_organization.this.id
    instances_ou_id = aws_organizations_organizational_unit.instances.id
  })
}

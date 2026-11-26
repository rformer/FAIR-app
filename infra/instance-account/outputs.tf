output "account_id" {
  description = "The instance's GovCloud account (infra/instance var.account_id)."
  value       = aws_organizations_account.commercial.govcloud_id
}

output "commercial_account_id" {
  description = "Its commercial pair (billing only)."
  value       = aws_organizations_account.commercial.id
}

output "joined" {
  description = "Whether the account is a member of the GovCloud organization in this state."
  value       = var.joined
}

output "parent_id" {
  description = "Its OU once joined (the instances OU), else null."
  value       = one(aws_organizations_account.member[*].parent_id)
}

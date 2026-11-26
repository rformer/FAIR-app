output "documents" {
  description = "The policy documents (JSON) by policy name."
  value       = local.documents
}

output "policy_ids" {
  description = "The policies' ids by name."
  value       = { for k, p in aws_organizations_policy.this : k => p.id }
}

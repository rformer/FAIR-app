output "repository_urls" {
  description = "Repository URLs by name."
  value       = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "kms_key_arn" {
  description = "The mirror's KMS key."
  value       = aws_kms_key.mirror.arn
}

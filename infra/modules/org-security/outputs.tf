output "archive_bucket" {
  description = "The log archive bucket (every account's Config delivers here)."
  value       = module.archive.id
}

output "archive_kms_key_arn" {
  description = "The log archive's KMS key."
  value       = aws_kms_key.archive.arn
}

output "trail_arn" {
  description = "The organization trail."
  value       = local.trail_arn
}

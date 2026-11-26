output "bucket" {
  description = "The state bucket (-backend-config=\"bucket=...\")."
  value       = module.state.id
}

output "kms_key_alias" {
  description = "The state key (kms_key_id in *.s3.tfbackend)."
  value       = aws_kms_alias.state.name
}

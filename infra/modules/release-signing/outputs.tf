output "kms_key" {
  description = "FAIR_RELEASE_KMS_KEY: the key's alias."
  value       = aws_kms_alias.release.name
}

output "key_arn" {
  description = "The release key's ARN."
  value       = aws_kms_key.release.arn
}

output "signer_role_arn" {
  description = "FAIR_RELEASE_ROLE_ARN: the sign-only role."
  value       = local.signer_role_arn
}

output "key_policy" {
  description = "The release key's policy (JSON)."
  value       = aws_kms_key.release.policy
}

output "oidc_subject" {
  description = "The sub claim the signer's trust policy accepts (StringLike)."
  value       = local.subject
}

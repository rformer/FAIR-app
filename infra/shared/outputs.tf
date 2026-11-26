output "github_variables" {
  description = "The repository variables release-sign.yml reads (set them after the first apply)."
  value = {
    FAIR_RELEASE_KMS_KEY  = module.release_signing.kms_key
    FAIR_RELEASE_ROLE_ARN = module.release_signing.signer_role_arn
    FAIR_RELEASE_REGION   = var.region
  }
}

output "release_key_arn" {
  description = "The release key."
  value       = module.release_signing.key_arn
}

output "mirror_repositories" {
  description = "The mirror's repositories."
  value       = module.mirror.repository_urls
}

output "dns_delegation" {
  description = "The parent zone's delegation (infra/instance var.dns and the organization root's var.dns_delegation); null without a parent zone."
  value       = one(module.parent_zone[*].dns_delegation)
}

output "parent_zone_registrar" {
  description = "The parent zone's name servers and DS record, for the registrar (once)."
  value       = one(module.parent_zone[*].registrar)
}

output "log_archive" {
  description = "The log archive, for the other roots' log_archive variable."
  value = {
    bucket      = module.org_security.archive_bucket
    kms_key_arn = module.org_security.archive_kms_key_arn
  }
}

output "trail_arn" {
  description = "The organization trail."
  value       = module.org_security.trail_arn
}

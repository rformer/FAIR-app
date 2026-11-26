output "id" {
  description = "The bucket's name."
  value       = aws_s3_bucket.this.bucket
}

output "arn" {
  description = "The bucket's ARN."
  value       = local.arn
}

output "policy" {
  description = "The bucket policy (JSON)."
  value       = aws_s3_bucket_policy.this.policy
}

output "object_lock" {
  description = "The Object Lock default retention as applied ({mode, days}), or null."
  value = var.object_lock == null ? null : {
    enabled = aws_s3_bucket.this.object_lock_enabled
    mode    = one(one(aws_s3_bucket_object_lock_configuration.this[0].rule).default_retention).mode
    days    = one(one(aws_s3_bucket_object_lock_configuration.this[0].rule).default_retention).days
  }
}

output "kms_key_arn" {
  description = "The key encrypting the bucket by default."
  value       = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id
}

output "public_access_blocked" {
  description = "All four public access blocks are on."
  value = alltrue([
    aws_s3_bucket_public_access_block.this.block_public_acls,
    aws_s3_bucket_public_access_block.this.block_public_policy,
    aws_s3_bucket_public_access_block.this.ignore_public_acls,
    aws_s3_bucket_public_access_block.this.restrict_public_buckets,
  ])
}

output "access_log_bucket" {
  description = "Where server access logs go, or null."
  value       = var.access_log_bucket == null ? null : aws_s3_bucket_logging.this[0].target_bucket
}

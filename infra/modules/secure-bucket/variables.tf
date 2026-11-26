variable "name" {
  description = "The bucket's name."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.name))
    error_message = "A valid S3 bucket name."
  }
}

variable "partition" {
  description = "The AWS partition (GovCloud)."
  type        = string
  default     = "aws-us-gov"
}

variable "kms_key_arn" {
  description = "The customer-managed KMS key that encrypts every object."
  type        = string
  validation {
    condition     = length(trimspace(var.kms_key_arn)) > 0
    error_message = "A KMS key is required: no bucket is encrypted with S3-managed keys."
  }
}

variable "object_lock" {
  description = "Object Lock default retention (mode COMPLIANCE or GOVERNANCE, days), or null for none."
  type = object({
    mode = string
    days = number
  })
  default = null
  validation {
    condition     = var.object_lock == null || (contains(["COMPLIANCE", "GOVERNANCE"], try(var.object_lock.mode, "")) && try(var.object_lock.days, 0) >= 1)
    error_message = "Object Lock mode is COMPLIANCE or GOVERNANCE, with at least one day."
  }
}

variable "object_lock_enabled" {
  description = "Enable Object Lock without a default retention: every write sets its own (internal/objstore CheckBucket requires Object Lock). Implied by object_lock."
  type        = bool
  default     = false
}

variable "expiration_days" {
  description = "Days after which current versions expire (replicas, which do not receive the source's deletes), or null to keep them."
  type        = number
  default     = null
  validation {
    condition     = var.expiration_days == null || try(var.expiration_days >= 1, false)
    error_message = "At least one day."
  }
}

variable "replication" {
  description = "Replicate every new object version to another bucket ({role_arn, destination_bucket_arn, destination_kms_key_arn}), or null."
  type = object({
    role_arn                = string
    destination_bucket_arn  = string
    destination_kms_key_arn = string
  })
  default = null
  validation {
    condition     = var.replication == null || (length(trimspace(try(var.replication.destination_kms_key_arn, ""))) > 0 && length(trimspace(try(var.replication.role_arn, ""))) > 0)
    error_message = "Replicas are encrypted under a named key, by a named role."
  }
}

variable "access_log_bucket" {
  description = "The bucket receiving this bucket's server access logs, or null (only for an access-log bucket itself)."
  type        = string
  default     = null
}

variable "noncurrent_days" {
  description = "Days after which noncurrent versions expire (never before Object Lock's retention), or null to keep them."
  type        = number
  default     = null
}

variable "policy_statements" {
  description = "Further bucket policy statements (service principals that deliver to the bucket)."
  type        = any
  default     = []
}

variable "tags" {
  description = "Tags for the bucket."
  type        = map(string)
  default     = {}
}

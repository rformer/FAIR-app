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

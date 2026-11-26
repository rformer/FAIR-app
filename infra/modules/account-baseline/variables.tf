variable "account_id" {
  description = "The account this baseline applies to."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "partition" {
  description = "The AWS partition."
  type        = string
  default     = "aws-us-gov"
}

variable "config_bucket" {
  description = "The log archive bucket receiving Config snapshots and history."
  type        = string
}

variable "config_kms_key_arn" {
  description = "The log archive's KMS key."
  type        = string
  validation {
    condition     = length(trimspace(var.config_kms_key_arn)) > 0
    error_message = "Config deliveries are encrypted with the log archive's key."
  }
}

variable "record_global_resources" {
  description = "Record global resources (IAM): true in the home region only."
  type        = bool
  default     = true
}

variable "create_config_service_linked_role" {
  description = "Create Config's service-linked role (false where it exists)."
  type        = bool
  default     = true
}

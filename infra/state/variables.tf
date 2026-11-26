variable "account_id" {
  description = "The GovCloud management account (holds the state)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "region" {
  description = "The home region."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = startswith(var.region, "us-gov-")
    error_message = "A GovCloud (US) region."
  }
}

variable "partition" {
  description = "The AWS partition."
  type        = string
  default     = "aws-us-gov"
}

variable "retention_days" {
  description = "Object Lock (governance, no bypass) retention of every state version."
  type        = number
  default     = 90
  validation {
    condition     = var.retention_days >= 30
    error_message = "At least 30 days."
  }
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = { "fair:managed-by" = "opentofu" }
}

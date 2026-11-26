variable "account_id" {
  description = "The security account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "management_account_id" {
  description = "The organization's management account (owner of the organization trail)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "A 12-digit account id."
  }
}

variable "organization_id" {
  description = "The organization id."
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "An organization id (o-...)."
  }
}

variable "home_region" {
  description = "The home region (the trail's)."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = startswith(var.home_region, "us-gov-")
    error_message = "A GovCloud (US) region."
  }
}

variable "partition" {
  description = "The AWS partition."
  type        = string
  default     = "aws-us-gov"
}

variable "trail_name" {
  description = "The organization trail's name."
  type        = string
  default     = "fair-organization"
}

variable "retention_days" {
  description = "Object Lock (compliance) retention of the log archive: 30 months by default (12 active and 18 cold, OMB M-21-31)."
  type        = number
  default     = 913
  validation {
    condition     = var.retention_days >= 365
    error_message = "At least one year (FedRAMP Moderate AU-11)."
  }
}

variable "guardduty_features" {
  description = "GuardDuty protections enabled for every member."
  type        = list(string)
  default     = ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS"]
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}

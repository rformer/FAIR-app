variable "account_id" {
  description = "This root's account."
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

variable "infrastructure_role_name" {
  description = "The role this root assumes in its account."
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = { "fair:managed-by" = "opentofu" }
}

variable "organization_id" {
  description = "The organization id (organization root output)."
  type        = string
}

variable "management_account_id" {
  description = "The management account (owner of the organization trail)."
  type        = string
}

variable "log_retention_days" {
  description = "Object Lock (compliance) retention of the log archive."
  type        = number
  default     = 913
}

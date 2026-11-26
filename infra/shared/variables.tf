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


variable "log_archive" {
  description = "The log archive (security root output log_archive)."
  type = object({
    bucket      = string
    kms_key_arn = string
  })
}

variable "organization_id" {
  description = "The organization id (organization root output)."
  type        = string
}

variable "pull_org_paths" {
  description = "Organization paths whose accounts pull from the mirror (the instances and core OUs)."
  type        = list(string)
}

variable "key_admin_trusted_arns" {
  description = "Principals that may assume the release key's admin role."
  type        = list(string)
}

variable "publisher_role_arns" {
  description = "Roles that push to the mirror."
  type        = list(string)
  default     = []
}

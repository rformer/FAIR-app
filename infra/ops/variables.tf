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

variable "workload_role_arns" {
  description = "The ops cluster's workload roles (empty until T-13's cluster exists)."
  type        = list(string)
  default     = []
}

variable "operator_access" {
  description = "Just-in-time operator access (design §3.9): the IAM Identity Center instance, the fleet repository (owner/name) and the instances OU's organization path (organization root output instances_ou_path); null until Identity Center is enabled."
  type = object({
    sso_instance_arn  = string
    fleet_repository  = string
    instances_ou_path = string
  })
  default = null
}

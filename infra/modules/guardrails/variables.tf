variable "target_ids" {
  description = "Organization root or OU ids the policies are attached to."
  type        = list(string)
  validation {
    condition     = length(var.target_ids) > 0
    error_message = "The guardrails must be attached somewhere (the organization root)."
  }
}

variable "allowed_regions" {
  description = "The only regions requests may use: GovCloud (US)."
  type        = list(string)
  default     = ["us-gov-west-1", "us-gov-east-1"]
  validation {
    condition     = length(var.allowed_regions) > 0 && alltrue([for r in var.allowed_regions : startswith(r, "us-gov-")])
    error_message = "GovCloud (US) regions only."
  }
}

variable "infrastructure_role_names" {
  description = "Roles that apply the reviewed infrastructure code (reconfigure, never stop, the security services; set public access blocks)."
  type        = list(string)
  default     = ["OrganizationAccountAccessRole"]
  validation {
    condition     = alltrue([for r in var.infrastructure_role_names : can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", r))])
    error_message = "Role names, not patterns."
  }
}

variable "partition" {
  description = "The AWS partition."
  type        = string
  default     = "aws-us-gov"
}

variable "tags" {
  description = "Tags for the policies."
  type        = map(string)
  default     = {}
}

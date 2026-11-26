variable "account_id" {
  description = "The GovCloud management account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "commercial_account_id" {
  description = "The commercial management account paired with it (creates GovCloud accounts)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.commercial_account_id))
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

variable "allowed_regions" {
  description = "The regions the guardrails allow."
  type        = list(string)
  default     = ["us-gov-west-1", "us-gov-east-1"]
}

variable "partition" {
  description = "The AWS partition."
  type        = string
  default     = "aws-us-gov"
}

variable "infrastructure_role_name" {
  description = "The role in each member account that applies the reviewed code (created with the account)."
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "core_accounts" {
  description = "The core accounts and their owners' (distribution list) addresses."
  type = map(object({
    email = string
  }))
  validation {
    condition     = toset(keys(var.core_accounts)) == toset(["security", "shared", "ops"])
    error_message = "Exactly the core accounts: security, shared, ops (instances are T-13/T-14)."
  }
  validation {
    condition     = alltrue([for a in values(var.core_accounts) : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", a.email))])
    error_message = "A valid address per account."
  }
}

variable "govcloud_account_ids" {
  description = "GovCloud ids of the core accounts that have joined the organization (imported and placed under core)."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for k, v in var.govcloud_account_ids : contains(["security", "shared", "ops"], k) && can(regex("^[0-9]{12}$", v))])
    error_message = "Core account names to 12-digit ids."
  }
}

variable "log_archive" {
  description = "The log archive (security root outputs) for the management account's Config; null until it exists."
  type = object({
    bucket      = string
    kms_key_arn = string
  })
  default = null
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = { "fair:managed-by" = "opentofu" }
}

variable "repository" {
  description = "The repository whose infra-instances.yml the instance pipeline's roles trust."
  type        = string
  default     = "rformer/FAIR-app"
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.repository))
    error_message = "<owner>/<name>, no wildcards."
  }
}

variable "dns_delegation" {
  description = "The parent zone's roles (shared root output dns_delegation), or null until the shared root has a parent zone."
  type = object({
    read_role_arn     = string
    delegate_role_arn = string
  })
  default = null
}

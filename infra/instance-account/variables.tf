variable "instance" {
  description = "The instance: its spec is infra/instances/<instance>.tfvars (the pipeline passes the file's name)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}[a-z0-9]$", var.instance))
    error_message = "3 to 21 characters: lower-case letters, digits and hyphens, starting with a letter."
  }
}

variable "instances_dir" {
  description = "Where the instances' tfvars files are (default infra/instances; the tests use the examples)."
  type        = string
  default     = null
  validation {
    condition     = var.instances_dir == null || length(trimspace(coalesce(var.instances_dir, " "))) > 0
    error_message = "A directory, or null."
  }
}

variable "account_id" {
  description = "The GovCloud management account (the organization's)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "commercial_account_id" {
  description = "The paired commercial management account (creates GovCloud accounts)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.commercial_account_id))
    error_message = "A 12-digit account id."
  }
}

variable "commercial_role_arn" {
  description = "The commercial account's pipeline role for this run (organization root output instances_pipeline: commercial_plan or commercial_apply), assumed with the workflow's OIDC token."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/fair-instances-(plan|apply)$", var.commercial_role_arn))
    error_message = "The commercial fair-instances-plan or fair-instances-apply role."
  }
}

variable "web_identity_token_file" {
  description = "The workflow's OIDC token (audience sts.amazonaws.com), refreshed by scripts/infra-instance.sh."
  type        = string
  default     = "/run/oidc/token"
  validation {
    condition     = startswith(var.web_identity_token_file, "/")
    error_message = "An absolute path."
  }
}

variable "region" {
  description = "The GovCloud home region."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.region)
    error_message = "A GovCloud (US) region."
  }
}

variable "instances_ou_id" {
  description = "The instances OU (organization root output instances_pipeline.instances_ou_id)."
  type        = string
  validation {
    condition     = can(regex("^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$", var.instances_ou_id))
    error_message = "An OU id (ou-...)."
  }
}

variable "infrastructure_role_name" {
  description = "The role created in each new account, trusted by the management account (the guardrails' exception)."
  type        = string
  default     = "OrganizationAccountAccessRole"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.infrastructure_role_name))
    error_message = "A role name."
  }
}

variable "joined" {
  description = "The GovCloud account has joined the organization and is imported (set by scripts/infra-instance.sh from the state)."
  type        = bool
  default     = false
  validation {
    condition     = var.joined == true || var.joined == false
    error_message = "true or false."
  }
}

variable "tags" {
  description = "Tags on the accounts."
  type        = map(string)
  default     = { "fair:managed-by" = "opentofu" }
  validation {
    condition     = alltrue([for k, _ in var.tags : length(k) > 0])
    error_message = "Tag keys are not empty."
  }
}

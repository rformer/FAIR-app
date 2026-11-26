variable "account_id" {
  description = "The shared-services account holding the key."
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

variable "repository" {
  description = "The GitHub repository (owner/name) whose release workflow signs."
  type        = string
  default     = "rformer/FAIR-app"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.repository))
    error_message = "owner/name, without wildcards."
  }
}

variable "signing_workflow" {
  description = "The reusable workflow that signs (the token's job_workflow_ref)."
  type        = string
  default     = ".github/workflows/release-sign.yml"
  validation {
    condition     = can(regex("^\\.github/workflows/[A-Za-z0-9_.-]+\\.ya?ml$", var.signing_workflow))
    error_message = "A workflow file path, without wildcards."
  }
}

variable "tag_pattern" {
  description = "The release tags that may sign (StringLike pattern)."
  type        = string
  default     = "v*"
  validation {
    condition     = startswith(var.tag_pattern, "v") && !strcontains(var.tag_pattern, ":")
    error_message = "Release tags start with v."
  }
}

variable "alias" {
  description = "The key's alias (FAIR_RELEASE_KMS_KEY is alias/<alias>)."
  type        = string
  default     = "fair-release"
}

variable "signer_role_name" {
  description = "The sign-only role (FAIR_RELEASE_ROLE_ARN)."
  type        = string
  default     = "fair-release-signer"
}

variable "admin_role_name" {
  description = "The key administrators' role."
  type        = string
  default     = "fair-release-key-admin"
}

variable "infrastructure_role_arn" {
  description = "The role applying this code: it creates and administers the key (never signs)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/", var.infrastructure_role_arn))
    error_message = "A role ARN in GovCloud, not a pattern."
  }
}

variable "key_admin_trusted_arns" {
  description = "Principals (roles, never wildcards) that may assume the key-admin role."
  type        = list(string)
  validation {
    condition     = length(var.key_admin_trusted_arns) > 0 && alltrue([for a in var.key_admin_trusted_arns : can(regex("^arn:aws-us-gov:iam::[0-9]{12}:", a)) && !strcontains(a, "*")])
    error_message = "At least one GovCloud principal ARN, no wildcards."
  }
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}

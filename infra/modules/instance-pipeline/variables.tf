variable "account_id" {
  description = "The GovCloud management account (the organization's; holds the state)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A 12-digit account id."
  }
}

variable "commercial_account_id" {
  description = "The commercial management account paired with it (creates the GovCloud accounts)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.commercial_account_id))
    error_message = "A 12-digit account id."
  }
}

variable "partition" {
  description = "The GovCloud partition."
  type        = string
  default     = "aws-us-gov"
  validation {
    condition     = var.partition == "aws-us-gov"
    error_message = "Instances run in AWS GovCloud (US) (ADR-016)."
  }
}

variable "organization_id" {
  description = "The GovCloud organization (o-...)."
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "An organization id (o-...)."
  }
}

variable "instances_ou_path" {
  description = "The instances OU's organization path, <org>/<root>/<ou>/ (aws:ResourceOrgPaths): the only accounts whose roles the pipeline assumes."
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}/r-[a-z0-9]{4,32}/ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}/$", var.instances_ou_path))
    error_message = "<org>/<root>/<ou>/ with the trailing slash (no wildcards)."
  }
}

variable "protected_account_ids" {
  description = "Accounts the apply role never assumes a role in, moves or tags: the core accounts (the management account is always protected)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.protected_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "12-digit account ids."
  }
}

variable "repository" {
  description = "The repository (<owner>/<name>) whose workflow the roles trust."
  type        = string
  default     = "rformer/FAIR-app"
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.repository))
    error_message = "<owner>/<name>, no wildcards."
  }
}

variable "workflow" {
  description = "The workflow file the roles trust (job_workflow_ref)."
  type        = string
  default     = ".github/workflows/infra-instances.yml"
  validation {
    condition     = can(regex("^\\.github/workflows/[A-Za-z0-9._-]+\\.ya?ml$", var.workflow))
    error_message = "A workflow file under .github/workflows/, no wildcards."
  }
}

variable "environment" {
  description = "The protected GitHub Environment (required reviewers, main only; infra/github) the apply role trusts."
  type        = string
  default     = "instances"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.environment))
    error_message = "An environment name, no wildcards."
  }
}

variable "state_bucket" {
  description = "The OpenTofu state bucket (state root: fair-tofu-state-<management account>)."
  type        = string
  validation {
    condition     = can(regex("^fair-tofu-state-[0-9]{12}$", var.state_bucket))
    error_message = "fair-tofu-state-<account id>."
  }
}

variable "state_kms_alias" {
  description = "The state key's alias."
  type        = string
  default     = "alias/fair-tofu-state"
  validation {
    condition     = startswith(var.state_kms_alias, "alias/")
    error_message = "A KMS alias."
  }
}

variable "infrastructure_role_name" {
  description = "The infrastructure role in each instance account (created with the account; the guardrails' exception)."
  type        = string
  default     = "OrganizationAccountAccessRole"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.infrastructure_role_name))
    error_message = "A role name, no wildcards."
  }
}

variable "instance_plan_role_name" {
  description = "The read-only role in each instance account (infra/instance)."
  type        = string
  default     = "fair-instance-plan"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.instance_plan_role_name))
    error_message = "A role name, no wildcards."
  }
}

variable "plan_role_name" {
  description = "The plan role's name (both management accounts)."
  type        = string
  default     = "fair-instances-plan"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.plan_role_name))
    error_message = "A role name."
  }
}

variable "apply_role_name" {
  description = "The apply role's name (both management accounts)."
  type        = string
  default     = "fair-instances-apply"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.apply_role_name))
    error_message = "A role name."
  }
}

variable "dns_read_role_arn" {
  description = "The parent zone's read role (shared root output dns_delegation), or null until it exists."
  type        = string
  default     = null
  validation {
    condition     = var.dns_read_role_arn == null || can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+$", var.dns_read_role_arn))
    error_message = "A role ARN, no wildcards."
  }
}

variable "dns_delegate_role_arn" {
  description = "The parent zone's delegation role (shared root output dns_delegation), or null until it exists."
  type        = string
  default     = null
  validation {
    condition     = var.dns_delegate_role_arn == null || can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+$", var.dns_delegate_role_arn))
    error_message = "A role ARN, no wildcards."
  }
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for k, _ in var.tags : length(k) > 0])
    error_message = "Tag keys are not empty."
  }
}

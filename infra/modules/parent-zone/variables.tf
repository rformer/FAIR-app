variable "account_id" {
  description = "The account holding the parent zone (shared)."
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
  validation {
    condition     = var.partition == "aws-us-gov"
    error_message = "AWS GovCloud (US) (ADR-016)."
  }
}

variable "region" {
  description = "The home region (the query logs' log group)."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.region)
    error_message = "A GovCloud (US) region."
  }
}

variable "domain" {
  description = "The SaaS parent domain: every instance's public name is <name>.<domain>."
  type        = string
  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", var.domain))
    error_message = "A lower-case DNS name without a trailing dot."
  }
}

variable "plan_role_arn" {
  description = "The instance pipeline's plan role (organization root output instances_pipeline.plan)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+$", var.plan_role_arn))
    error_message = "A role ARN, no wildcards."
  }
}

variable "apply_role_arn" {
  description = "The instance pipeline's apply role (organization root output instances_pipeline.apply)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+$", var.apply_role_arn))
    error_message = "A role ARN, no wildcards."
  }
}

variable "read_role_name" {
  description = "The read role's name."
  type        = string
  default     = "fair-dns-read"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.read_role_name))
    error_message = "A role name."
  }
}

variable "delegate_role_name" {
  description = "The delegation role's name."
  type        = string
  default     = "fair-dns-delegate"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.delegate_role_name))
    error_message = "A role name."
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

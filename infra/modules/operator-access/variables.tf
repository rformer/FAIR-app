variable "account_id" {
  description = "The operations account (IAM Identity Center's delegated administrator; accessctl runs here)."
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
    error_message = "GovCloud (US) only."
  }
}

variable "sso_instance_arn" {
  description = "The organization's IAM Identity Center instance (enabled in the management account, administered from this account)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws-us-gov:sso:::instance/(sso)?ins-[a-zA-Z0-9-.]{16}$", var.sso_instance_arn))
    error_message = "An IAM Identity Center instance ARN in GovCloud."
  }
}

variable "fleet_repository" {
  description = "The private fleet repository (owner/name) whose access workflow runs accessctl (design §3.6, §3.9)."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.fleet_repository))
    error_message = "owner/name, no wildcards."
  }
}

variable "access_environment" {
  description = "The fleet repository's protected environment (main only) the access workflow's AWS jobs run in: the OIDC token's sub is repo:<fleet>:environment:<this>."
  type        = string
  default     = "access"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.access_environment))
    error_message = "An environment name, no wildcards."
  }
}

variable "instances_ou_path" {
  description = "The instances OU's organization path (o-…/r-…/ou-…/): the only accounts whose EKS role accessctl may assume."
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}/r-[a-z0-9]{4,32}/ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}/$", var.instances_ou_path))
    error_message = "o-<id>/r-<root>/ou-<id>/ (no wildcards)."
  }
}

variable "controller_role_name" {
  description = "accessctl's role in this account (AWS_ROLE_ARN of the access workflow)."
  type        = string
  default     = "fair-access-controller"
}

variable "eks_role_name" {
  description = "The role accessctl assumes in each instance account for the cluster's access entries (infra/instance)."
  type        = string
  default     = "fair-access-eks"
}

variable "session_duration" {
  description = "How long a console or CLI session from a permission set lasts (ISO 8601). Sessions outlive a removed assignment by at most this much (docs/operations/access.md)."
  type        = string
  default     = "PT1H"
  validation {
    condition     = contains(["PT1H", "PT2H"], var.session_duration)
    error_message = "PT1H or PT2H: short, so expiry takes effect soon."
  }
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}

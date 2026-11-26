variable "account_id" {
  description = "The shared-services account."
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

variable "organization_id" {
  description = "The organization whose accounts may pull."
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "An organization id (o-...)."
  }
}

variable "pull_org_paths" {
  description = "Organization paths (aws:PrincipalOrgPaths patterns) whose accounts may pull: the instances and core OUs."
  type        = list(string)
  validation {
    condition     = length(var.pull_org_paths) > 0 && alltrue([for p in var.pull_org_paths : can(regex("^o-[a-z0-9]+/r-[a-z0-9]+/ou-[a-z0-9-]+/", p))])
    error_message = "Paths under an OU (o-.../r-.../ou-.../), never the whole organization or '*'."
  }
}

variable "publisher_role_arns" {
  description = "Roles that push (the release publisher and the third-party mirroring job)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.publisher_role_arns : can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/", a)) && !strcontains(a, "*")])
    error_message = "Role ARNs, no wildcards."
  }
}

variable "prefix" {
  description = "Repository name prefix."
  type        = string
  default     = "fair"
}

variable "repositories" {
  description = "Repositories: the platform's images and the mirrored third-party images."
  type        = list(string)
  default = [
    "iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate", "engine-gate", "engine",
    "mirror/flux-source-controller", "mirror/flux-kustomize-controller", "mirror/flux-notification-controller",
    "mirror/policy-controller", "mirror/external-secrets", "mirror/cert-manager-controller", "mirror/cert-manager-webhook",
    "mirror/cert-manager-cainjector", "mirror/opentelemetry-collector",
  ]
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}

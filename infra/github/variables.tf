variable "owner" {
  description = "The repository's owner (user or organization)."
  type        = string
  default     = "rformer"
}

variable "repository" {
  description = "The repository name."
  type        = string
  default     = "FAIR-app"
}

variable "required_checks" {
  description = "Status checks every change to main must pass (the CI job names)."
  type        = list(string)
  default = [
    "test",
    "lint",
    "deployment-modes (saas)",
    "deployment-modes (self-hosted)",
    "deployment-modes (air-gapped)",
    "k8s-e2e",
    "fleet",
    "admission-e2e",
    "engine",
    "proto",
    "release-verify",
    "openapi",
    "observability",
    "images (iam)",
    "images (gateway)",
    "images (posture)",
    "images (posture-scanner)",
    "images (fips-probe)",
    "images (audit)",
    "images (risk)",
    "images (notify)",
    "images (integrate)",
    "images (engine-gate)",
    "images (engine)",
    "web",
    "ui-e2e",
    "upgrade / upgrade",
    "pdfua",
    "infra",
    "infra-drift",
  ]
  validation {
    condition     = length(var.required_checks) > 0 && alltrue([for c in var.required_checks : length(trimspace(c)) > 0])
    error_message = "At least one required check, none empty."
  }
}

variable "bypass_actors" {
  description = "Repository roles that may bypass the rules in an emergency (each bypass is recorded by GitHub). Empty: nobody."
  type        = list(number)
  default     = []
}

variable "instance_reviewers" {
  description = "Who approves the instance pipeline's applies (environment instances): GitHub user and team ids; at least one (F-012 T-14)."
  type = object({
    users = list(number)
    teams = list(number)
  })
  validation {
    condition     = length(var.instance_reviewers.users) + length(var.instance_reviewers.teams) > 0 && length(var.instance_reviewers.users) + length(var.instance_reviewers.teams) <= 6
    error_message = "One to six reviewers (GitHub's limit is six)."
  }
}

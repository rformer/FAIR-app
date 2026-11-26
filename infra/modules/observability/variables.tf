variable "account_id" {
  description = "The operations account."
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

variable "evidence_retention_days" {
  description = "Object Lock (compliance) retention of the evidence bucket: 7 years (design §4)."
  type        = number
  default     = 2557
  validation {
    condition     = var.evidence_retention_days >= 2557
    error_message = "Evidence is kept at least 7 years."
  }
}

variable "workload_role_arns" {
  description = "IRSA roles of the ops cluster's workloads (Loki, Tempo, the evidence receiver); empty until the ops cluster exists (T-13)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.workload_role_arns : can(regex("^arn:aws-us-gov:iam::[0-9]{12}:role/", a)) && !strcontains(a, "*")])
    error_message = "Role ARNs, no wildcards."
  }
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}

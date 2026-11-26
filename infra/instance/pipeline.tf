# Given by the pipeline (scripts/infra-instance.sh, from the repository
# variables and infra/instance-account's output), never by the spec: a spec
# setting one of these is refused (scripts/infra-check.sh,
# scripts/infra-instance.sh), so a pull request cannot point its plan at
# another account or role.

variable "account_id" {
  description = "The instance's account (infra/instance-account output account_id)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id)) && var.account_id != var.management_account_id
    error_message = "A 12-digit account id, not the management account."
  }
}

variable "mode" {
  description = "plan (pull requests, drift: the read-only fair-instance-plan role and the parent zone's read role) or apply (after approval: the infrastructure role and the delegation role)."
  type        = string
  default     = "plan"
  validation {
    condition     = contains(["plan", "apply"], var.mode)
    error_message = "plan or apply."
  }
}

variable "management_account_id" {
  description = "The GovCloud management account (the pipeline's roles; fair-instance-plan trusts its fair-instances-plan)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "A 12-digit account id."
  }
}

variable "log_archive" {
  description = "The log archive (security root output log_archive): the account's Config deliveries."
  type = object({
    bucket      = string
    kms_key_arn = string
  })
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.log_archive.bucket)) && can(regex("^arn:aws-us-gov:kms:us-gov-(west|east)-1:[0-9]{12}:key/", var.log_archive.kms_key_arn))
    error_message = "A bucket name and a GovCloud KMS key ARN."
  }
}

variable "dns" {
  description = "The SaaS parent zone (shared root output dns_delegation): the instance's zone is delegated there."
  type = object({
    account_id        = string
    zone_id           = string
    domain            = string
    read_role_arn     = string
    delegate_role_arn = string
  })
  validation {
    condition = (can(regex("^[0-9]{12}$", var.dns.account_id)) && can(regex("^Z[A-Z0-9]{1,31}$", var.dns.zone_id))
      && can(regex("^arn:aws-us-gov:iam::${var.dns.account_id}:role/[A-Za-z0-9+=,.@_-]+$", var.dns.read_role_arn))
    && can(regex("^arn:aws-us-gov:iam::${var.dns.account_id}:role/[A-Za-z0-9+=,.@_-]+$", var.dns.delegate_role_arn)))
    error_message = "The parent zone's account, zone id, domain and its two roles (in that account)."
  }
}

variable "ops_telemetry" {
  description = "The ops account's telemetry endpoint service (instance module), or null."
  type = object({
    service_name = string
    ports        = list(number)
  })
  default = null
  validation {
    condition     = var.ops_telemetry == null || can(regex("^com\\.amazonaws\\.vpce\\.us-gov-(west|east)-1\\.vpce-svc-[0-9a-f]+$", var.ops_telemetry.service_name))
    error_message = "A GovCloud VPC endpoint service name."
  }
}

variable "infrastructure_role_name" {
  description = "The instance account's infrastructure role (applies)."
  type        = string
  default     = "OrganizationAccountAccessRole"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.infrastructure_role_name))
    error_message = "A role name."
  }
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = { "fair:managed-by" = "opentofu" }
  validation {
    condition     = alltrue([for k, _ in var.tags : length(k) > 0])
    error_message = "Tag keys are not empty."
  }
}

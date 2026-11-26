# The instance's spec: infra/instances/<name>.tfvars (a pull request;
# infra/instances/examples/example.tfvars shows every field). Only these
# variables may be set by a spec (pipeline.tf's come from the pipeline).

variable "instance" {
  description = "The instance id: the tfvars file's name, every resource's name, the secrets' prefix fair/<instance>/."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}[a-z0-9]$", var.instance))
    error_message = "3 to 21 characters: lower-case letters, digits and hyphens, starting with a letter."
  }
}

variable "account_email" {
  description = "The instance account's owner address (a distribution list), read by infra/instance-account when it creates the account."
  type        = string
  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.account_email))
    error_message = "An address."
  }
}

variable "domain" {
  description = "The instance's public name: <name>.<the SaaS parent domain> (var.dns.domain), delegated by this root."
  type        = string
  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", var.domain)) && endswith(var.domain, ".${var.dns.domain}") && !strcontains(trimsuffix(var.domain, ".${var.dns.domain}"), ".")
    error_message = "A lower-case DNS name one label below the SaaS parent domain (var.dns.domain)."
  }
}

variable "region" {
  description = "The home region."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.region)
    error_message = "A GovCloud (US) region."
  }
}

variable "replica_region" {
  description = "The second GovCloud region (replicas, backup copies)."
  type        = string
  default     = "us-gov-east-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.replica_region) && var.replica_region != var.region
    error_message = "The other GovCloud (US) region."
  }
}

variable "availability_zones" {
  description = "Three zones of the home region."
  type        = list(string)
  default     = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
  validation {
    condition     = length(var.availability_zones) == 3 && length(distinct(var.availability_zones)) == 3 && alltrue([for z in var.availability_zones : startswith(z, var.region)])
    error_message = "Three distinct zones of the home region."
  }
}

variable "vpc_cidr" {
  description = "The VPC's range (a private /16)."
  type        = string
  default     = "10.40.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && endswith(var.vpc_cidr, "/16") && startswith(var.vpc_cidr, "10.")
    error_message = "A /16 in 10.0.0.0/8."
  }
}

variable "node_instance_types" {
  description = "The nodes' instance types (x86_64, for Bottlerocket FIPS)."
  type        = list(string)
  default     = ["m6i.xlarge"]
  validation {
    condition     = length(var.node_instance_types) > 0 && alltrue([for t in var.node_instance_types : can(regex("^[a-z][a-z0-9]*[a-z0-9]\\.[0-9]*[a-z]+$", t)) && !can(regex("^[a-z0-9]+g[a-z]*\\.", t))])
    error_message = "x86_64 instance types (no Graviton: Bottlerocket's FIPS variant here is x86_64)."
  }
}

variable "node_count" {
  description = "Nodes: min, desired, max (at least one per zone)."
  type = object({
    min     = number
    desired = number
    max     = number
  })
  default = { min = 3, desired = 3, max = 9 }
  validation {
    condition     = var.node_count.min >= 3 && var.node_count.min <= var.node_count.desired && var.node_count.desired <= var.node_count.max && var.node_count.max <= 50
    error_message = "3 <= min <= desired <= max <= 50."
  }
}

variable "db_instance_class" {
  description = "The database's instance class."
  type        = string
  default     = "db.r6i.large"
  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[0-9]*[a-z]+$", var.db_instance_class))
    error_message = "An RDS instance class (db.<family>.<size>)."
  }
}

variable "audit_worm_retention_days" {
  description = "Object Lock (compliance) retention of the audit WORM copies: the agreed retention of the audit trail."
  type        = number
  default     = 2557
  validation {
    condition     = var.audit_worm_retention_days >= 365 && floor(var.audit_worm_retention_days) == var.audit_worm_retention_days
    error_message = "Whole days, at least a year."
  }
}

variable "audit_retention_days" {
  description = "How long the audit replicas keep their copies (audit.retention_total)."
  type        = number
  default     = 2557
  validation {
    condition     = var.audit_retention_days >= var.audit_worm_retention_days && floor(var.audit_retention_days) == var.audit_retention_days
    error_message = "Whole days, at least the WORM retention."
  }
}

variable "status" {
  description = "active; retiring (exports are taken, the database's and load balancer's deletion protection lifted); retired (workloads removed, retained stores kept). docs/operations/decommissioning.md."
  type        = string
  default     = "active"
  validation {
    condition     = contains(["active", "retiring", "retired"], var.status)
    error_message = "active, retiring or retired."
  }
}

variable "retirement" {
  description = "The decommissioning record (null while active): the change that asked for it, the dates, and the SHA-256 digests of the customer's export and the audit evidence export (both required before retired)."
  type = object({
    change                 = string
    requested_on           = string
    retain_until           = string
    customer_export_sha256 = optional(string)
    audit_export_sha256    = optional(string)
  })
  default = null
  validation {
    condition = var.status == "active" ? var.retirement == null : (
      var.retirement != null
      && length(trimspace(try(var.retirement.change, ""))) > 0
      && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", try(var.retirement.requested_on, "")))
      && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", try(var.retirement.retain_until, "")))
      && try(timecmp("${var.retirement.retain_until}T00:00:00Z", timeadd("${var.retirement.requested_on}T00:00:00Z", "${var.audit_worm_retention_days * 24}h")) >= 0, false)
    )
    error_message = "Active: null. Retiring or retired: change, requested_on and retain_until (YYYY-MM-DD), retain_until at least the audit retention after requested_on."
  }
  validation {
    condition = var.status != "retired" || (
      can(regex("^[0-9a-f]{64}$", try(var.retirement.customer_export_sha256, "")))
      && can(regex("^[0-9a-f]{64}$", try(var.retirement.audit_export_sha256, "")))
    )
    error_message = "Retired only after the customer's export and the audit evidence export are taken: both SHA-256 digests (lower-case hex) recorded."
  }
}

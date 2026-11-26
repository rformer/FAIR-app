variable "instance" {
  description = "The instance id (lower case, a letter first): names every resource, the secrets' prefix fair/<instance>/ and the cluster."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}[a-z0-9]$", var.instance))
    error_message = "3 to 21 characters: lower-case letters, digits and hyphens, starting with a letter."
  }
}

variable "account_id" {
  description = "The instance's own account (one account per instance, ADR-016): every principal and resource the module names is in it."
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
    error_message = "Instances run in AWS GovCloud (US) (ADR-016)."
  }
}

variable "region" {
  description = "The home region (the aws provider's)."
  type        = string
  default     = "us-gov-west-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.region)
    error_message = "A GovCloud (US) region."
  }
}

variable "replica_region" {
  description = "The second GovCloud region (the aws.replica provider's): replicas of the audit and store buckets, the database's backup copies."
  type        = string
  default     = "us-gov-east-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.replica_region) && var.replica_region != var.region
    error_message = "The other GovCloud (US) region."
  }
}

variable "availability_zones" {
  description = "Three Availability Zones of the home region (design §3.5)."
  type        = list(string)
  default     = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
  validation {
    condition     = length(var.availability_zones) == 3 && length(distinct(var.availability_zones)) == 3 && alltrue([for z in var.availability_zones : startswith(z, var.region)])
    error_message = "Three distinct zones of the home region."
  }
}

variable "vpc_cidr" {
  description = "The VPC's range (a /16): workload subnets /19, database and public subnets /24."
  type        = string
  default     = "10.40.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && endswith(var.vpc_cidr, "/16")
    error_message = "An IPv4 /16."
  }
}

variable "domain" {
  description = "The instance's public name (the gateway's): its public hosted zone, certificate and load balancer record. Delegated from the parent zone at onboarding (T-14)."
  type        = string
  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", var.domain))
    error_message = "A lower-case DNS name without a trailing dot."
  }
}

variable "private_domain" {
  description = "The private hosted zone's name (internal names; default <instance>.fair.internal)."
  type        = string
  default     = null
}

variable "kubernetes_version" {
  description = "The EKS cluster's Kubernetes version."
  type        = string
  default     = "1.34"
  validation {
    condition     = can(regex("^1\\.[0-9]{2}$", var.kubernetes_version))
    error_message = "A Kubernetes minor version, such as 1.34."
  }
}

variable "node_instance_types" {
  description = "Instance types of the managed node group (x86_64: the Bottlerocket FIPS variant)."
  type        = list(string)
  default     = ["m6i.xlarge"]
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
    condition     = var.node_count.min >= 3 && var.node_count.min <= var.node_count.desired && var.node_count.desired <= var.node_count.max
    error_message = "min >= 3 (one per zone) <= desired <= max."
  }
}

variable "node_data_volume_gib" {
  description = "The nodes' data volume (containers, images), GiB."
  type        = number
  default     = 100
}

variable "cluster_admin_role_arns" {
  description = "Roles given cluster administration by EKS access entries (the instance pipeline's role, for Flux's bootstrap). Roles of this account only; operators come through just-in-time access (design §3.9)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.cluster_admin_role_arns : can(regex("^arn:aws-us-gov:iam::${var.account_id}:role/[A-Za-z0-9+=,.@_/-]+$", a))])
    error_message = "Role ARNs of the instance's own account, no wildcards."
  }
}

variable "secret_reader_role_arns" {
  description = "Roles besides External Secrets that may read the key-layout entries' values (the pipeline's key-rotation role: `iam keys rotate` works on a copy taken from the store, docs/install/keys.md). Never the database passwords, and never operators (design §3.9). Roles of this account only."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.secret_reader_role_arns : can(regex("^arn:aws-us-gov:iam::${var.account_id}:role/[A-Za-z0-9+=,.@_/-]+$", a))])
    error_message = "Role ARNs of the instance's own account, no wildcards."
  }
}

variable "gateway_port" {
  description = "The gateway pods' HTTPS port (the load balancer's targets)."
  type        = number
  default     = 8443
}

variable "external_egress_ports" {
  description = "TCP ports nodes may reach outside the VPC through the NAT gateways: HTTPS (webhooks, connectors, AWS APIs without an endpoint) and SMTP submission (465, 587). Which pods may use them is the platform's NetworkPolicies' (only notify and integrate, F-009, F-011)."
  type        = list(number)
  default     = [443, 465, 587]
  validation {
    condition     = alltrue([for p in var.external_egress_ports : p >= 1 && p <= 65535 && floor(p) == p]) && !contains(var.external_egress_ports, 22) && !contains(var.external_egress_ports, 80)
    error_message = "TCP ports; never 22 or plaintext HTTP."
  }
}

variable "interface_endpoints" {
  description = "AWS services reached through interface VPC endpoints (com.amazonaws.<region>.<name>), so nodes call them without leaving the VPC. FIPS variants where the service has one; confirm the list in the sandbox apply (T-14)."
  type        = list(string)
  default     = ["sts", "ecr.api", "ecr.dkr", "secretsmanager", "kms-fips", "logs", "ec2", "elasticloadbalancing", "eks", "acm-pca"]
}

variable "ops_telemetry" {
  description = "The ops account's telemetry endpoint service (PrivateLink; the instance Collector forwards there, deploy/observability/collector-saas.yaml): {service_name, ports}, or null until the ops cluster offers it."
  type = object({
    service_name = string
    ports        = list(number)
  })
  default = null
  validation {
    condition     = var.ops_telemetry == null || can(regex("^com\\.amazonaws\\.vpce\\.us-gov-(west|east)-1\\.vpce-svc-[0-9a-f]+$", var.ops_telemetry.service_name))
    error_message = "A GovCloud VPC endpoint service name (com.amazonaws.vpce.<region>.vpce-svc-...)."
  }
}

variable "db_instance_class" {
  description = "The database's instance class."
  type        = string
  default     = "db.r6i.large"
}

variable "db_allocated_storage_gib" {
  description = "The database's initial storage, GiB (grows to db_max_allocated_storage_gib)."
  type        = number
  default     = 100
}

variable "db_max_allocated_storage_gib" {
  description = "The database's storage autoscaling ceiling, GiB."
  type        = number
  default     = 1000
}

variable "postgres_version" {
  description = "The PostgreSQL major version (16, F-001: the platform's tests run PostgreSQL 16); minor versions upgrade in the maintenance window."
  type        = string
  default     = "16"
  validation {
    condition     = var.postgres_version == "16" || startswith(var.postgres_version, "16.")
    error_message = "PostgreSQL 16."
  }
}

variable "db_backup_retention_days" {
  description = "Automated backups and point-in-time recovery, days (design §3.5: 35)."
  type        = number
  default     = 35
  validation {
    condition     = var.db_backup_retention_days == 35
    error_message = "Point-in-time recovery covers 35 days (design §3.5)."
  }
}

variable "db_iam_authentication" {
  description = "Allow IAM database authentication besides the roles' passwords (the services use passwords from files)."
  type        = bool
  default     = true
}

variable "db_ca_cert_identifier" {
  description = "The RDS certificate authority the database's server certificate chains to (the services verify it: PGSSLMODE=verify-full, PGSSLROOTCERT)."
  type        = string
  default     = "rds-ca-rsa4096-g1"
}

variable "audit_worm_retention_days" {
  description = "Object Lock (compliance) default retention of the audit WORM bucket (checkpoint copies, F-002 AC-10), days; each copy also sets its own retention."
  type        = number
  default     = 2557
  validation {
    condition     = var.audit_worm_retention_days >= 365
    error_message = "At least a year (the smallest audit.retention_total bound)."
  }
}

variable "audit_retention_days" {
  description = "How long the audit replicas keep a copy (audit.retention_total; the replicas do not receive the source's deletes)."
  type        = number
  default     = 2557
  validation {
    condition     = var.audit_retention_days >= 365
    error_message = "At least a year (the smallest audit.retention_total bound)."
  }
}

variable "report_replica_days" {
  description = "How long the report store's replica keeps a copy (report.retention_days, at most 365; the replica does not receive the purges)."
  type        = number
  default     = 30
  validation {
    condition     = var.report_replica_days >= 1 && var.report_replica_days <= 365
    error_message = "1 to 365 days (report.retention_days is at most a year)."
  }
}

variable "waf_rate_limit" {
  description = "Requests per client address per five minutes before the web ACL blocks it."
  type        = number
  default     = 2000
  validation {
    condition     = var.waf_rate_limit >= 100
    error_message = "At least 100 (WAF's minimum)."
  }
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = {}
}

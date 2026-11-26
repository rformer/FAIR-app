output "vpc_id" {
  description = "The instance's VPC (null once retired)."
  value       = one(aws_vpc.this[*].id)
}

output "subnet_ids" {
  description = "Subnets by tier (public, workload, database), each in zone order (null once retired)."
  value = !local.live ? null : {
    public   = [for z in var.availability_zones : aws_subnet.public[z].id]
    workload = [for z in var.availability_zones : aws_subnet.workload[z].id]
    database = [for z in var.availability_zones : aws_subnet.database[z].id]
  }
}

output "cluster" {
  description = "The EKS cluster: name, private API endpoint, CA, OIDC provider (IRSA); null once retired."
  value = !local.live ? null : {
    name                  = aws_eks_cluster.this[0].name
    endpoint              = aws_eks_cluster.this[0].endpoint
    certificate_authority = aws_eks_cluster.this[0].certificate_authority[0].data
    oidc_provider_arn     = aws_iam_openid_connect_provider.cluster[0].arn
  }
}

output "workload_roles" {
  description = "IRSA role ARNs by workload, for the service accounts' eks.amazonaws.com/role-arn annotations in the instance overlay (T-15): external-secrets (fair-platform/fair-external-secrets), audit, risk, load-balancer-controller, privateca-issuer, ebs-csi."
  value       = { for k, r in aws_iam_role.irsa : k => r.arn }
}

output "database" {
  description = "PostgreSQL: host (PGHOST, verify-full: the RDS name itself), port, database, the RDS CA bundle id, and the master secret's ARN (RDS-managed); null once retired (the final snapshot is fair-<instance>-final)."
  value = !local.live ? null : {
    host              = aws_db_instance.this[0].address
    port              = aws_db_instance.this[0].port
    database          = aws_db_instance.this[0].db_name
    ca_cert           = aws_db_instance.this[0].ca_cert_identifier
    master_secret_arn = aws_db_instance.this[0].master_user_secret[0].secret_arn
  }
}

output "buckets" {
  description = "The stores (home region) and their replicas."
  value = {
    audit_worm           = module.audit_worm.id
    audit_store          = module.audit_store.id
    report_store         = module.report_store.id
    access               = module.access.id
    audit_worm_replica   = module.audit_worm_replica.id
    audit_store_replica  = module.audit_store_replica.id
    report_store_replica = module.report_store_replica.id
    access_replica       = module.access_replica.id
  }
}

output "service_environment" {
  description = "The stores' environment for the platform's manifests (the instance overlay, T-15): bucket, S3 FIPS endpoint (host:port), region and web-identity credentials (the service's IRSA role; ADR-012 amendment 1) per FAIR_<STORE> prefix."
  value = {
    for prefix, bucket in {
      FAIR_AUDIT_WORM   = module.audit_worm.id
      FAIR_AUDIT_STORE  = module.audit_store.id
      FAIR_REPORT_STORE = module.report_store.id
      } : prefix => {
      "${prefix}_BUCKET"      = bucket
      "${prefix}_ENDPOINT"    = local.s3_endpoint
      "${prefix}_REGION"      = var.region
      "${prefix}_CREDENTIALS" = "web-identity"
    }
  }
}

output "kms_keys" {
  description = "Key ARNs by purpose: home and replica."
  value = {
    home    = { for k, v in aws_kms_key.home : k => v.arn }
    replica = { for k, v in aws_kms_key.replica : k => v.arn }
    dnssec  = one(aws_kms_key.dnssec[*].arn)
  }
}

output "secret_names" {
  description = "The Secrets Manager entries (values loaded at onboarding, T-14)."
  value       = sort([for s in aws_secretsmanager_secret.this : s.name])
}

output "gateway_target_group_arn" {
  description = "The public load balancer's target group, for the gateway's TargetGroupBinding (T-15)."
  value       = one(aws_lb_target_group.gateway[*].arn)
}

output "dns" {
  description = "Zones: the public zone's id and name servers (delegated from the parent at onboarding), the private zone's id, the DNSSEC signing key's DS record."
  value = !local.live ? null : {
    public_zone_id  = aws_route53_zone.public[0].zone_id
    name_servers    = aws_route53_zone.public[0].name_servers
    private_zone_id = aws_route53_zone.private[0].zone_id
    private_domain  = local.private_domain
    ds_record       = aws_route53_key_signing_key.public[0].ds_record
  }
}

output "private_ca_arn" {
  description = "The internal Private CA, for cert-manager's AWSPCAClusterIssuer (T-15)."
  value       = one(aws_acmpca_certificate_authority.internal[*].arn)
}

output "web_acl_arn" {
  description = "The public entry's WAF web ACL."
  value       = one(aws_wafv2_web_acl.public[*].arn)
}

output "policy_documents" {
  description = "Every IAM, key, bucket, secret, endpoint and log resource policy the module writes, by name (the isolation tests read them)."
  value = merge(
    { for k, v in aws_kms_key.home : "kms/${k}" => v.policy },
    { for k, v in aws_kms_key.replica : "kms-replica/${k}" => v.policy },
    { for k in aws_kms_key.dnssec : "kms/dnssec" => k.policy },
    {
      "s3/access"               = module.access.policy
      "s3/audit-worm"           = module.audit_worm.policy
      "s3/audit-store"          = module.audit_store.policy
      "s3/report-store"         = module.report_store.policy
      "s3/access-replica"       = module.access_replica.policy
      "s3/audit-worm-replica"   = module.audit_worm_replica.policy
      "s3/audit-store-replica"  = module.audit_store_replica.policy
      "s3/report-store-replica" = module.report_store_replica.policy
    },
    { for k, v in local.trust_policy : "trust/${k}" => v },
    { for k, v in local.role_policy : "role/${k}" => v.policy },
    { for k, v in aws_secretsmanager_secret_policy.this : "secret/${k}" => v.policy },
    { for k, v in aws_vpc_endpoint.interface : "endpoint/${k}" => v.policy if contains(local.endpoint_policy_services, k) },
    { for e in aws_vpc_endpoint.s3 : "endpoint/s3" => e.policy },
    { for l in aws_cloudwatch_log_resource_policy.dns : "logs/dns" => l.policy_document },
    { for l in aws_cloudwatch_log_resource_policy.waf : "logs/waf" => l.policy_document },
  )
}

output "status" {
  description = "The instance's lifecycle state (var.status): active, retiring (exports taken; the database's and load balancer's deletion protection lifted), retired (workloads removed; the retained stores, keys and logs kept)."
  value       = var.status
}

output "retained" {
  description = "What decommissioning keeps (docs/operations/decommissioning.md): the stores and their replicas, every key that encrypts them, the log groups, the replication role, and the database's final snapshot (outside OpenTofu's state, encrypted with the database key)."
  value = {
    buckets = {
      audit_worm           = module.audit_worm.id
      audit_store          = module.audit_store.id
      report_store         = module.report_store.id
      access               = module.access.id
      audit_worm_replica   = module.audit_worm_replica.id
      audit_store_replica  = module.audit_store_replica.id
      report_store_replica = module.report_store_replica.id
      access_replica       = module.access_replica.id
    }
    kms_keys            = merge({ for k, v in aws_kms_key.home : k => v.arn }, { for k, v in aws_kms_key.replica : "replica/${k}" => v.arn })
    log_groups          = sort(local.retained_log_groups)
    replication_role    = aws_iam_role.service["replication"].arn
    database_snapshot   = "${local.name}-final"
    database_backup_key = aws_kms_key.replica["database"].arn
  }
}

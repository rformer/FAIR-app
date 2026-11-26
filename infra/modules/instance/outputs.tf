output "vpc_id" {
  description = "The instance's VPC."
  value       = aws_vpc.this.id
}

output "subnet_ids" {
  description = "Subnets by tier (public, workload, database), each in zone order."
  value = {
    public   = [for z in var.availability_zones : aws_subnet.public[z].id]
    workload = [for z in var.availability_zones : aws_subnet.workload[z].id]
    database = [for z in var.availability_zones : aws_subnet.database[z].id]
  }
}

output "cluster" {
  description = "The EKS cluster: name, private API endpoint, CA, OIDC provider (IRSA)."
  value = {
    name                  = aws_eks_cluster.this.name
    endpoint              = aws_eks_cluster.this.endpoint
    certificate_authority = aws_eks_cluster.this.certificate_authority[0].data
    oidc_provider_arn     = aws_iam_openid_connect_provider.cluster.arn
  }
}

output "workload_roles" {
  description = "IRSA role ARNs by workload, for the service accounts' eks.amazonaws.com/role-arn annotations in the instance overlay (T-15): external-secrets (fair-platform/fair-external-secrets), audit, risk, load-balancer-controller, privateca-issuer, ebs-csi."
  value       = { for k, r in aws_iam_role.irsa : k => r.arn }
}

output "database" {
  description = "PostgreSQL: host (PGHOST, verify-full: the RDS name itself), port, database, the RDS CA bundle id, and the master secret's ARN (RDS-managed)."
  value = {
    host              = aws_db_instance.this.address
    port              = aws_db_instance.this.port
    database          = aws_db_instance.this.db_name
    ca_cert           = aws_db_instance.this.ca_cert_identifier
    master_secret_arn = aws_db_instance.this.master_user_secret[0].secret_arn
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
  description = "The stores' environment for the platform's manifests (the instance overlay, T-15): bucket, S3 FIPS endpoint (host:port), region per FAIR_<STORE> prefix."
  value = {
    for prefix, bucket in {
      FAIR_AUDIT_WORM   = module.audit_worm.id
      FAIR_AUDIT_STORE  = module.audit_store.id
      FAIR_REPORT_STORE = module.report_store.id
      } : prefix => {
      "${prefix}_BUCKET"   = bucket
      "${prefix}_ENDPOINT" = local.s3_endpoint
      "${prefix}_REGION"   = var.region
    }
  }
}

output "kms_keys" {
  description = "Key ARNs by purpose: home and replica."
  value = {
    home    = { for k, v in aws_kms_key.home : k => v.arn }
    replica = { for k, v in aws_kms_key.replica : k => v.arn }
    dnssec  = aws_kms_key.dnssec.arn
  }
}

output "secret_names" {
  description = "The Secrets Manager entries (values loaded at onboarding, T-14)."
  value       = sort([for s in aws_secretsmanager_secret.this : s.name])
}

output "gateway_target_group_arn" {
  description = "The public load balancer's target group, for the gateway's TargetGroupBinding (T-15)."
  value       = aws_lb_target_group.gateway.arn
}

output "dns" {
  description = "Zones: the public zone's id and name servers (delegated from the parent at onboarding), the private zone's id, the DNSSEC signing key's DS record."
  value = {
    public_zone_id  = aws_route53_zone.public.zone_id
    name_servers    = aws_route53_zone.public.name_servers
    private_zone_id = aws_route53_zone.private.zone_id
    private_domain  = local.private_domain
    ds_record       = aws_route53_key_signing_key.public.ds_record
  }
}

output "private_ca_arn" {
  description = "The internal Private CA, for cert-manager's AWSPCAClusterIssuer (T-15)."
  value       = aws_acmpca_certificate_authority.internal.arn
}

output "web_acl_arn" {
  description = "The public entry's WAF web ACL."
  value       = aws_wafv2_web_acl.public.arn
}

output "policy_documents" {
  description = "Every IAM, key, bucket, secret, endpoint and log resource policy the module writes, by name (the isolation tests read them)."
  value = merge(
    { for k, v in aws_kms_key.home : "kms/${k}" => v.policy },
    { for k, v in aws_kms_key.replica : "kms-replica/${k}" => v.policy },
    { "kms/dnssec" = aws_kms_key.dnssec.policy },
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
    { "endpoint/s3" = aws_vpc_endpoint.s3.policy },
    {
      "logs/dns" = aws_cloudwatch_log_resource_policy.dns.policy_document
      "logs/waf" = aws_cloudwatch_log_resource_policy.waf.policy_document
    },
  )
}

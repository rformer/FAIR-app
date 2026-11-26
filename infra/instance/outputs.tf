output "account_id" {
  description = "The instance's account."
  value       = var.account_id
}

output "status" {
  description = "The instance's lifecycle state."
  value       = var.status
}

output "pipeline" {
  description = "The roles this root runs as in the instance account (plan: read-only; apply: the infrastructure role) and in the parent zone's account."
  value = {
    plan_role_arn      = local.role_arn.plan
    apply_role_arn     = local.role_arn.apply
    current_role_arn   = local.role_arn[var.mode]
    dns_role_arn       = local.dns_role_arn[var.mode]
    plan_role_trust    = local.plan_trust
    plan_role_denied   = local.plan_deny
    plan_role_policies = [aws_iam_role_policy_attachment.plan.policy_arn]
  }
}

output "access" {
  description = "fair-access-eks (just-in-time operator access entries, F-012 T-18): its ARN, trust and policy; null until access_controller_role_arn is given, and once retired."
  value = !local.access_enabled ? null : {
    eks_role_arn = aws_iam_role.access_eks[0].arn
    trust        = local.access_trust
    policy       = local.access_policy
  }
}

output "delegation" {
  description = "The zone's NS and DS records in the parent zone (null once retired)."
  value = !local.live ? null : {
    name         = var.domain
    name_servers = aws_route53_record.delegation_ns[0].records
    ds           = aws_route53_record.delegation_ds[0].records
  }
}

output "secret_names" {
  description = "The Secrets Manager entries scripts/infra-instance.sh loads at onboarding (values from `iam keys init` and generated passwords)."
  value       = module.instance.secret_names
}

output "service_environment" {
  description = "The stores' environment for the instance overlay (T-15)."
  value       = module.instance.service_environment
}

output "workload_roles" {
  description = "IRSA role ARNs for the instance overlay (T-15)."
  value       = module.instance.workload_roles
}

output "cluster" {
  description = "The EKS cluster (null once retired)."
  value       = module.instance.cluster
}

output "database" {
  description = "PostgreSQL (null once retired)."
  value       = module.instance.database
}

output "retained" {
  description = "What decommissioning keeps (docs/operations/decommissioning.md)."
  value       = module.instance.retained
}

output "retirement" {
  description = "The decommissioning record (null while active)."
  value       = var.retirement
}

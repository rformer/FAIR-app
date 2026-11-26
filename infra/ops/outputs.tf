output "buckets" {
  description = "The operations buckets (evidence, loki, tempo)."
  value       = module.observability.buckets
}

output "operator_access" {
  description = "accessctl's role (the instance roots' access_controller_role_arn, the access workflow's AWS_ROLE_ARN) and the values of the fleet repository's access/controller.yaml; null until configured."
  value = var.operator_access == null ? null : {
    controller_role_arn = module.operator_access[0].controller_role_arn
    controller_config   = merge(module.operator_access[0].controller_config, { region = var.region })
  }
}

output "controller_role_arn" {
  description = "accessctl's role (the access workflow's AWS_ROLE_ARN; the instance roots' access_controller_role_arn)."
  value       = aws_iam_role.controller.arn
}

output "controller_config" {
  description = "The values of the fleet repository's access/controller.yaml."
  value = {
    format       = "fair.access-controller.v1"
    partition    = var.partition
    instance_arn = var.sso_instance_arn
    permission_sets = { for role, ps in aws_ssoadmin_permission_set.this : role => {
      arn  = ps.arn
      name = ps.name
    } }
    eks_role = var.eks_role_name
  }
}

output "denied_actions" {
  description = "The data-plane actions both permission sets deny."
  value       = local.denied_actions
}

output "policy_documents" {
  description = "Every policy the module writes (for the tests)."
  value = {
    inline            = local.inline_policy
    controller        = local.controller_policy
    controller_trust  = local.controller_trust
    view_only         = local.view_only_policy_arn
    permission_set_of = { for role, ps in local.permission_sets : role => ps.name }
  }
}

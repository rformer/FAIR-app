output "roles" {
  description = "The pipeline's roles (the repository variables of infra-instances.yml, docs/operations/onboarding.md)."
  value = {
    plan             = aws_iam_role.plan.arn
    apply            = aws_iam_role.apply.arn
    commercial_plan  = aws_iam_role.commercial_plan.arn
    commercial_apply = aws_iam_role.commercial_apply.arn
  }
}

output "policy_documents" {
  description = "The roles' trust and permission policies, by name (the tests read them)."
  value = {
    "trust/plan"             = local.trust_plan
    "trust/apply"            = local.trust_apply
    "trust/commercial_plan"  = local.trust_commercial_plan
    "trust/commercial_apply" = local.trust_commercial_apply
    "role/plan"              = local.policy.plan
    "role/apply"             = local.policy.apply
    "role/commercial_plan"   = local.policy.commercial_plan
    "role/commercial_apply"  = local.policy.commercial_apply
  }
}

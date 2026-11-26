# F-012 T-14 (F-012-AC-16; design §3.5): the protected environment the
# instance pipeline's applies run in (.github/workflows/infra-instances.yml,
# job apply). Its required reviewers approve each apply after seeing the
# plan; the person who started the run cannot approve it; only main
# deploys; admins do not bypass. The management account's
# fair-instances-apply role trusts only OIDC tokens of this environment
# (subject repo:<repo>:environment:instances:job_workflow_ref:...).
resource "github_repository_environment" "instances" {
  repository          = var.repository
  environment         = "instances"
  prevent_self_review = true
  can_admins_bypass   = false

  reviewers {
    users = var.instance_reviewers.users
    teams = var.instance_reviewers.teams
  }

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

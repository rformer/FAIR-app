# F-012 T-12 (design §3.3, §6 "E: the release key is misused"; ADR-016):
# the repository's OIDC subject template. Adding job_workflow_ref to the sub
# claim lets the release key's sign-only role (infra/modules/release-signing)
# trust only the release-sign.yml reusable workflow on a v* tag through sub
# alone, the one claim STS checks in every partition:
#   repo:<owner>/<repo>:ref:refs/tags/<tag>:job_workflow_ref:<owner>/<repo>/.github/workflows/release-sign.yml@refs/tags/<tag>
# Keyless signing is unaffected: Fulcio names a workflow by job_workflow_ref,
# never by sub.
resource "github_actions_repository_oidc_subject_claim_customization_template" "repository" {
  repository         = var.repository
  use_default        = false
  include_claim_keys = ["repo", "context", "job_workflow_ref"]
}

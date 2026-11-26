# F-012 T-02: the ruleset's invariants, with a mock provider (no GitHub call).
mock_provider "github" {}

variables {
  instance_reviewers = { users = [1001], teams = [] }
}

run "protects_the_default_branch" {
  command = plan

  assert {
    condition     = github_repository_ruleset.main.enforcement == "active" && github_repository_ruleset.main.target == "branch"
    error_message = "the ruleset must be active on branches"
  }
  assert {
    condition     = contains(github_repository_ruleset.main.conditions[0].ref_name[0].include, "~DEFAULT_BRANCH")
    error_message = "the ruleset must cover the default branch"
  }
  assert {
    condition     = github_repository_ruleset.main.rules[0].non_fast_forward && github_repository_ruleset.main.rules[0].deletion
    error_message = "no force pushes, no deletion"
  }
  assert {
    condition     = github_repository_ruleset.main.rules[0].required_linear_history && github_repository_ruleset.main.rules[0].required_signatures
    error_message = "linear, signed history"
  }
}

run "a_second_engineer_approves" {
  command = plan

  assert {
    condition     = github_repository_ruleset.main.rules[0].pull_request[0].required_approving_review_count >= 1
    error_message = "at least one approval"
  }
  assert {
    condition     = github_repository_ruleset.main.rules[0].pull_request[0].require_last_push_approval
    error_message = "the approver must not be the last pusher"
  }
  assert {
    condition     = github_repository_ruleset.main.rules[0].pull_request[0].require_code_owner_review && github_repository_ruleset.main.rules[0].pull_request[0].dismiss_stale_reviews_on_push
    error_message = "code owners review; a new push dismisses earlier approvals"
  }
}

run "every_gate_is_required" {
  command = plan

  assert {
    condition = alltrue([for c in ["test", "lint", "ui-e2e", "deployment-modes (air-gapped)", "images (iam)", "images (engine)"] :
    contains([for r in github_repository_ruleset.main.rules[0].required_status_checks[0].required_check : r.context], c)])
    error_message = "the platform's gates must be required checks"
  }
  assert {
    condition     = github_repository_ruleset.main.rules[0].required_status_checks[0].strict_required_status_checks_policy
    error_message = "checks must pass on the branch as merged (up to date with main)"
  }
}

run "nobody_bypasses_by_default" {
  command = plan

  assert {
    condition     = length(github_repository_ruleset.main.bypass_actors) == 0
    error_message = "no bypass unless configured"
  }
}

run "empty_checks_refused" {
  command = plan
  variables {
    required_checks = []
  }
  expect_failures = [var.required_checks]
}

# F-012 T-12: the sub claim names the reusable workflow, as the release
# key's sign-only role expects (infra/modules/release-signing).
run "oidc_subject_names_the_workflow" {
  command = plan

  assert {
    condition     = !github_actions_repository_oidc_subject_claim_customization_template.repository.use_default
    error_message = "the repository uses its own subject template"
  }
  assert {
    condition     = github_actions_repository_oidc_subject_claim_customization_template.repository.include_claim_keys == tolist(["repo", "context", "job_workflow_ref"])
    error_message = "sub is repo:<repo>:<context>:job_workflow_ref:<workflow>, in that order"
  }
}

# F-012 T-14: applies to instances wait for a reviewer who did not start
# them, from main only.
run "instance_applies_need_an_approval" {
  command = plan

  assert {
    condition     = github_repository_environment.instances.environment == "instances" && github_repository_environment.instances.prevent_self_review && !github_repository_environment.instances.can_admins_bypass
    error_message = "the instances environment: no self-review, no admin bypass"
  }
  assert {
    condition     = github_repository_environment.instances.reviewers[0].users == toset([1001])
    error_message = "its required reviewers"
  }
  assert {
    condition     = github_repository_environment.instances.deployment_branch_policy[0].protected_branches && !github_repository_environment.instances.deployment_branch_policy[0].custom_branch_policies
    error_message = "only protected branches (main) deploy"
  }
}

run "an_environment_without_reviewers_refused" {
  command = plan
  variables {
    instance_reviewers = { users = [], teams = [] }
  }
  expect_failures = [var.instance_reviewers]
}

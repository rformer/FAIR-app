# F-012 T-02: the ruleset's invariants, with a mock provider (no GitHub call).
mock_provider "github" {}

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
    condition = alltrue([for c in ["test", "lint", "ui-e2e", "deployment-modes (air-gapped)", "image"] :
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

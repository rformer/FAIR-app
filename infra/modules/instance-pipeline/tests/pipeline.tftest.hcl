# F-012 T-14 (F-012-AC-14, AC-16; design §3.5, §6 "T: infrastructure drifts
# from code"): the instance pipeline's roles, with mock providers. The plan
# role reads and never writes; the apply role is assumable only from the
# protected environment on main and reaches only instance accounts.
mock_provider "aws" {}

mock_provider "aws" {
  alias = "commercial"
}

variables {
  account_id            = "111111111111"
  commercial_account_id = "999999999999"
  organization_id       = "o-abcdefghij"
  instances_ou_path     = "o-abcdefghij/r-ab12/ou-ab12-abcdefgh/"
  protected_account_ids = ["444444444444", "222222222222", "333333333333"]
  state_bucket          = "fair-tofu-state-111111111111"
  dns_read_role_arn     = "arn:aws-us-gov:iam::222222222222:role/fair-dns-read"
  dns_delegate_role_arn = "arn:aws-us-gov:iam::222222222222:role/fair-dns-delegate"
}

run "trust_is_this_workflow_only" {
  command = plan

  assert {
    condition = alltrue([for k in ["trust/plan", "trust/commercial_plan"] : length(jsondecode(output.policy_documents[k]).Statement) == 2 && alltrue([for s in jsondecode(output.policy_documents[k]).Statement :
      s.Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com" && (
        s.Sid == "PullRequestPlans" ? s.Condition.StringLike["token.actions.githubusercontent.com:sub"] == "repo:rformer/FAIR-app:pull_request:job_workflow_ref:rformer/FAIR-app/.github/workflows/infra-instances.yml@refs/pull/*/merge"
        : s.Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:rformer/FAIR-app:ref:refs/heads/main:job_workflow_ref:rformer/FAIR-app/.github/workflows/infra-instances.yml@refs/heads/main"
    )])])
    error_message = "plans: infra-instances.yml on a pull request or on main (the subject template of infra/github)"
  }
  assert {
    condition = alltrue([for k in ["trust/apply", "trust/commercial_apply"] : alltrue([for s in jsondecode(output.policy_documents[k]).Statement :
      s.Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:rformer/FAIR-app:environment:instances:job_workflow_ref:rformer/FAIR-app/.github/workflows/infra-instances.yml@refs/heads/main"
    && !can(s.Condition.StringLike)])])
    error_message = "applies: only the protected environment, the workflow at main, matched exactly"
  }
  assert {
    condition = alltrue([for k, d in output.policy_documents : alltrue([for s in jsondecode(d).Statement :
      s.Action == "sts:AssumeRoleWithWebIdentity" && endswith(s.Principal.Federated, ":oidc-provider/token.actions.githubusercontent.com")
    ]) if startswith(k, "trust/")])
    error_message = "every role is assumed with a GitHub OIDC token only"
  }
}

run "the_plan_roles_never_write" {
  command = plan

  # Every allowed action is a read: Get, List, Describe, Decrypt of the
  # state, or assuming a read-only role.
  assert {
    condition = alltrue([for k in ["role/plan", "role/commercial_plan"] : alltrue([for s in jsondecode(output.policy_documents[k]).Statement :
      alltrue([for a in flatten([s.Action]) : can(regex("^[a-z0-9-]+:(Get|List|Describe)[A-Za-z]*$", a)) || contains(["kms:Decrypt", "sts:AssumeRole"], a)])
    if s.Effect == "Allow"])])
    error_message = "the plan roles allow reads only"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/plan"]).Statement :
      toset(flatten([s.Resource])) == toset(["arn:aws-us-gov:iam::*:role/fair-instance-plan"]) && s.Condition["ForAnyValue:StringLike"]["aws:ResourceOrgPaths"] == ["o-abcdefghij/r-ab12/ou-ab12-abcdefgh/*"]
    if s.Effect == "Allow" && s.Action == "sts:AssumeRole" && s.Sid != "ReadTheParentZone"])
    error_message = "the plan role assumes only the instances' read-only role, in the instances OU"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.policy_documents["role/plan"]).Statement :
    s.Sid == "ReadTheParentZone" && s.Resource == "arn:aws-us-gov:iam::222222222222:role/fair-dns-read"])
    error_message = "and the parent zone's read role, never its delegation role"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/plan"]).Statement :
      alltrue([for r in flatten([s.Resource]) : startswith(r, "arn:aws-us-gov:s3:::fair-tofu-state-111111111111/instances/") || r == "arn:aws-us-gov:s3:::fair-tofu-state-111111111111"])
    if startswith(s.Sid, "ListInstanceState") || startswith(s.Sid, "ReadInstanceState")])
    error_message = "the state it reads is the instances' only"
  }
}

run "the_apply_role_reaches_instance_accounts_only" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
      toset(flatten([s.Resource])) == toset(["arn:aws-us-gov:iam::*:role/OrganizationAccountAccessRole"])
    if s.Effect == "Allow" && s.Action == "sts:AssumeRole" && s.Sid != "DelegateInTheParentZone"])
    error_message = "the apply role assumes the infrastructure role of an account, nothing else (and the delegation role)"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
    s.Sid == "InfrastructureRoleOfAnInstance" && s.Condition["ForAnyValue:StringLike"]["aws:ResourceOrgPaths"] == ["o-abcdefghij/r-ab12/ou-ab12-abcdefgh/*"]])
    error_message = "in the instances OU"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
    s.Sid == "InfrastructureRoleOfANewAccount" && s.Condition.Null["aws:ResourceOrgID"] == "true"])
    error_message = "or in a new account outside any organization (to accept the invitation)"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
      s.Effect == "Deny" && contains(flatten([s.Action]), "sts:AssumeRole") && toset(s.Resource) == toset([
        "arn:aws-us-gov:iam::111111111111:role/*", "arn:aws-us-gov:iam::222222222222:role/*",
        "arn:aws-us-gov:iam::333333333333:role/*", "arn:aws-us-gov:iam::444444444444:role/*",
    ])])
    error_message = "never a role of the management or a core account"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
      s.Effect == "Deny" && contains(s.Action, "organizations:MoveAccount") && contains(s.Action, "organizations:TagResource") && length(s.Resource) == 4
    && alltrue([for r in s.Resource : startswith(r, "arn:aws-us-gov:organizations::111111111111:account/o-abcdefghij/")])])
    error_message = "the management and core accounts cannot be moved into the instances OU (or retagged)"
  }
  assert {
    condition = alltrue([for k in ["role/apply", "role/commercial_apply"] : anytrue([for s in jsondecode(output.policy_documents[k]).Statement :
    s.Effect == "Deny" && contains(s.Action, "organizations:CloseAccount") && contains(s.Action, "organizations:RemoveAccountFromOrganization") && s.Resource == "*"])])
    error_message = "no account is ever closed or removed (decommissioning keeps the account and its retained stores)"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/apply"]).Statement :
      alltrue([for r in flatten([s.Resource]) : startswith(r, "arn:aws-us-gov:s3:::fair-tofu-state-111111111111/instances/") || r == "arn:aws-us-gov:s3:::fair-tofu-state-111111111111"])
    if startswith(s.Sid, "ListInstanceState") || startswith(s.Sid, "WriteInstanceState")])
    error_message = "the state it writes is the instances' only (never the core roots')"
  }
}

run "the_commercial_apply_role_creates_govcloud_accounts_only" {
  command = plan

  assert {
    condition = toset(flatten([for s in jsondecode(output.policy_documents["role/commercial_apply"]).Statement : s.Action if s.Effect == "Allow" && !startswith(s.Sid, "Read")])) == toset([
      "organizations:CreateGovCloudAccount", "organizations:TagResource", "iam:CreateServiceLinkedRole",
    ])
    error_message = "beyond reads: CreateGovCloudAccount (tagged) and Organizations' service-linked role"
  }
}

run "wildcard_ou_path_refused" {
  command = plan
  variables {
    instances_ou_path = "o-abcdefghij/*"
  }
  expect_failures = [var.instances_ou_path]
}

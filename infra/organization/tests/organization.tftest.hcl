# F-012 T-12: the organization's invariants, with mock providers.
mock_provider "aws" {
  mock_resource "aws_organizations_organization" {
    defaults = {
      id    = "o-abcdefghij"
      roots = [{ id = "r-ab12", arn = "arn:aws-us-gov:organizations::111111111111:root/o-abcdefghij/r-ab12", name = "Root", policy_types = [] }]
    }
  }
  mock_resource "aws_organizations_organizational_unit" {
    defaults = { id = "ou-ab12-abcdefgh" }
  }
}

mock_provider "aws" {
  alias = "commercial"
}

variables {
  account_id            = "111111111111"
  commercial_account_id = "999999999999"
  core_accounts = {
    security = { email = "fair-security@example.com" }
    shared   = { email = "fair-shared@example.com" }
    ops      = { email = "fair-ops@example.com" }
  }
}

run "an_organization_with_guardrails_on_its_root" {
  command = plan

  assert {
    condition     = aws_organizations_organization.this.feature_set == "ALL" && contains(aws_organizations_organization.this.enabled_policy_types, "SERVICE_CONTROL_POLICY")
    error_message = "all features, with service control policies"
  }
  assert {
    condition     = length(module.guardrails.policy_ids) == 3
    error_message = "the three guardrail policies"
  }
  assert {
    condition     = alltrue([for s in ["cloudtrail.amazonaws.com", "config.amazonaws.com", "guardduty.amazonaws.com"] : contains(aws_organizations_organization.this.aws_service_access_principals, s)])
    error_message = "trusted access for CloudTrail, Config and GuardDuty"
  }
  assert {
    condition     = aws_organizations_organizational_unit.core.parent_id == "r-ab12" && aws_organizations_organizational_unit.instances.parent_id == "r-ab12"
    error_message = "core and instances OUs under the root"
  }
  assert {
    condition     = jsondecode(module.guardrails.documents["fair-region-transport"]).Statement[0].Condition.StringNotEquals["aws:RequestedRegion"] == ["us-gov-west-1", "us-gov-east-1"]
    error_message = "the organization's regions are GovCloud's"
  }
}

run "core_accounts_are_govcloud_accounts" {
  command = plan

  assert {
    condition     = toset(keys(aws_organizations_account.commercial)) == toset(["security", "shared", "ops"])
    error_message = "the security, shared and ops accounts"
  }
  assert {
    condition     = alltrue([for a in aws_organizations_account.commercial : a.create_govcloud && a.iam_user_access_to_billing == "DENY" && !a.close_on_deletion])
    error_message = "each with its GovCloud account, no IAM billing access, never closed by a destroy"
  }
  assert {
    condition     = length(aws_organizations_account.member) == 0 && length(aws_organizations_delegated_administrator.security) == 0 && length(aws_guardduty_organization_admin_account.security) == 0
    error_message = "nothing is delegated before the security account has joined"
  }
  assert {
    condition     = length(module.baseline) == 0
    error_message = "the management account's Config waits for the log archive"
  }
}

run "joined_accounts_are_placed_and_security_delegated" {
  command = plan
  variables {
    govcloud_account_ids = { security = "444444444444", shared = "222222222222", ops = "555555555555" }
    log_archive = {
      bucket      = "fair-log-archive-444444444444"
      kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/test"
    }
  }

  assert {
    condition     = alltrue([for a in aws_organizations_account.member : a.parent_id == aws_organizations_organizational_unit.core.id])
    error_message = "core accounts sit under the core OU"
  }
  assert {
    condition     = alltrue([for d in aws_organizations_delegated_administrator.security : d.account_id == "444444444444"]) && length(aws_organizations_delegated_administrator.security) == 3
    error_message = "CloudTrail and Config are delegated to the security account"
  }
  assert {
    condition     = aws_guardduty_organization_admin_account.security[0].admin_account_id == "444444444444"
    error_message = "GuardDuty is administered by the security account"
  }
  assert {
    condition     = length(module.baseline) == 1
    error_message = "the management account records Config to the archive"
  }
}

run "only_core_accounts" {
  command = plan
  variables {
    core_accounts = {
      security   = { email = "fair-security@example.com" }
      shared     = { email = "fair-shared@example.com" }
      ops        = { email = "fair-ops@example.com" }
      customer-a = { email = "a@example.com" }
    }
  }
  expect_failures = [var.core_accounts]
}

# F-012 T-14: the instance pipeline's roles reach the instances OU only,
# never the management or a joined core account.
run "the_instance_pipeline_reaches_the_instances_ou_only" {
  command = plan
  variables {
    govcloud_account_ids = { security = "444444444444", shared = "222222222222", ops = "333333333333" }
  }

  assert {
    condition = anytrue([for s in jsondecode(module.instance_pipeline.policy_documents["role/apply"]).Statement :
    s.Sid == "InfrastructureRoleOfAnInstance" && s.Condition["ForAnyValue:StringLike"]["aws:ResourceOrgPaths"] == ["o-abcdefghij/r-ab12/ou-ab12-abcdefgh/*"]])
    error_message = "the apply role's instance accounts are the instances OU's"
  }
  assert {
    condition = anytrue([for s in jsondecode(module.instance_pipeline.policy_documents["role/apply"]).Statement :
      s.Sid == "NeverTheManagementOrCoreAccounts" && toset(s.Resource) == toset([
        "arn:aws-us-gov:iam::111111111111:role/*", "arn:aws-us-gov:iam::222222222222:role/*",
        "arn:aws-us-gov:iam::333333333333:role/*", "arn:aws-us-gov:iam::444444444444:role/*",
    ])])
    error_message = "the management and the joined core accounts are protected"
  }
  assert {
    condition = alltrue([for s in jsondecode(module.instance_pipeline.policy_documents["role/plan"]).Statement :
    alltrue([for r in flatten([s.Resource]) : !startswith(r, "arn:aws-us-gov:s3:::") || startswith(r, "arn:aws-us-gov:s3:::fair-tofu-state-111111111111")])])
    error_message = "the state bucket is the management account's"
  }
}

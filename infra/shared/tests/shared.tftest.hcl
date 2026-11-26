# F-012 T-12: the shared-services root's wiring, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:222222222222:log-group:/aws/route53/fair-risk.example" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:222222222222:key/00000000-0000-0000-0000-000000000005" }
  }
}

variables {
  account_id             = "222222222222"
  organization_id        = "o-abcdefghij"
  pull_org_paths         = ["o-abcdefghij/r-ab12/ou-ab12-instances/*"]
  key_admin_trusted_arns = ["arn:aws-us-gov:iam::222222222222:role/fair-operator"]
  log_archive = {
    bucket      = "fair-log-archive-444444444444"
    kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/test"
  }
}

run "release_sign_yml_variables" {
  command = plan

  assert {
    condition = output.github_variables == {
      FAIR_RELEASE_KMS_KEY  = "alias/fair-release"
      FAIR_RELEASE_ROLE_ARN = "arn:aws-us-gov:iam::222222222222:role/fair-release-signer"
      FAIR_RELEASE_REGION   = "us-gov-west-1"
    }
    error_message = "the values release-sign.yml expects (alias, sign-only role, GovCloud region)"
  }
}

run "the_infrastructure_role_administers_but_never_signs" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(module.release_signing.key_policy).Statement :
      !contains(flatten([s.Action]), "kms:Sign")
    if s.Effect == "Allow" && contains(flatten([s.Principal.AWS]), "arn:aws-us-gov:iam::222222222222:role/OrganizationAccountAccessRole")])
    error_message = "the role applying this code administers the key and cannot sign"
  }
}

run "a_parent_zone_for_the_instances" {
  command = plan
  variables {
    parent_zone = {
      domain         = "fair-risk.example"
      plan_role_arn  = "arn:aws-us-gov:iam::111111111111:role/fair-instances-plan"
      apply_role_arn = "arn:aws-us-gov:iam::111111111111:role/fair-instances-apply"
    }
  }

  assert {
    condition     = output.dns_delegation.domain == "fair-risk.example" && output.dns_delegation.account_id == "222222222222"
    error_message = "the parent zone is the shared account's"
  }
}

run "no_parent_zone_by_default" {
  command = plan

  assert {
    condition     = length(module.parent_zone) == 0 && output.dns_delegation == null
    error_message = "the parent zone comes once its domain and the pipeline's roles are known"
  }
}

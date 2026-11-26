# F-012 T-14 (F-012-AC-14, AC-17; design §3.5): an instance's account, with
# mock providers: created through the commercial management account with
# its GovCloud pair, from the instance's own spec file, and placed under the
# instances OU once it has joined.
mock_provider "aws" {}

mock_provider "aws" {
  alias = "commercial"
  mock_resource "aws_organizations_account" {
    defaults = { govcloud_id = "777777777777", id = "888888888888" }
  }
}

variables {
  instance              = "example"
  instances_dir         = "../instances/examples"
  account_id            = "111111111111"
  commercial_account_id = "999999999999"
  commercial_role_arn   = "arn:aws:iam::999999999999:role/fair-instances-plan"
  instances_ou_id       = "ou-ab12-abcdefgh"
}

run "a_new_account_through_the_commercial_pair" {
  command = plan

  assert {
    condition = (aws_organizations_account.commercial.create_govcloud && aws_organizations_account.commercial.name == "fair-example"
      && aws_organizations_account.commercial.email == "aws+fair-example@fair-risk.example"
      && aws_organizations_account.commercial.role_name == "OrganizationAccountAccessRole"
    && aws_organizations_account.commercial.iam_user_access_to_billing == "DENY")
    error_message = "CreateGovCloudAccount, named for the instance, owned by the spec's address, with the infrastructure role"
  }
  assert {
    condition     = !aws_organizations_account.commercial.close_on_deletion && aws_organizations_account.commercial.tags["fair:instance"] == "example"
    error_message = "never closed by OpenTofu; tagged with its instance"
  }
  assert {
    condition     = length(aws_organizations_account.member) == 0 && output.account_id == "777777777777" && output.parent_id == null
    error_message = "before it joins, the GovCloud account id is known and nothing is placed"
  }
}

run "a_joined_account_under_the_instances_ou" {
  command = plan
  variables {
    joined = true
  }

  assert {
    condition     = aws_organizations_account.member[0].parent_id == "ou-ab12-abcdefgh" && !aws_organizations_account.member[0].close_on_deletion && aws_organizations_account.member[0].email == "aws+fair-example@fair-risk.example"
    error_message = "the joined account is placed under the instances OU, never closed"
  }
}

run "a_missing_spec_refused" {
  command = plan
  variables {
    instance = "nobody"
  }
  expect_failures = [aws_organizations_account.commercial]
}

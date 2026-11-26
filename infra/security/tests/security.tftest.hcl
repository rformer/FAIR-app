# F-012 T-12: the security root's wiring, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/00000000-0000-0000-0000-000000000004" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::444444444444:role/mock" }
  }
}

variables {
  account_id            = "444444444444"
  management_account_id = "111111111111"
  organization_id       = "o-abcdefghij"
}

run "the_account_records_to_its_own_archive" {
  command = plan

  assert {
    condition     = output.log_archive.bucket == "fair-log-archive-444444444444"
    error_message = "the archive every account delivers to"
  }
  assert {
    condition     = output.trail_arn == "arn:aws-us-gov:cloudtrail:us-gov-west-1:111111111111:trail/fair-organization"
    error_message = "the organization trail, owned by the management account"
  }
}

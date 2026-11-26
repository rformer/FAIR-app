# F-012 T-12: the state backend's invariants, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111111111111:key/00000000-0000-0000-0000-000000000003" }
  }
}

variables {
  account_id = "111111111111"
}

run "state_is_kept_and_encrypted" {
  command = plan

  assert {
    condition     = module.state.id == "fair-tofu-state-111111111111" && output.kms_key_alias == "alias/fair-tofu-state"
    error_message = "the bucket and key the *.s3.tfbackend files name"
  }
  assert {
    condition     = module.state.object_lock.enabled && module.state.object_lock.mode == "GOVERNANCE" && module.state.object_lock.days >= 30
    error_message = "every state version is under Object Lock"
  }
  assert {
    condition = anytrue([for s in jsondecode(module.state.policy).Statement :
    s.Effect == "Deny" && s.Principal == "*" && s.Action == "s3:BypassGovernanceRetention"])
    error_message = "nobody bypasses the retention"
  }
  assert {
    condition     = module.state.kms_key_arn == aws_kms_key.state.arn && aws_kms_key.state.enable_key_rotation
    error_message = "encrypted under the state key, which rotates"
  }
  assert {
    condition     = module.state.public_access_blocked && module.state.access_log_bucket == "fair-tofu-state-access-111111111111"
    error_message = "private, with access logs"
  }
  assert {
    condition     = alltrue([for s in jsondecode(module.state.policy).Statement : s.Effect == "Deny"])
    error_message = "the bucket policy grants nothing (access through the management account's IAM only)"
  }
}

run "commercial_region_refused" {
  command = plan
  variables {
    region = "us-east-1"
  }
  expect_failures = [var.region]
}

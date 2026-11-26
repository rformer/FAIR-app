# F-012 T-12: the operations root's wiring, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:555555555555:key/00000000-0000-0000-0000-000000000006" }
  }
  mock_resource "aws_ssoadmin_permission_set" {
    defaults = { arn = "arn:aws-us-gov:sso:::permissionSet/ssoins-7907a1b2c3d4e5f6/ps-0a1b2c3d4e5f6071" }
  }
}

variables {
  account_id = "555555555555"
  log_archive = {
    bucket      = "fair-log-archive-444444444444"
    kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/test"
  }
}

run "evidence_logs_and_traces_storage" {
  command = plan

  assert {
    condition = output.buckets == {
      evidence = "fair-evidence-555555555555"
      loki     = "fair-loki-555555555555"
      tempo    = "fair-tempo-555555555555"
    }
    error_message = "the ops buckets"
  }
}

run "no_operator_access_until_configured" {
  command = plan

  assert {
    condition     = length(module.operator_access) == 0 && output.operator_access == null
    error_message = "nothing before IAM Identity Center is enabled"
  }
}

# F-012 T-18 (design §3.9): the operator permission sets and accessctl's role.
run "operator_access" {
  command = plan
  variables {
    operator_access = {
      sso_instance_arn  = "arn:aws-us-gov:sso:::instance/ssoins-7907a1b2c3d4e5f6"
      fleet_repository  = "rformer/FAIR-fleet"
      instances_ou_path = "o-abcdefghij/r-ab12/ou-ab12-cdefghij/"
    }
  }

  assert {
    condition     = output.operator_access.controller_config.region == "us-gov-west-1" && output.operator_access.controller_config.eks_role == "fair-access-eks"
    error_message = "access/controller.yaml's values, in the home region"
  }
  assert {
    condition     = contains(module.operator_access[0].denied_actions, "s3:GetObject*") && contains(module.operator_access[0].denied_actions, "rds-db:connect")
    error_message = "the permission sets deny the data plane"
  }
}

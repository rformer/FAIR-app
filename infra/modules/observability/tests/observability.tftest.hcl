# F-012 T-12: the operations account's storage, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:555555555555:key/00000000-0000-0000-0000-000000000002" }
  }
}

variables {
  account_id = "555555555555"
}

run "evidence_is_kept_seven_years_write_once" {
  command = plan

  assert {
    condition     = output.evidence_object_lock.mode == "COMPLIANCE" && output.evidence_object_lock.days >= 2557
    error_message = "evidence under Object Lock compliance mode for 7 years"
  }
  assert {
    condition     = alltrue([module.evidence.public_access_blocked, module.loki.public_access_blocked, module.tempo.public_access_blocked])
    error_message = "no public bucket"
  }
  assert {
    condition     = alltrue([for k in [module.evidence.kms_key_arn, module.loki.kms_key_arn, module.tempo.kms_key_arn] : k == aws_kms_key.ops.arn])
    error_message = "every bucket under the ops key"
  }
}

run "no_workload_access_until_the_cluster_exists" {
  command = plan

  assert {
    condition     = alltrue([for b in [module.evidence.policy, module.loki.policy, module.tempo.policy] : alltrue([for s in jsondecode(b).Statement : s.Effect == "Deny"])])
    error_message = "without workload roles, the buckets grant nothing"
  }
}

run "workloads_never_delete_evidence" {
  command = plan
  variables {
    workload_role_arns = ["arn:aws-us-gov:iam::555555555555:role/fair-evidence-receiver"]
  }

  assert {
    condition = alltrue([for s in jsondecode(module.evidence.policy).Statement :
    !contains(flatten([s.Action]), "s3:DeleteObject") if s.Effect == "Allow"])
    error_message = "evidence is written and read, never deleted"
  }
}

run "short_evidence_retention_refused" {
  command = plan
  variables {
    evidence_retention_days = 365
  }
  expect_failures = [var.evidence_retention_days]
}

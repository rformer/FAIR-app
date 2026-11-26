# F-012 T-12: the operations root's wiring, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:555555555555:key/00000000-0000-0000-0000-000000000006" }
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

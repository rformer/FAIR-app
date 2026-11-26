# F-012 T-12: the security account's invariants, with a mock provider.
# ARNs the provider validates get well-formed mock values.
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/00000000-0000-0000-0000-000000000001" }
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

run "log_archive_is_write_once" {
  command = plan

  assert {
    condition     = module.archive.object_lock.enabled && module.archive.object_lock.mode == "COMPLIANCE" && module.archive.object_lock.days >= 365
    error_message = "the log archive is under Object Lock in compliance mode for at least a year"
  }
  assert {
    condition     = module.access_logs.object_lock.mode == "COMPLIANCE"
    error_message = "the archive's access logs are write-once too"
  }
  assert {
    condition     = module.archive.kms_key_arn == aws_kms_key.archive.arn && aws_kms_key.archive.enable_key_rotation
    error_message = "encrypted under the archive's own rotating key"
  }
  assert {
    condition     = module.archive.public_access_blocked && module.archive.access_log_bucket == "fair-log-archive-access-444444444444"
    error_message = "private, with server access logs"
  }
  assert {
    condition     = module.archive.id == "fair-log-archive-444444444444"
    error_message = "the archive's name"
  }
}

run "short_retention_refused" {
  command = plan
  variables {
    retention_days = 30
  }
  expect_failures = [var.retention_days]
}

run "archive_grants_only_the_trail_and_config" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(module.archive.policy).Statement :
      contains(["cloudtrail.amazonaws.com", "config.amazonaws.com"], try(s.Principal.Service, ""))
    if s.Effect == "Allow"])
    error_message = "the archive allows only CloudTrail and Config to write"
  }
  assert {
    condition = alltrue([for s in jsondecode(module.archive.policy).Statement :
      try(s.Condition.StringEquals["aws:SourceArn"], "") == "arn:aws-us-gov:cloudtrail:us-gov-west-1:111111111111:trail/fair-organization"
      || try(s.Condition.StringEquals["aws:SourceOrgID"], "") == "o-abcdefghij"
    if s.Effect == "Allow"])
    error_message = "each grant is bound to the organization trail or the organization"
  }
  assert {
    condition = alltrue([for s in jsondecode(module.archive.policy).Statement :
      !contains(flatten([s.Action]), "s3:DeleteObject") && !contains(flatten([s.Action]), "s3:*")
    if s.Effect == "Allow"])
    error_message = "no grant deletes or does everything"
  }
}

run "trail_covers_the_organization" {
  command = plan

  assert {
    condition = alltrue([
      aws_cloudtrail.organization.is_organization_trail,
      aws_cloudtrail.organization.is_multi_region_trail,
      aws_cloudtrail.organization.include_global_service_events,
      aws_cloudtrail.organization.enable_log_file_validation,
      aws_cloudtrail.organization.enable_logging,
    ])
    error_message = "an organization trail over every region, with log file validation, logging"
  }
  assert {
    condition     = aws_cloudtrail.organization.kms_key_id == aws_kms_key.archive.arn && aws_cloudtrail.organization.s3_bucket_name == "fair-log-archive-444444444444"
    error_message = "encrypted, to the log archive"
  }
}

run "guardduty_and_config_everywhere" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this.enable && aws_guardduty_organization_configuration.this.auto_enable_organization_members == "ALL"
    error_message = "GuardDuty on, for every member"
  }
  assert {
    condition     = alltrue([for f in aws_guardduty_organization_configuration_feature.this : f.auto_enable == "ALL"]) && contains(keys(aws_guardduty_organization_configuration_feature.this), "S3_DATA_EVENTS")
    error_message = "GuardDuty protections for every member"
  }
  assert {
    condition     = one(aws_config_configuration_aggregator.organization.organization_aggregation_source).all_regions
    error_message = "Config aggregated over the organization and every region"
  }
}

run "archive_key_grants_services_bound_to_the_organization" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.archive.policy).Statement :
      can(s.Condition)
    if s.Effect == "Allow" && can(s.Principal.Service)])
    error_message = "service principals use the key only under conditions"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.archive.policy).Statement :
      s.Principal.AWS == "arn:aws-us-gov:iam::444444444444:root"
    if s.Effect == "Allow" && can(s.Principal.AWS)])
    error_message = "no other account administers the archive key"
  }
}

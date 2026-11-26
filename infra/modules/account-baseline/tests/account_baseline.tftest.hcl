# F-012 T-12: every account's baseline, with a mock provider.
mock_provider "aws" {}

variables {
  account_id         = "333333333333"
  config_bucket      = "fair-log-archive-test"
  config_kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/test"
}

run "no_public_s3_and_encrypted_volumes" {
  command = plan

  assert {
    condition = alltrue([
      aws_s3_account_public_access_block.this.block_public_acls,
      aws_s3_account_public_access_block.this.block_public_policy,
      aws_s3_account_public_access_block.this.ignore_public_acls,
      aws_s3_account_public_access_block.this.restrict_public_buckets,
    ]) && aws_s3_account_public_access_block.this.account_id == var.account_id
    error_message = "the account blocks public S3 access entirely"
  }
  assert {
    condition     = aws_ebs_encryption_by_default.this.enabled
    error_message = "EBS volumes are encrypted by default"
  }
}

run "config_records_everything_to_the_archive" {
  command = plan

  assert {
    condition     = one(aws_config_configuration_recorder.this.recording_group).all_supported && one(aws_config_configuration_recorder.this.recording_group).include_global_resource_types
    error_message = "every supported resource, global ones in the home region"
  }
  assert {
    condition     = aws_config_configuration_recorder_status.this.is_enabled
    error_message = "the recorder is on"
  }
  assert {
    condition     = aws_config_delivery_channel.this.s3_bucket_name == var.config_bucket && aws_config_delivery_channel.this.s3_kms_key_arn == var.config_kms_key_arn
    error_message = "delivered to the log archive under its key"
  }
}

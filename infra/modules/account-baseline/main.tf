# F-012 T-12 (F-012-AC-15; design §3.5): what every account of the
# organization has, applied by each account's root (management, security,
# shared, ops; the instances with T-13):
#   - S3 Block Public Access for the whole account (the guardrails deny
#     changing it to anyone but the infrastructure role);
#   - EBS encryption by default;
#   - AWS Config recording every supported resource, delivered to the log
#     archive in the security account (the guardrails deny stopping it).
locals {
  config_role_arn = "arn:${var.partition}:iam::${var.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}

resource "aws_s3_account_public_access_block" "this" {
  account_id              = var.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_iam_service_linked_role" "config" {
  count            = var.create_config_service_linked_role ? 1 : 0
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "fair"
  role_arn = local.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.record_global_resources
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }

  depends_on = [aws_iam_service_linked_role.config]
}

resource "aws_config_delivery_channel" "this" {
  name           = "fair"
  s3_bucket_name = var.config_bucket
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.config_kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

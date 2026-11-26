# F-012 T-12: every bucket's invariants, with a mock provider (no AWS call).
mock_provider "aws" {}

variables {
  name        = "fair-test-bucket"
  kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111111111111:key/test"
}

run "encrypted_private_versioned" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "objects are encrypted with KMS"
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id == var.kms_key_arn
    error_message = "under the caller's key"
  }
  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.this.block_public_acls,
      aws_s3_bucket_public_access_block.this.block_public_policy,
      aws_s3_bucket_public_access_block.this.ignore_public_acls,
      aws_s3_bucket_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "no public access of any kind"
  }
  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Enabled"
    error_message = "versioned"
  }
  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "ACLs disabled"
  }
  assert {
    condition     = !aws_s3_bucket.this.force_destroy && !aws_s3_bucket.this.object_lock_enabled && length(aws_s3_bucket_object_lock_configuration.this) == 0
    error_message = "no force destroy; no Object Lock unless asked"
  }
}

run "policy_refuses_plaintext_and_other_encryption" {
  command = plan

  assert {
    condition = anytrue([for s in jsondecode(aws_s3_bucket_policy.this.policy).Statement :
    s.Effect == "Deny" && s.Principal == "*" && s.Action == "s3:*" && try(s.Condition.Bool["aws:SecureTransport"], "") == "false"])
    error_message = "requests without TLS are denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_s3_bucket_policy.this.policy).Statement :
    s.Effect == "Deny" && try(s.Condition.NumericLessThan["s3:TlsVersion"], "") == "1.2"])
    error_message = "TLS below 1.2 is denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_s3_bucket_policy.this.policy).Statement :
    s.Effect == "Deny" && s.Action == "s3:PutObject" && try(s.Condition.StringNotEquals["s3:x-amz-server-side-encryption"], []) == ["aws:kms", "aws:kms:dsse"]])
    error_message = "uploads naming another encryption are denied"
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_s3_bucket_policy.this.policy).Statement : s.Effect == "Deny"])
    error_message = "the baseline policy grants nothing"
  }
}

run "object_lock_compliance" {
  command = plan
  variables {
    object_lock = { mode = "COMPLIANCE", days = 365 }
  }

  assert {
    condition     = aws_s3_bucket.this.object_lock_enabled
    error_message = "Object Lock enabled at creation"
  }
  assert {
    condition     = one(one(aws_s3_bucket_object_lock_configuration.this[0].rule).default_retention).mode == "COMPLIANCE" && one(one(aws_s3_bucket_object_lock_configuration.this[0].rule).default_retention).days == 365
    error_message = "compliance mode, with the asked retention"
  }
}

run "object_lock_mode_checked" {
  command = plan
  variables {
    object_lock = { mode = "NONE", days = 1 }
  }
  expect_failures = [var.object_lock]
}

run "access_logging" {
  command = plan
  variables {
    access_log_bucket = "fair-test-logs"
  }

  assert {
    condition     = aws_s3_bucket_logging.this[0].target_bucket == "fair-test-logs"
    error_message = "server access logs go to the named bucket"
  }
}

run "kms_key_required" {
  command = plan
  variables {
    kms_key_arn = ""
  }
  expect_failures = [var.kms_key_arn]
}

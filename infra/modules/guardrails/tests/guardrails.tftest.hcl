# F-012 T-12 (design §3.5): the service control policies' invariants, with a
# mock provider (no AWS call). Every statement is checked by its Sid: present,
# a Deny, and denying what it should.
mock_provider "aws" {}

variables {
  target_ids = ["r-test"]
}

run "three_policies_attached_to_the_root" {
  command = plan

  assert {
    condition     = toset(keys(aws_organizations_policy.this)) == toset(["fair-region-transport", "fair-security-services", "fair-data-protection"])
    error_message = "the three guardrail policies"
  }
  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : p.type == "SERVICE_CONTROL_POLICY"])
    error_message = "service control policies"
  }
  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 3 && alltrue([for a in aws_organizations_policy_attachment.this : a.target_id == "r-test"])
    error_message = "each policy attached to every target"
  }
  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : length(p.content) <= 5120])
    error_message = "each policy fits the SCP size limit (5,120 characters)"
  }
}

run "every_statement_denies" {
  command = plan

  assert {
    condition = alltrue(flatten([for p in aws_organizations_policy.this : [for s in jsondecode(p.content).Statement :
    s.Effect == "Deny" && s.Resource == "*"]]))
    error_message = "a guardrail never allows: every statement is a Deny on every resource"
  }
  assert {
    condition = toset(flatten([for p in aws_organizations_policy.this : [for s in jsondecode(p.content).Statement : s.Sid]])) == toset([
      "DenyOutsideGovCloudRegions", "DenyInsecureTransport",
      "DenyStoppingCloudTrail", "DenyReconfiguringCloudTrail",
      "DenyDisablingGuardDuty", "DenyReconfiguringGuardDuty",
      "DenyDisablingConfig", "DenyReconfiguringConfig", "DenyLeavingOrganization",
      "DenyS3UploadsWithoutKMS", "DenyS3PublicACLs", "DenyS3PublicACLGrants", "DenyS3PublicAccessBlockChanges",
      "DenyUnencryptedRDS",
    ])
    error_message = "every guardrail statement is present (and no other)"
  }
}

run "govcloud_regions_only" {
  command = plan

  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-region-transport"].content).Statement :
      s.Sid == "DenyOutsideGovCloudRegions" && s.Condition.StringNotEquals["aws:RequestedRegion"] == ["us-gov-west-1", "us-gov-east-1"]
    && !contains(s.NotAction, "*") && !anytrue([for a in s.NotAction : startswith(a, "s3") || startswith(a, "kms") || startswith(a, "ec2")])])
    error_message = "requests outside us-gov-west-1 and us-gov-east-1 are denied, exempting only global services"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-region-transport"].content).Statement :
    s.Sid == "DenyInsecureTransport" && s.Action == "*" && s.Condition.Bool["aws:SecureTransport"] == "false"])
    error_message = "every request without TLS is denied"
  }
}

run "commercial_regions_refused" {
  command = plan
  variables {
    allowed_regions = ["us-east-1"]
  }
  expect_failures = [var.allowed_regions]
}

run "security_services_cannot_be_disabled" {
  command = plan

  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-security-services"].content).Statement :
      s.Sid == "DenyStoppingCloudTrail" && !can(s.Condition)
    && length(setsubtract(["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"], s.Action)) == 0])
    error_message = "nobody stops or deletes CloudTrail"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-security-services"].content).Statement :
      s.Sid == "DenyDisablingGuardDuty" && !can(s.Condition)
    && length(setsubtract(["guardduty:DeleteDetector", "guardduty:DisassociateFromAdministratorAccount", "guardduty:StopMonitoringMembers"], s.Action)) == 0])
    error_message = "nobody deletes or detaches GuardDuty"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-security-services"].content).Statement :
      s.Sid == "DenyDisablingConfig" && !can(s.Condition)
    && length(setsubtract(["config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel"], s.Action)) == 0])
    error_message = "nobody stops or deletes Config"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_organizations_policy.this["fair-security-services"].content).Statement :
      s.Condition.ArnNotLike["aws:PrincipalArn"] == ["arn:aws-us-gov:iam::*:role/OrganizationAccountAccessRole"]
    if can(s.Condition)])
    error_message = "only the infrastructure role reconfigures the security services"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-security-services"].content).Statement :
    s.Sid == "DenyLeavingOrganization" && s.Action == "organizations:LeaveOrganization" && !can(s.Condition)])
    error_message = "no account leaves the organization"
  }
}

run "data_is_encrypted_and_never_public" {
  command = plan

  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-data-protection"].content).Statement :
      s.Sid == "DenyS3UploadsWithoutKMS" && s.Action == "s3:PutObject"
      && s.Condition.Null["s3:x-amz-server-side-encryption"] == "false"
    && s.Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == ["aws:kms", "aws:kms:dsse"]])
    error_message = "S3 uploads asking for anything but KMS are denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-data-protection"].content).Statement :
      s.Sid == "DenyUnencryptedRDS" && s.Condition.Bool["rds:StorageEncrypted"] == "false"
    && length(setsubtract(["rds:CreateDBInstance", "rds:CreateDBCluster"], s.Action)) == 0])
    error_message = "unencrypted RDS instances and clusters are denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-data-protection"].content).Statement :
      s.Sid == "DenyS3PublicACLs"
    && length(setsubtract(["public-read", "public-read-write", "authenticated-read"], s.Condition.StringEquals["s3:x-amz-acl"])) == 0])
    error_message = "public canned ACLs are denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_organizations_policy.this["fair-data-protection"].content).Statement :
      s.Sid == "DenyS3PublicAccessBlockChanges"
      && length(setsubtract(["s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPublicAccessBlock"], s.Action)) == 0
    && s.Condition.ArnNotLike["aws:PrincipalArn"] == ["arn:aws-us-gov:iam::*:role/OrganizationAccountAccessRole"]])
    error_message = "only the infrastructure role changes public access blocks"
  }
}

run "nothing_unattached" {
  command = plan
  variables {
    target_ids = []
  }
  expect_failures = [var.target_ids]
}

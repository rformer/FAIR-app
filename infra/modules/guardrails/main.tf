# F-012 T-12 (F-012-AC-15; design §3.5): the organization's service control
# policies, attached to the targets (the organization root: every account but
# the management account, which SCPs never restrict).
#
# Three policies, each under the 5,120-character SCP limit:
#   fair-region-transport    GovCloud regions only; TLS on every request
#   fair-security-services   CloudTrail, GuardDuty and Config cannot be
#                            stopped or deleted; no account leaves
#   fair-data-protection     S3 uploads and RDS storage encrypted; no public
#                            S3 (ACLs, public access block changes)
#
# FIPS endpoints: IAM has no condition key naming the endpoint a request
# used, so an SCP cannot require them. They are required where the client
# is ours (the providers' use_fips_endpoint, AWS_USE_FIPS_ENDPOINT,
# internal/kmssign; ADR-016) and TLS is required here for every request.
locals {
  # Principals that apply the reviewed infrastructure code: the only ones
  # that may change a public access block or reconfigure (never stop or
  # delete) the security services.
  infrastructure_arns = [for r in var.infrastructure_role_names : "arn:${var.partition}:iam::*:role/${r}"]

  # Services without a regional endpoint choice; GovCloud serves them from
  # us-gov-west-1, so this exemption is defence in depth.
  global_actions = [
    "account:*",
    "health:*",
    "iam:*",
    "organizations:*",
    "sts:*",
    "support:*",
  ]

  statements = {
    "fair-region-transport" = [
      {
        Sid       = "DenyOutsideGovCloudRegions"
        Effect    = "Deny"
        NotAction = local.global_actions
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]

    "fair-security-services" = [
      {
        Sid    = "DenyStoppingCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteEventDataStore",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopEventDataStoreIngestion",
          "cloudtrail:StopLogging",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyReconfiguringCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:PutEventSelectors",
          "cloudtrail:PutInsightSelectors",
          "cloudtrail:UpdateEventDataStore",
          "cloudtrail:UpdateTrail",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.infrastructure_arns } }
      },
      {
        Sid    = "DenyDisablingGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DeleteMembers",
          "guardduty:DisableOrganizationAdminAccount",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:StopMonitoringMembers",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyReconfiguringGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:CreateFilter",
          "guardduty:CreateIPSet",
          "guardduty:UpdateDetector",
          "guardduty:UpdateFilter",
          "guardduty:UpdateIPSet",
          "guardduty:UpdateOrganizationConfiguration",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.infrastructure_arns } }
      },
      {
        Sid    = "DenyDisablingConfig"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigurationAggregator",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:DeleteRetentionConfiguration",
          "config:StopConfigurationRecorder",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyReconfiguringConfig"
        Effect = "Deny"
        Action = [
          "config:PutConfigurationAggregator",
          "config:PutConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:PutRetentionConfiguration",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.infrastructure_arns } }
      },
      {
        Sid      = "DenyLeavingOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      },
    ]

    "fair-data-protection" = [
      {
        # An upload may rely on the bucket's KMS default (no header) but
        # never ask for S3-managed or no encryption.
        Sid      = "DenyS3UploadsWithoutKMS"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          Null            = { "s3:x-amz-server-side-encryption" = "false" }
          StringNotEquals = { "s3:x-amz-server-side-encryption" = ["aws:kms", "aws:kms:dsse"] }
        }
      },
      {
        Sid       = "DenyS3PublicACLs"
        Effect    = "Deny"
        Action    = ["s3:CreateBucket", "s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"]
        Resource  = "*"
        Condition = { StringEquals = { "s3:x-amz-acl" = ["authenticated-read", "public-read", "public-read-write"] } }
      },
      {
        Sid       = "DenyS3PublicACLGrants"
        Effect    = "Deny"
        Action    = ["s3:CreateBucket", "s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"]
        Resource  = "*"
        Condition = { StringLike = { "s3:x-amz-grant-read" = ["*AllUsers*", "*AuthenticatedUsers*"] } }
      },
      {
        Sid    = "DenyS3PublicAccessBlockChanges"
        Effect = "Deny"
        Action = [
          "s3:DeleteAccountPublicAccessBlock",
          "s3:DeleteBucketPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.infrastructure_arns } }
      },
      {
        Sid    = "DenyUnencryptedRDS"
        Effect = "Deny"
        Action = [
          "rds:CreateDBCluster",
          "rds:CreateDBInstance",
          "rds:RestoreDBClusterFromS3",
          "rds:RestoreDBInstanceFromS3",
        ]
        Resource  = "*"
        Condition = { Bool = { "rds:StorageEncrypted" = "false" } }
      },
    ]
  }

  descriptions = {
    "fair-region-transport"  = "GovCloud (US) regions only; TLS on every request (F-012 design 3.5)."
    "fair-security-services" = "CloudTrail, GuardDuty and Config cannot be stopped or deleted; accounts cannot leave (F-012 design 3.5)."
    "fair-data-protection"   = "S3 uploads and RDS storage encrypted; no public S3 (F-012 design 3.5)."
  }

  documents = { for name, s in local.statements : name => jsonencode({ Version = "2012-10-17", Statement = s }) }

  attachments = { for pair in setproduct(keys(local.documents), var.target_ids) : "${pair[0]}/${pair[1]}" => { policy = pair[0], target = pair[1] } }
}

resource "aws_organizations_policy" "this" {
  for_each    = local.documents
  name        = each.key
  description = local.descriptions[each.key]
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value
  tags        = var.tags
}

resource "aws_organizations_policy_attachment" "this" {
  for_each  = local.attachments
  policy_id = aws_organizations_policy.this[each.value.policy].id
  target_id = each.value.target
}

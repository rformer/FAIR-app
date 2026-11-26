# F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing access
# to customer data"; ADR-016): just-in-time operator access, administered
# from the operations account (IAM Identity Center's delegated
# administrator, organization root).
#
#   - Two permission sets, FairReadOnly and FairOperator, assigned to nobody
#     here: accessctl (cmd/accessctl) assigns one to one operator in one
#     instance account for at most 8 hours, from an approved request in the
#     fleet repository's access/, and removes it at expiry. Both are AWS's
#     ViewOnlyAccess (configuration, never contents) plus a few operating
#     actions for FairOperator, and both explicitly deny every data-plane
#     action: object reads and writes in the stores, secret values, key use,
#     database connections and snapshots, sessions on nodes, the cluster's
#     access configuration, IAM changes and role assumption. Reading customer
#     data is possible only through the platform's break-glass (F-001
#     T-34/T-35), with the customer's recorded consent.
#   - fair-access-controller: accessctl's role, assumed only with a GitHub
#     OIDC token of the fleet repository's access environment (main only).
#     It may create and delete assignments of these two permission sets,
#     read assignments, and assume fair-access-eks in the instances OU's
#     accounts; it may never change a permission set or an identity.
locals {
  p                 = var.partition
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = "arn:${local.p}:iam::${var.account_id}:oidc-provider/${local.oidc_host}"
  subject           = "repo:${var.fleet_repository}:environment:${var.access_environment}"

  # The account the session is in: permission sets are provisioned into
  # every instance account, and each may reach only its own resources.
  self = "$${aws:PrincipalAccount}"

  permission_sets = {
    "read-only" = { name = "FairReadOnly", description = "FAIR operator, read-only: views configuration, never data (F-012 design 3.9)" }
    "operator"  = { name = "FairOperator", description = "FAIR operator: manages workloads, never reads data (F-012 design 3.9)" }
  }

  # Every data-plane action, denied to both permission sets whatever else
  # allows it (design §3.9): the stores' objects, secret values, the keys,
  # database connections and copies of the database, sessions on nodes and
  # copies of their volumes, certificates the services trust, the cluster's
  # access configuration (an access entry or pod identity would be standing
  # access), IAM changes and role assumption (no hop to a workload role).
  denied_actions = [
    "s3:GetObject*",
    "s3:PutObject*",
    "s3:DeleteObject*",
    "s3:RestoreObject",
    "s3:ReplicateObject",
    "s3:BypassGovernanceRetention",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutReplicationConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:CreateJob",
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:PutResourcePolicy",
    "secretsmanager:DeleteSecret",
    "secretsmanager:RotateSecret",
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
    "kms:CreateGrant",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
    "rds-db:connect",
    "rds-data:*",
    "rds:ModifyDBInstance",
    "rds:ModifyDBCluster",
    "rds:CreateDBSnapshot",
    "rds:CopyDBSnapshot",
    "rds:ModifyDBSnapshotAttribute",
    "rds:RestoreDBInstance*",
    "rds:StartExportTask",
    "rds:CreateDBInstanceReadReplica",
    "rds:DeleteDBInstance",
    "ssm:StartSession",
    "ssm:SendCommand",
    "ssm:GetParameter*",
    "ec2-instance-connect:*",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
    "ec2:GetPasswordData",
    "ec2:CreateSnapshot*",
    "ec2:CopySnapshot",
    "ec2:ModifySnapshotAttribute",
    "ec2:ModifyInstanceAttribute",
    "ec2:RunInstances",
    "ebs:*",
    "backup:StartRestoreJob",
    "backup:StartCopyJob",
    "acm-pca:IssueCertificate",
    "acm:ExportCertificate",
    "route53:ChangeResourceRecordSets",
    "eks:CreateAccessEntry",
    "eks:UpdateAccessEntry",
    "eks:DeleteAccessEntry",
    "eks:AssociateAccessPolicy",
    "eks:DisassociateAccessPolicy",
    "eks:CreatePodIdentityAssociation",
    "eks:UpdatePodIdentityAssociation",
    "eks:AssociateIdentityProviderConfig",
    "eks:UpdateClusterConfig",
    "iam:Create*",
    "iam:Put*",
    "iam:Attach*",
    "iam:Update*",
    "iam:Delete*",
    "iam:Add*",
    "iam:PassRole",
    "sts:AssumeRole*",
    "cloudshell:*",
  ]

  # What each role may do beyond ViewOnlyAccess, in its own account only.
  allowed = {
    "read-only" = [
      {
        Sid      = "ReachTheCluster"
        Action   = ["eks:DescribeCluster", "eks:ListClusters", "eks:AccessKubernetesApi"]
        Resource = ["arn:${local.p}:eks:*:${local.self}:cluster/fair-*"]
      },
    ]
    "operator" = [
      {
        Sid      = "ReachTheCluster"
        Action   = ["eks:DescribeCluster", "eks:ListClusters", "eks:AccessKubernetesApi", "eks:DescribeNodegroup", "eks:ListNodegroups"]
        Resource = ["arn:${local.p}:eks:*:${local.self}:cluster/fair-*", "arn:${local.p}:eks:*:${local.self}:nodegroup/fair-*/*/*"]
      },
      {
        Sid      = "ScaleNodes"
        Action   = ["eks:UpdateNodegroupConfig"]
        Resource = ["arn:${local.p}:eks:*:${local.self}:nodegroup/fair-*/*/*"]
      },
      {
        Sid      = "RebootTheDatabase"
        Action   = ["rds:RebootDBInstance"]
        Resource = ["arn:${local.p}:rds:*:${local.self}:db:fair-*"]
      },
      {
        Sid      = "ReadControlPlaneLogs"
        Action   = ["logs:GetLogEvents", "logs:FilterLogEvents"]
        Resource = ["arn:${local.p}:logs:*:${local.self}:log-group:/aws/eks/fair-*:*"]
      },
    ]
  }

  inline_policy = { for role, _ in local.permission_sets : role => jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [for s in local.allowed[role] : merge(s, { Effect = "Allow" })],
      [{
        Sid      = "NoDataPlane"
        Effect   = "Deny"
        Action   = local.denied_actions
        Resource = "*"
      }],
    )
  }) }

  view_only_policy_arn = "arn:${local.p}:iam::aws:policy/job-function/ViewOnlyAccess"

  controller_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "FleetAccessWorkflow"
      Effect    = "Allow"
      Principal = { Federated = local.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = local.subject
        }
      }
    }]
  })

  # What IAM Identity Center creates in a member account.
  reserved_iam = [
    "arn:${local.p}:iam::*:role/aws-reserved/sso.amazonaws.com/*",
    "arn:${local.p}:iam::*:saml-provider/AWSSSO_*",
  ]

  sso_resources = concat(
    [var.sso_instance_arn, "arn:${local.p}:sso:::account/*"],
    [for ps in aws_ssoadmin_permission_set.this : ps.arn],
  )

  controller_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssignTheFairPermissionSets"
        Effect   = "Allow"
        Action   = ["sso:CreateAccountAssignment", "sso:DeleteAccountAssignment"]
        Resource = local.sso_resources
      },
      {
        Sid    = "ReadAssignments"
        Effect = "Allow"
        Action = [
          "sso:ListAccountAssignments",
          "sso:ListAccountsForProvisionedPermissionSet",
          "sso:DescribeAccountAssignmentCreationStatus",
          "sso:DescribeAccountAssignmentDeletionStatus",
        ]
        Resource = local.sso_resources
      },
      {
        # IAM Identity Center provisions the permission set's role in the
        # instance account as part of an assignment; these are the
        # assignment calls' dependent actions (AWS's service authorization
        # reference), on the roles and SAML provider it reserves only.
        Sid    = "ProvisionTheReservedRoles"
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:PutRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:CreateSAMLProvider",
          "iam:GetSAMLProvider",
          "iam:UpdateSAMLProvider",
          "iam:DeleteSAMLProvider",
        ]
        Resource = local.reserved_iam
      },
      {
        Sid      = "InstanceClusterAccess"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:${local.p}:iam::*:role/${var.eks_role_name}"
        Condition = {
          "ForAnyValue:StringLike" = { "aws:ResourceOrgPaths" = ["${var.instances_ou_path}*"] }
        }
      },
      {
        # Whatever is added later: the controller never changes what a
        # permission set allows, and never who someone is.
        Sid    = "NeverChangePermissionSetsOrIdentities"
        Effect = "Deny"
        Action = [
          "sso:CreatePermissionSet",
          "sso:UpdatePermissionSet",
          "sso:DeletePermissionSet",
          "sso:PutInlinePolicyToPermissionSet",
          "sso:DeleteInlinePolicyFromPermissionSet",
          "sso:AttachManagedPolicyToPermissionSet",
          "sso:DetachManagedPolicyFromPermissionSet",
          "sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
          "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet",
          "sso:PutPermissionsBoundaryToPermissionSet",
          "sso:DeletePermissionsBoundaryFromPermissionSet",
          "identitystore:Create*",
          "identitystore:Update*",
          "identitystore:Delete*",
        ]
        Resource = "*"
      },
      {
        Sid         = "NoOtherIAM"
        Effect      = "Deny"
        Action      = "iam:*"
        NotResource = local.reserved_iam
      },
    ]
  })
}

resource "aws_ssoadmin_permission_set" "this" {
  for_each         = local.permission_sets
  instance_arn     = var.sso_instance_arn
  name             = each.value.name
  description      = each.value.description
  session_duration = var.session_duration
  tags             = var.tags
}

resource "aws_ssoadmin_managed_policy_attachment" "view_only" {
  for_each           = local.permission_sets
  instance_arn       = var.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  managed_policy_arn = local.view_only_policy_arn
}

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each           = local.permission_sets
  instance_arn       = var.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = local.inline_policy[each.key]
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

resource "aws_iam_role" "controller" {
  #checkov:skip=CKV_AWS_393:The sub is exact (StringEquals repo:<owner>/<name>:environment:<env>, no wildcard); Checkov cannot resolve var.fleet_repository, which has no default and whose validation refuses wildcards (tests/operator_access.tftest.hcl).
  name                 = var.controller_role_name
  description          = "accessctl: just-in-time operator access from the fleet repository's access workflow (F-012 T-18)"
  assume_role_policy   = local.controller_trust
  max_session_duration = 3600
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "controller" {
  name   = "just-in-time-access"
  role   = aws_iam_role.controller.id
  policy = local.controller_policy
}

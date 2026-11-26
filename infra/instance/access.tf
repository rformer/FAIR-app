# F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing access
# to customer data"): fair-access-eks, the role accessctl (the operations
# account's fair-access-controller) assumes in this account to give a
# just-in-time grant its EKS access entry and to remove it at expiry.
#
# It manages access entries only for the roles IAM Identity Center
# provisions for the two FAIR permission sets (AWSReservedSSO_FairReadOnly_*,
# AWSReservedSSO_FairOperator_*), with no Kubernetes group but fair:operator
# and no access policy but AmazonEKSViewPolicy at cluster scope; it finds
# those roles by listing roles. Nothing else: no administrator policy, no
# other principal, no change to the cluster.
#
# The instance pipeline gives access_controller_role_arn (the ops root's
# output operator_access.controller_role_arn); until then the role is not
# created. A retired instance has no cluster and no role.
locals {
  access_eks_role_name = "fair-access-eks"
  access_enabled       = var.access_controller_role_arn != null && local.live

  cluster_arn      = "arn:${local.p}:eks:${var.region}:${var.account_id}:cluster/${local.name}"
  access_entry_arn = "arn:${local.p}:eks:${var.region}:${var.account_id}:access-entry/${local.name}/*"
  view_policy_arn  = "arn:${local.p}:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
  # EKS takes Identity Center's roles without their path.
  sso_principals = [
    "arn:${local.p}:iam::${var.account_id}:role/AWSReservedSSO_FairReadOnly_*",
    "arn:${local.p}:iam::${var.account_id}:role/AWSReservedSSO_FairOperator_*",
  ]

  access_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccessController"
      Effect    = "Allow"
      Principal = { AWS = var.access_controller_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })

  access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAccessEntries"
        Effect   = "Allow"
        Action   = ["eks:ListAccessEntries", "eks:DescribeAccessEntry", "eks:ListAssociatedAccessPolicies"]
        Resource = [local.cluster_arn, local.access_entry_arn]
      },
      {
        Sid      = "EntriesForTheOperatorRolesOnly"
        Effect   = "Allow"
        Action   = "eks:CreateAccessEntry"
        Resource = local.cluster_arn
        Condition = {
          ArnLike                     = { "eks:principalArn" = local.sso_principals }
          "ForAllValues:StringEquals" = { "eks:kubernetesGroups" = ["fair:operator"] }
        }
      },
      {
        Sid      = "TheViewPolicyOnly"
        Effect   = "Allow"
        Action   = "eks:AssociateAccessPolicy"
        Resource = [local.cluster_arn, local.access_entry_arn]
        Condition = {
          ArnLike      = { "eks:principalArn" = local.sso_principals }
          StringEquals = { "eks:policyArn" = local.view_policy_arn, "eks:accessScope" = "cluster" }
        }
      },
      {
        Sid       = "RemoveTheOperatorRolesEntries"
        Effect    = "Allow"
        Action    = "eks:DeleteAccessEntry"
        Resource  = local.access_entry_arn
        Condition = { ArnLike = { "eks:principalArn" = local.sso_principals } }
      },
      {
        # ListRoles has no resource-level permission.
        Sid      = "FindTheProvisionedRoles"
        Effect   = "Allow"
        Action   = "iam:ListRoles"
        Resource = "*"
      },
      {
        Sid       = "NeverAnotherPrincipal"
        Effect    = "Deny"
        Action    = ["eks:CreateAccessEntry", "eks:UpdateAccessEntry", "eks:AssociateAccessPolicy", "eks:DeleteAccessEntry"]
        Resource  = "*"
        Condition = { ArnNotLike = { "eks:principalArn" = local.sso_principals } }
      },
      {
        Sid       = "NeverAnotherPolicy"
        Effect    = "Deny"
        Action    = "eks:AssociateAccessPolicy"
        Resource  = "*"
        Condition = { StringNotEquals = { "eks:policyArn" = local.view_policy_arn } }
      },
    ]
  })
}

resource "aws_iam_role" "access_eks" {
  count                = local.access_enabled ? 1 : 0
  name                 = local.access_eks_role_name
  description          = "FAIR ${var.instance}: just-in-time operator access entries (accessctl, F-012 T-18)"
  assume_role_policy   = local.access_trust
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "access_eks" {
  count  = local.access_enabled ? 1 : 0
  name   = "operator-access-entries"
  role   = aws_iam_role.access_eks[0].id
  policy = local.access_policy
}

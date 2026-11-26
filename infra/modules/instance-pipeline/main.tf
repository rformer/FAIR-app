# F-012 T-14 (F-012-AC-14, AC-16; design §3.5, §6 "T: infrastructure drifts
# from code"; ADR-016): the instance pipeline's roles in the two management
# accounts, trusted only by GitHub OIDC tokens of the infra-instances.yml
# workflow of this repository (the repository's subject template, infra/github:
# repo:<repo>:<context>:job_workflow_ref:<repo>/<workflow>@<ref>).
#
# GovCloud management account (the organization's, which holds the state):
#   - fair-instances-plan: pull requests' plans and the daily drift plans
#     (contexts pull_request and ref:refs/heads/main). Reads the instances'
#     state (instances/ in the state bucket) and the organization, and
#     assumes fair-instance-plan (read-only, infra/instance) in accounts of
#     the instances OU and the parent zone's read role. Writes nothing.
#   - fair-instances-apply: applies after approval (context
#     environment:<environment>, the protected GitHub Environment with
#     required reviewers; the workflow at refs/heads/main). Writes the
#     instances' state, invites a new instance account and places it under
#     the instances OU, and assumes the infrastructure role
#     (OrganizationAccountAccessRole) only in accounts of the instances OU, or
#     in a new account that has not joined any organization yet (to accept
#     the invitation). Never the management account or a core account.
#
# Commercial management account (paired with it; creates GovCloud accounts):
#   - fair-instances-plan: reads the accounts it created.
#   - fair-instances-apply: CreateGovCloudAccount, and reads.
locals {
  oidc_host = "token.actions.githubusercontent.com"
  p         = var.partition

  apply_subject = "repo:${var.repository}:environment:${var.environment}:job_workflow_ref:${var.repository}/${var.workflow}@refs/heads/main"

  state_bucket_arn = "arn:${local.p}:s3:::${var.state_bucket}"
  state_prefix     = "instances/"
  state_key_arns   = "arn:${local.p}:kms:*:${var.account_id}:key/*"

  # The accounts the apply role must never reach or move: this one and the
  # core accounts.
  protected_accounts = sort(distinct(concat([var.account_id], var.protected_account_ids)))

  trust_plan = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PullRequestPlans"
        Effect    = "Allow"
        Principal = { Federated = "arn:${local.p}:iam::${var.account_id}:oidc-provider/${local.oidc_host}" }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = { "${local.oidc_host}:aud" = "sts.amazonaws.com" }
          StringLike   = { "${local.oidc_host}:sub" = "repo:${var.repository}:pull_request:job_workflow_ref:${var.repository}/${var.workflow}@refs/pull/*/merge" }
        }
      },
      {
        Sid       = "MainPlansAndDrift"
        Effect    = "Allow"
        Principal = { Federated = "arn:${local.p}:iam::${var.account_id}:oidc-provider/${local.oidc_host}" }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_host}:aud" = "sts.amazonaws.com"
            "${local.oidc_host}:sub" = "repo:${var.repository}:ref:refs/heads/main:job_workflow_ref:${var.repository}/${var.workflow}@refs/heads/main"
          }
        }
      },
    ]
  })
  trust_apply = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ApprovedInstanceApplies"
      Effect    = "Allow"
      Principal = { Federated = "arn:${local.p}:iam::${var.account_id}:oidc-provider/${local.oidc_host}" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = local.apply_subject
        }
      }
    }]
  })
  trust_commercial_plan = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PullRequestPlans"
        Effect    = "Allow"
        Principal = { Federated = "arn:aws:iam::${var.commercial_account_id}:oidc-provider/${local.oidc_host}" }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = { "${local.oidc_host}:aud" = "sts.amazonaws.com" }
          StringLike   = { "${local.oidc_host}:sub" = "repo:${var.repository}:pull_request:job_workflow_ref:${var.repository}/${var.workflow}@refs/pull/*/merge" }
        }
      },
      {
        Sid       = "MainPlansAndDrift"
        Effect    = "Allow"
        Principal = { Federated = "arn:aws:iam::${var.commercial_account_id}:oidc-provider/${local.oidc_host}" }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_host}:aud" = "sts.amazonaws.com"
            "${local.oidc_host}:sub" = "repo:${var.repository}:ref:refs/heads/main:job_workflow_ref:${var.repository}/${var.workflow}@refs/heads/main"
          }
        }
      },
    ]
  })
  trust_commercial_apply = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ApprovedInstanceApplies"
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${var.commercial_account_id}:oidc-provider/${local.oidc_host}" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = local.apply_subject
        }
      }
    }]
  })

  org_read = [
    "organizations:DescribeAccount",
    "organizations:DescribeCreateAccountStatus",
    "organizations:DescribeHandshake",
    "organizations:DescribeOrganization",
    "organizations:DescribeOrganizationalUnit",
    "organizations:ListAccounts",
    "organizations:ListHandshakesForOrganization",
    "organizations:ListParents",
    "organizations:ListTagsForResource",
  ]

  state_key_condition = { "ForAnyValue:StringEquals" = { "kms:ResourceAliases" = var.state_kms_alias } }

  policy = {
    plan = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        {
          Sid       = "ListInstanceState"
          Effect    = "Allow"
          Action    = "s3:ListBucket"
          Resource  = local.state_bucket_arn
          Condition = { StringLike = { "s3:prefix" = ["${local.state_prefix}*"] } }
        },
        {
          # Plans read the state and never lock it (tofu plan -lock=false).
          Sid      = "ReadInstanceState"
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:GetObjectVersion"]
          Resource = "${local.state_bucket_arn}/${local.state_prefix}*"
        },
        {
          Sid       = "DecryptInstanceState"
          Effect    = "Allow"
          Action    = ["kms:Decrypt", "kms:DescribeKey"]
          Resource  = local.state_key_arns
          Condition = local.state_key_condition
        },
        {
          Sid      = "ReadTheOrganization"
          Effect   = "Allow"
          Action   = local.org_read
          Resource = "*"
        },
        {
          Sid       = "ReadOnlyRoleOfAnInstance"
          Effect    = "Allow"
          Action    = "sts:AssumeRole"
          Resource  = "arn:${local.p}:iam::*:role/${var.instance_plan_role_name}"
          Condition = { "ForAnyValue:StringLike" = { "aws:ResourceOrgPaths" = ["${var.instances_ou_path}*"] } }
        },
        ], [for arn in compact([var.dns_read_role_arn]) : {
          Sid      = "ReadTheParentZone"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = arn
      }])
    })

    apply = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        {
          Sid       = "ListInstanceState"
          Effect    = "Allow"
          Action    = "s3:ListBucket"
          Resource  = local.state_bucket_arn
          Condition = { StringLike = { "s3:prefix" = ["${local.state_prefix}*"] } }
        },
        {
          # The state and its lock files (use_lockfile).
          Sid      = "WriteInstanceState"
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"]
          Resource = "${local.state_bucket_arn}/${local.state_prefix}*"
        },
        {
          Sid       = "EncryptInstanceState"
          Effect    = "Allow"
          Action    = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
          Resource  = local.state_key_arns
          Condition = local.state_key_condition
        },
        {
          Sid      = "ReadTheOrganization"
          Effect   = "Allow"
          Action   = local.org_read
          Resource = "*"
        },
        {
          # A new instance account (created through the commercial account)
          # joins by invitation, then moves under the instances OU.
          Sid      = "InviteAndPlaceInstanceAccounts"
          Effect   = "Allow"
          Action   = ["organizations:InviteAccountToOrganization", "organizations:MoveAccount", "organizations:TagResource", "organizations:UntagResource"]
          Resource = "*"
        },
        {
          Sid       = "InfrastructureRoleOfAnInstance"
          Effect    = "Allow"
          Action    = "sts:AssumeRole"
          Resource  = "arn:${local.p}:iam::*:role/${var.infrastructure_role_name}"
          Condition = { "ForAnyValue:StringLike" = { "aws:ResourceOrgPaths" = ["${var.instances_ou_path}*"] } }
        },
        {
          # Accepting the invitation happens inside the new account, before
          # it belongs to any organization. Only accounts created through
          # the paired commercial account trust this account's principals
          # with that role.
          Sid       = "InfrastructureRoleOfANewAccount"
          Effect    = "Allow"
          Action    = "sts:AssumeRole"
          Resource  = "arn:${local.p}:iam::*:role/${var.infrastructure_role_name}"
          Condition = { Null = { "aws:ResourceOrgID" = "true" } }
        },
        {
          Sid      = "NeverTheManagementOrCoreAccounts"
          Effect   = "Deny"
          Action   = ["sts:AssumeRole", "sts:TagSession"]
          Resource = [for a in local.protected_accounts : "arn:${local.p}:iam::${a}:role/*"]
        },
        {
          Sid      = "NeverMoveOrTagTheManagementOrCoreAccounts"
          Effect   = "Deny"
          Action   = ["organizations:MoveAccount", "organizations:TagResource", "organizations:UntagResource", "organizations:RemoveAccountFromOrganization", "organizations:CloseAccount"]
          Resource = [for a in local.protected_accounts : "arn:${local.p}:organizations::${var.account_id}:account/${var.organization_id}/${a}"]
        },
        {
          # Decommissioning never closes or removes an instance account
          # (its retained stores live in it, docs/operations/decommissioning.md).
          Sid      = "NeverCloseOrRemoveAnAccount"
          Effect   = "Deny"
          Action   = ["organizations:CloseAccount", "organizations:RemoveAccountFromOrganization", "organizations:LeaveOrganization"]
          Resource = "*"
        },
        ], [for arn in compact([var.dns_delegate_role_arn]) : {
          Sid      = "DelegateInTheParentZone"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = arn
      }])
    })

    commercial_plan = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid      = "ReadTheCreatedAccounts"
        Effect   = "Allow"
        Action   = local.org_read
        Resource = "*"
      }]
    })

    commercial_apply = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "ReadTheCreatedAccounts"
          Effect   = "Allow"
          Action   = local.org_read
          Resource = "*"
        },
        {
          # Each GovCloud account is created with its commercial pair, tagged
          # with its instance at creation.
          Sid       = "CreateGovCloudAccounts"
          Effect    = "Allow"
          Action    = ["organizations:CreateGovCloudAccount", "organizations:TagResource"]
          Resource  = "*"
          Condition = { "ForAllValues:StringEquals" = { "aws:TagKeys" = ["fair:instance", "fair:managed-by", "fair:root"] } }
        },
        {
          Sid       = "OrganizationsServiceLinkedRole"
          Effect    = "Allow"
          Action    = "iam:CreateServiceLinkedRole"
          Resource  = "*"
          Condition = { StringEquals = { "iam:AWSServiceName" = "organizations.amazonaws.com" } }
        },
        {
          Sid      = "NeverCloseOrRemoveAnAccount"
          Effect   = "Deny"
          Action   = ["organizations:CloseAccount", "organizations:RemoveAccountFromOrganization", "organizations:LeaveOrganization", "organizations:MoveAccount"]
          Resource = "*"
        },
      ]
    })
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

resource "aws_iam_role" "plan" {
  name                 = var.plan_role_name
  description          = "FAIR instance plans and drift (read-only; infra-instances.yml, F-012 T-14)"
  assume_role_policy   = local.trust_plan
  max_session_duration = 3600
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "plan" {
  name   = "instances-plan"
  role   = aws_iam_role.plan.id
  policy = local.policy.plan
}

resource "aws_iam_role" "apply" {
  name                 = var.apply_role_name
  description          = "FAIR instance applies after approval (infra-instances.yml in its protected environment, F-012 T-14)"
  assume_role_policy   = local.trust_apply
  max_session_duration = 7200
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "apply" {
  name   = "instances-apply"
  role   = aws_iam_role.apply.id
  policy = local.policy.apply
}

# The commercial management account.
resource "aws_iam_openid_connect_provider" "commercial" {
  provider       = aws.commercial
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

resource "aws_iam_role" "commercial_plan" {
  provider             = aws.commercial
  name                 = var.plan_role_name
  description          = "FAIR instance plans and drift: the created accounts (read-only; F-012 T-14)"
  assume_role_policy   = local.trust_commercial_plan
  max_session_duration = 3600
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.commercial]
}

resource "aws_iam_role_policy" "commercial_plan" {
  #checkov:skip=CKV_AWS_355:Organizations reads in the commercial management account: ListAccounts, DescribeOrganization and DescribeCreateAccountStatus take no resource, and the role reads only (it cannot be narrowed to accounts it has not created yet).
  provider = aws.commercial
  name     = "instances-plan"
  role     = aws_iam_role.commercial_plan.id
  policy   = local.policy.commercial_plan
}

resource "aws_iam_role" "commercial_apply" {
  provider             = aws.commercial
  name                 = var.apply_role_name
  description          = "FAIR instance accounts: CreateGovCloudAccount after approval (F-012 T-14)"
  assume_role_policy   = local.trust_commercial_apply
  max_session_duration = 3600
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.commercial]
}

resource "aws_iam_role_policy" "commercial_apply" {
  #checkov:skip=CKV_AWS_355:CreateGovCloudAccount, DescribeCreateAccountStatus and ListAccounts take no resource (IAM's service authorization for Organizations); the account it creates has no ARN before it exists, and the tag keys are limited by aws:TagKeys.
  provider = aws.commercial
  name     = "instances-apply"
  role     = aws_iam_role.commercial_apply.id
  policy   = local.policy.commercial_apply
}

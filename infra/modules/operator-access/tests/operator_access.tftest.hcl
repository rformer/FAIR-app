# F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing access
# to customer data"): the operator permission sets deny every data-plane
# action, allow nothing that reads data, and accessctl's role may only
# assign them, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_ssoadmin_permission_set" {
    defaults = { arn = "arn:aws-us-gov:sso:::permissionSet/ssoins-7907a1b2c3d4e5f6/ps-0a1b2c3d4e5f6071" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::555555555555:role/fair-access-controller" }
  }
}

variables {
  account_id        = "555555555555"
  sso_instance_arn  = "arn:aws-us-gov:sso:::instance/ssoins-7907a1b2c3d4e5f6"
  fleet_repository  = "rformer/FAIR-fleet"
  instances_ou_path = "o-abcdefghij/r-ab12/ou-ab12-cdefghij/"
}

run "two_permission_sets_with_short_sessions" {
  command = plan

  assert {
    condition     = toset([for ps in aws_ssoadmin_permission_set.this : ps.name]) == toset(["FairReadOnly", "FairOperator"])
    error_message = "the permission sets accessctl assigns (access/controller.yaml names them)"
  }
  assert {
    condition     = alltrue([for ps in aws_ssoadmin_permission_set.this : ps.session_duration == "PT1H" && ps.instance_arn == var.sso_instance_arn])
    error_message = "sessions last an hour: a removed assignment's session ends soon after"
  }
  assert {
    condition     = alltrue([for a in aws_ssoadmin_managed_policy_attachment.view_only : a.managed_policy_arn == "arn:aws-us-gov:iam::aws:policy/job-function/ViewOnlyAccess"]) && length(aws_ssoadmin_managed_policy_attachment.view_only) == 2
    error_message = "the one managed policy is ViewOnlyAccess (configuration, never contents; not ReadOnlyAccess, which reads objects)"
  }
}

run "both_permission_sets_deny_the_data_plane" {
  command = plan

  # The actions the design names and the ones that reach the same data.
  assert {
    condition = alltrue([for role in ["read-only", "operator"] : length(setsubtract([
      "s3:GetObject*", "s3:PutObject*", "s3:DeleteObject*", "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
      "kms:Decrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:CreateGrant", "rds-db:connect", "rds-data:*",
      "rds:ModifyDBInstance", "rds:CreateDBSnapshot", "rds:RestoreDBInstance*", "rds:StartExportTask",
      "ssm:StartSession", "ssm:SendCommand", "ec2-instance-connect:*", "ec2:CreateSnapshot*", "ebs:*",
      "eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "eks:CreatePodIdentityAssociation",
      "acm-pca:IssueCertificate", "iam:PassRole", "iam:Create*", "iam:Put*", "iam:Attach*", "sts:AssumeRole*",
    ], flatten([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.this[role].inline_policy).Statement : s.Action if s.Effect == "Deny" && s.Resource == "*" && !can(s.Condition)]))) == 0])
    error_message = "each permission set denies, unconditionally on every resource, object, secret, key, database, node-session, snapshot, cluster-access, certificate and IAM actions"
  }
  assert {
    condition = alltrue([for role in ["read-only", "operator"] : alltrue([
      for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.this[role].inline_policy).Statement :
      length(setintersection(flatten([s.Action]), [
        "s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt", "rds-db:connect", "ssm:StartSession",
        "eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "sts:AssumeRole", "iam:PassRole",
      ])) == 0 && alltrue([for a in flatten([s.Action]) : !strcontains(a, "*")])
    if s.Effect == "Allow"])])
    error_message = "no allow names a data-plane action or a wildcard action"
  }
  assert {
    condition = alltrue([for role in ["read-only", "operator"] : alltrue([
      for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.this[role].inline_policy).Statement :
      alltrue([for r in flatten([s.Resource]) : strcontains(r, ":$${aws:PrincipalAccount}:") && (strcontains(r, ":cluster/fair-") || strcontains(r, ":nodegroup/fair-") || strcontains(r, ":db:fair-") || strcontains(r, ":log-group:/aws/eks/fair-"))])
    if s.Effect == "Allow"])])
    error_message = "allows reach only the instance's own cluster, node group, database and control-plane logs"
  }
  assert {
    condition     = toset(flatten([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.this["read-only"].inline_policy).Statement : s.Action if s.Effect == "Allow"])) == toset(["eks:DescribeCluster", "eks:ListClusters", "eks:AccessKubernetesApi"])
    error_message = "read-only adds only what reaching the cluster needs (its rights there are the EKS view policy)"
  }
  assert {
    condition = length(setsubtract(flatten([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.this["operator"].inline_policy).Statement : s.Action if s.Effect == "Allow"]),
    ["eks:DescribeCluster", "eks:ListClusters", "eks:AccessKubernetesApi", "eks:DescribeNodegroup", "eks:ListNodegroups", "eks:UpdateNodegroupConfig", "rds:RebootDBInstance", "logs:GetLogEvents", "logs:FilterLogEvents"])) == 0
    error_message = "operator adds only operating actions: scale nodes, reboot the database, read control-plane logs"
  }
  assert {
    condition     = output.denied_actions == jsondecode(aws_ssoadmin_permission_set_inline_policy.this["operator"].inline_policy).Statement[length(jsondecode(aws_ssoadmin_permission_set_inline_policy.this["operator"].inline_policy).Statement) - 1].Action
    error_message = "the output lists what is denied"
  }
}

run "the_controller_only_assigns" {
  command = plan

  assert {
    condition = (length(jsondecode(aws_iam_role.controller.assume_role_policy).Statement) == 1
      && jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Principal.Federated == "arn:aws-us-gov:iam::555555555555:oidc-provider/token.actions.githubusercontent.com"
      && jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
      && jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Condition == {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:rformer/FAIR-fleet:environment:access"
        }
    })
    error_message = "only the fleet repository's access environment assumes it, by exact sub (no pattern)"
  }
  assert {
    condition     = aws_iam_role.controller.max_session_duration == 3600
    error_message = "short sessions"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_iam_role_policy.controller.policy).Statement :
      alltrue([for a in flatten([s.Action]) : startswith(a, "sso:") || startswith(a, "iam:") || a == "sts:AssumeRole"])
    if s.Effect == "Allow"])
    error_message = "the controller's allows are Identity Center assignments, their provisioning and the EKS role"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_iam_role_policy.controller.policy).Statement :
      s.Effect == "Deny" && length(setsubtract(["sso:CreatePermissionSet", "sso:PutInlinePolicyToPermissionSet", "sso:AttachManagedPolicyToPermissionSet", "identitystore:Create*"], flatten([s.Action]))) == 0
    ])
    error_message = "the controller can never change a permission set or an identity"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_iam_role_policy.controller.policy).Statement :
    s.Effect == "Deny" && s.Action == "iam:*" && toset(s.NotResource) == toset(["arn:aws-us-gov:iam::*:role/aws-reserved/sso.amazonaws.com/*", "arn:aws-us-gov:iam::*:saml-provider/AWSSSO_*"])])
    error_message = "IAM only on what IAM Identity Center reserves"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_iam_role_policy.controller.policy).Statement :
      s.Action == "sts:AssumeRole" && s.Resource == "arn:aws-us-gov:iam::*:role/fair-access-eks"
    && s.Condition["ForAnyValue:StringLike"]["aws:ResourceOrgPaths"] == ["o-abcdefghij/r-ab12/ou-ab12-cdefghij/*"]])
    error_message = "the controller reaches clusters only through fair-access-eks in the instances OU"
  }
  assert {
    condition     = output.controller_config.eks_role == "fair-access-eks" && output.controller_config.permission_sets["operator"].name == "FairOperator" && output.controller_config.format == "fair.access-controller.v1"
    error_message = "the output is access/controller.yaml's content"
  }
}

run "the_fleet_repository_is_exact" {
  command = plan
  variables {
    fleet_repository = "rformer/*"
  }
  expect_failures = [var.fleet_repository]
}

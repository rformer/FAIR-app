# F-012 T-12 (F-012-AC-08, AC-09, AC-15; design §3.3, §3.5, §6 "E: the release
# key is misused"; ADR-016, ADR-018): the release key and the only principal
# that may sign with it.
#
#   - The key: ECC_NIST_P256, SIGN_VERIFY, in KMS (FIPS 140-validated HSMs),
#     alias alias/fair-release (FAIR_RELEASE_KMS_KEY).
#   - The sign-only role (FAIR_RELEASE_ROLE_ARN): assumed only with a GitHub
#     OIDC token of this repository's release-sign.yml reusable workflow on a
#     v* tag; it may Sign, read the public key and describe the key, on this
#     key only. cosign's KMS client (sigstore pkg/signature/kms/aws) calls
#     DescribeKey before it signs; internal/kmssign uses GetPublicKey and Sign.
#   - The key administrators (the infrastructure role and a key-admin role):
#     manage the key and its policy, never sign; no grants for anyone.
#
# The trust condition is on the token's sub claim alone, which the
# repository's OIDC subject template (infra/github) makes
#   repo:<owner>/<repo>:ref:refs/tags/<tag>:job_workflow_ref:<owner>/<repo>/.github/workflows/release-sign.yml@refs/tags/<tag>
# STS checks sub in every partition; tag names cannot hold ':' (git refname
# rules), so the pattern's wildcards cannot reach into the next segment.
locals {
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = "arn:${var.partition}:iam::${var.account_id}:oidc-provider/${local.oidc_host}"
  signer_role_arn   = "arn:${var.partition}:iam::${var.account_id}:role/${var.signer_role_name}"
  admin_role_arn    = "arn:${var.partition}:iam::${var.account_id}:role/${var.admin_role_name}"

  subject = "repo:${var.repository}:ref:refs/tags/${var.tag_pattern}:job_workflow_ref:${var.repository}/${var.signing_workflow}@refs/tags/${var.tag_pattern}"

  admin_actions = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:EnableKey",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListKeyPolicies",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
  ]

  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = [local.admin_role_arn, var.infrastructure_role_arn] }
        Action    = local.admin_actions
        Resource  = "*"
      },
      {
        Sid       = "ReleaseSigning"
        Effect    = "Allow"
        Principal = { AWS = local.signer_role_arn }
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { StringEquals = { "kms:SigningAlgorithm" = "ECDSA_SHA_256" } }
      },
      {
        Sid       = "ReleaseSignerReadsTheKey"
        Effect    = "Allow"
        Principal = { AWS = local.signer_role_arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey"]
        Resource  = "*"
      },
      {
        # Whatever an identity policy or a future edit says: only the
        # signer signs.
        Sid       = "DenySigningByAnyoneElse"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.signer_role_arn } }
      },
      {
        Sid       = "DenyGrants"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["kms:CreateGrant", "kms:RetireGrant", "kms:RevokeGrant"]
        Resource  = "*"
      },
    ]
  })

  trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ReleaseWorkflowOnAVersionTag"
      Effect    = "Allow"
      Principal = { Federated = local.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "${local.oidc_host}:aud" = "sts.amazonaws.com" }
        StringLike   = { "${local.oidc_host}:sub" = local.subject }
      }
    }]
  })

  admin_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "KeyAdministrators"
      Effect    = "Allow"
      Principal = { AWS = var.key_admin_trusted_arns }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_kms_key" "release" {
  #checkov:skip=CKV_AWS_7:KMS does not rotate asymmetric keys; the release key is rotated by a new key and a release that ships its public key (ADR-018).
  description                        = "FAIR release signing key (ECDSA P-256; F-012 ADR-018)"
  customer_master_key_spec           = "ECC_NIST_P256"
  key_usage                          = "SIGN_VERIFY"
  enable_key_rotation                = false
  deletion_window_in_days            = 30
  multi_region                       = false
  bypass_policy_lockout_safety_check = false
  policy                             = local.key_policy
  tags                               = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "release" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.release.key_id
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

resource "aws_iam_role" "signer" {
  name                 = var.signer_role_name
  description          = "Signs FAIR releases with the release key; only release-sign.yml on a v* tag (F-012 T-12)"
  assume_role_policy   = local.trust_policy
  max_session_duration = 3600
  tags                 = var.tags
  depends_on           = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "signer" {
  name = "release-key-sign-only"
  role = aws_iam_role.signer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SignWithTheReleaseKey"
      Effect   = "Allow"
      Action   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
      Resource = aws_kms_key.release.arn
    }]
  })
}

resource "aws_iam_role" "admin" {
  name                 = var.admin_role_name
  description          = "Administers the FAIR release key; never signs (F-012 T-12)"
  assume_role_policy   = local.admin_trust_policy
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "admin" {
  name = "release-key-administration"
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AdministerTheReleaseKey"
      Effect   = "Allow"
      Action   = local.admin_actions
      Resource = aws_kms_key.release.arn
    }]
  })
}

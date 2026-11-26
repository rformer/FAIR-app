# F-012 T-12 (design §3.3, §6 "E: the release key is misused"): the release
# key, its policy and the sign-only role's trust, with a mock provider.
mock_provider "aws" {}

variables {
  account_id              = "222222222222"
  infrastructure_role_arn = "arn:aws-us-gov:iam::222222222222:role/OrganizationAccountAccessRole"
  key_admin_trusted_arns  = ["arn:aws-us-gov:iam::222222222222:role/fair-operator"]
}

run "an_ecdsa_p256_signing_key" {
  command = plan

  assert {
    condition     = aws_kms_key.release.customer_master_key_spec == "ECC_NIST_P256" && aws_kms_key.release.key_usage == "SIGN_VERIFY"
    error_message = "the release key is ECC_NIST_P256 for SIGN_VERIFY (internal/kmssign refuses anything else)"
  }
  assert {
    condition     = aws_kms_alias.release.name == "alias/fair-release" && output.kms_key == "alias/fair-release"
    error_message = "FAIR_RELEASE_KMS_KEY is alias/fair-release (cosign awskms:///alias/fair-release)"
  }
  assert {
    condition     = !aws_kms_key.release.bypass_policy_lockout_safety_check && !aws_kms_key.release.multi_region && aws_kms_key.release.deletion_window_in_days == 30
    error_message = "no lockout bypass, single region, the longest deletion window"
  }
  assert {
    condition     = output.signer_role_arn == "arn:aws-us-gov:iam::222222222222:role/fair-release-signer"
    error_message = "FAIR_RELEASE_ROLE_ARN is the sign-only role"
  }
}

run "only_the_signer_signs" {
  command = plan

  # Every statement that allows kms:Sign names the signer role and nobody else.
  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
      s.Principal.AWS == "arn:aws-us-gov:iam::222222222222:role/fair-release-signer"
    if s.Effect == "Allow" && contains(flatten([s.Action]), "kms:Sign")])
    error_message = "kms:Sign is allowed to the sign-only role alone"
  }
  assert {
    condition = length([for s in jsondecode(aws_kms_key.release.policy).Statement : s
    if s.Effect == "Allow" && contains(flatten([s.Action]), "kms:Sign")]) == 1
    error_message = "exactly one statement allows signing"
  }
  # No Allow uses a wildcard principal or a wildcard action.
  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
      !contains(flatten([s.Principal.AWS]), "*") && alltrue([for a in flatten([s.Action]) : !strcontains(a, "*")])
    if s.Effect == "Allow"])
    error_message = "no Allow for '*' principals and no wildcard actions (no kms:*)"
  }
  # The administrators manage the key and never sign, verify or use grants.
  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
      length(setintersection(flatten([s.Action]), ["kms:Sign", "kms:Verify", "kms:CreateGrant", "kms:GetPublicKey"])) == 0
      && toset(s.Principal.AWS) == toset(["arn:aws-us-gov:iam::222222222222:role/fair-release-key-admin", var.infrastructure_role_arn])
    if s.Sid == "KeyAdministration"])
    error_message = "the administrators (key-admin role, infrastructure role) never sign"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
      s.Effect == "Deny" && s.Action == "kms:Sign" && s.Principal.AWS == "*"
    && s.Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws-us-gov:iam::222222222222:role/fair-release-signer"])
    error_message = "signing by any other principal is denied explicitly"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
    s.Effect == "Deny" && contains(s.Action, "kms:CreateGrant") && s.Principal.AWS == "*" && !can(s.Condition)])
    error_message = "no grants: nothing can lend signing to anyone"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
    s.Sid == "ReleaseSigning" && s.Condition.StringEquals["kms:SigningAlgorithm"] == "ECDSA_SHA_256"])
    error_message = "the signer signs ECDSA_SHA_256 only"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_kms_key.release.policy).Statement :
      toset(flatten([s.Action])) == toset(["kms:DescribeKey", "kms:GetPublicKey"])
    if s.Effect == "Allow" && s.Sid != "KeyAdministration" && s.Sid != "ReleaseSigning"])
    error_message = "the only other allowance is reading the key (the signer's)"
  }
}

run "the_signer_role_trusts_only_the_release_workflow_on_a_tag" {
  command = plan

  assert {
    condition     = length(jsondecode(aws_iam_role.signer.assume_role_policy).Statement) == 1
    error_message = "one trust statement"
  }
  assert {
    condition     = jsondecode(aws_iam_role.signer.assume_role_policy).Statement[0].Principal.Federated == "arn:aws-us-gov:iam::222222222222:oidc-provider/token.actions.githubusercontent.com"
    error_message = "trusted principal: GitHub's OIDC provider, nothing else"
  }
  assert {
    condition     = jsondecode(aws_iam_role.signer.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
    error_message = "web identity only"
  }
  assert {
    condition     = jsondecode(aws_iam_role.signer.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "audience sts.amazonaws.com (what release-sign.yml requests)"
  }
  assert {
    condition     = jsondecode(aws_iam_role.signer.assume_role_policy).Statement[0].Condition.StringLike["token.actions.githubusercontent.com:sub"] == "repo:rformer/FAIR-app:ref:refs/tags/v*:job_workflow_ref:rformer/FAIR-app/.github/workflows/release-sign.yml@refs/tags/v*"
    error_message = "sub: this repository, a v* tag, and the release-sign.yml reusable workflow at a v* tag"
  }
  assert {
    condition     = keys(jsondecode(aws_iam_role.signer.assume_role_policy).Statement[0].Condition) == ["StringEquals", "StringLike"]
    error_message = "no other (weaker) operator in the trust conditions"
  }
  assert {
    condition     = aws_iam_openid_connect_provider.github.url == "https://token.actions.githubusercontent.com" && aws_iam_openid_connect_provider.github.client_id_list == toset(["sts.amazonaws.com"])
    error_message = "the OIDC provider is GitHub Actions' with the STS audience"
  }
  assert {
    condition     = aws_iam_role.signer.max_session_duration == 3600
    error_message = "short sessions"
  }
}

run "the_signer_role_may_only_sign_with_this_key" {
  command = plan

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.signer.policy).Statement) == 1
    error_message = "one statement"
  }
  assert {
    condition     = toset(jsondecode(aws_iam_role_policy.signer.policy).Statement[0].Action) == toset(["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"])
    error_message = "Sign, GetPublicKey and DescribeKey (cosign reads the key's metadata) only"
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.signer.policy).Statement[0].Resource == aws_kms_key.release.arn
    error_message = "on the release key only"
  }
}

run "admin_role_policy_never_signs" {
  command = plan

  assert {
    condition     = length(setintersection(jsondecode(aws_iam_role_policy.admin.policy).Statement[0].Action, ["kms:Sign", "kms:Verify", "kms:CreateGrant"])) == 0
    error_message = "the key admin role cannot sign"
  }
  assert {
    condition     = jsondecode(aws_iam_role.admin.assume_role_policy).Statement[0].Principal.AWS == var.key_admin_trusted_arns
    error_message = "the key admin role is assumed by the named principals only"
  }
}

run "wildcard_repository_refused" {
  command = plan
  variables {
    repository = "rformer/*"
  }
  expect_failures = [var.repository]
}

run "wildcard_admins_refused" {
  command = plan
  variables {
    key_admin_trusted_arns = ["arn:aws-us-gov:iam::222222222222:role/*"]
  }
  expect_failures = [var.key_admin_trusted_arns]
}

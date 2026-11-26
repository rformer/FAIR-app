# Secrets Manager entries (design §3.5; F-001 T-41, docs/install/keys.md):
#   - fair/<instance>/<service>/<dir>: one per store entry of the key
#     layout (internal/keys Mounts; deploy/k8s/keys/saas/external-secrets.yaml
#     reads exactly these), a JSON object with one field per file;
#   - fair/<instance>/database/<role>: the password of each database login
#     role (scripts/db-bootstrap.sh's FAIR_*_PASSWORD_FILE).
# The module creates the entries only, never a value: onboarding (T-14)
# loads them from `iam keys init` and generated passwords, through files.
# Each entry is encrypted under the secrets key; its resource policy lets
# only the External Secrets role read its value (and, for the key files,
# var.secret_reader_role_arns: the pipeline's rotation role), and nobody
# outside the instance's account do anything with it.
locals {
  key_layout = [
    "gateway/jwt", "gateway/login-ticket", "gateway/secrets",
    "iam/jwt", "iam/login-ticket", "iam/secrets",
    "posture/jwt",
    "audit/jwt", "audit/checkpoint",
    "risk/jwt", "risk/engine-client", "risk/secrets",
    "engine-gate/tls",
    "notify/jwt", "notify/webhook-secrets",
    "integrate/jwt", "integrate/secrets",
  ]
  database_roles = ["app_migrator", "app_rw", "app_engine", "app_posture", "app_gateway", "app_audit", "app_notify", "app_integrate"]

  secret_entries = merge(
    { for e in local.key_layout : e => "Key files ${e} (F-001 T-41 layout)" },
    { for r in local.database_roles : "database/${r}" => "Password of the database role ${r}" },
  )
}

resource "aws_secretsmanager_secret" "this" {
  #checkov:skip=CKV2_AWS_57:Not rotated by a Lambda: the entries are key files rotated by `iam keys rotate` (docs/install/keys.md: rotation adds a key and the old one keeps verifying) and database passwords changed with the role (T-14 runbook); a generic rotation function would break the key sets' pairing.
  for_each                = local.secret_entries
  name                    = "fair/${var.instance}/${each.key}"
  description             = "FAIR ${var.instance}: ${each.value}"
  kms_key_id              = aws_kms_key.home["secrets"].arn
  recovery_window_in_days = 30
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_policy" "this" {
  for_each   = local.secret_entries
  secret_arn = aws_secretsmanager_secret.this[each.key].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyOutsideTheInstance"
        Effect    = "Deny"
        Principal = "*"
        Action    = "secretsmanager:*"
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:PrincipalAccount" = local.acct } }
      },
      {
        Sid       = "OnlyExternalSecretsReads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "secretsmanager:GetSecretValue"
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = startswith(each.key, "database/") ? [local.role_arn["external-secrets"]] : concat([local.role_arn["external-secrets"]], var.secret_reader_role_arns) } }
      },
    ]
  })
}

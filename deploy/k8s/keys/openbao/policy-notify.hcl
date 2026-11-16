# F-009 T-03: the notify service reads its own keys and nothing else.
path "secret/data/fair/notify/jwt" {
  capabilities = ["read"]
}
# The AES keys its webhook secrets are kept under (F-009 design §1).
path "secret/data/fair/notify/webhook-secrets" {
  capabilities = ["read"]
}

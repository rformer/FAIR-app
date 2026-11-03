# F-001 T-41: the iam reads its own keys and nothing else.
path "secret/data/fair/iam/jwt" {
  capabilities = ["read"]
}
path "secret/data/fair/iam/login-ticket" {
  capabilities = ["read"]
}
path "secret/data/fair/iam/secrets" {
  capabilities = ["read"]
}

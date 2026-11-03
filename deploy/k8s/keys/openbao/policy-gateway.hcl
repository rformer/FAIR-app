# F-001 T-41: the gateway reads its own keys and nothing else.
path "secret/data/fair/gateway/jwt" {
  capabilities = ["read"]
}
path "secret/data/fair/gateway/login-ticket" {
  capabilities = ["read"]
}
path "secret/data/fair/gateway/secrets" {
  capabilities = ["read"]
}

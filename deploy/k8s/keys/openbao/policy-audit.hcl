# F-002 T-05: the audit service reads its own keys and nothing else.
path "secret/data/fair/audit/jwt" {
  capabilities = ["read"]
}
path "secret/data/fair/audit/checkpoint" {
  capabilities = ["read"]
}

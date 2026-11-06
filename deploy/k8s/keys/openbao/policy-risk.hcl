# F-003 T-04: the risk service reads its own keys and nothing else.
path "secret/data/fair/risk/jwt" {
  capabilities = ["read"]
}

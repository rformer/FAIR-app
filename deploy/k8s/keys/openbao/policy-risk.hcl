# F-003 T-04: the risk service reads its own keys and nothing else.
path "secret/data/fair/risk/jwt" {
  capabilities = ["read"]
}
# F-005 T-10: the engine client's certificate, key and gate pins.
path "secret/data/fair/risk/engine-client" {
  capabilities = ["read"]
}

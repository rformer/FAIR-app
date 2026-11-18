# F-011 T-15: the integrate service reads its own keys and nothing else.
path "secret/data/fair/integrate/jwt" {
  capabilities = ["read"]
}
# The AES keys its connector credentials are kept under (F-011 design §3.1).
path "secret/data/fair/integrate/secrets" {
  capabilities = ["read"]
}

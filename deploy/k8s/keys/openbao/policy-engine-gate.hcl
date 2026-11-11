# F-005 T-10: engine-gate reads its own TLS keys and nothing else.
path "secret/data/fair/engine-gate/tls" {
  capabilities = ["read"]
}

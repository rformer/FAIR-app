# F-014 T-08 (design §3.3, D-OQ9): the bundled OpenBao's configuration
# (ConfigMap openbao-config, mounted at /openbao/config). Raft storage on each
# server's encrypted volume; TLS 1.2 or later on the API and between servers
# (Secret openbao-tls: installation CA; SANs openbao.openbao.svc and
# *.openbao-internal.openbao.svc). No UI (not built), no PGP-wrapped unseal
# keys or root tokens, and fairctl enables only KV v2 and the auth methods
# the platform needs: the SSH engine, Transit's chacha20-poly1305 and ed448
# keys and PKCS#12 import run outside the Go FIPS module
# (deploy/bundled/sources.json). Unseal: Shamir shares written by fairctl to
# the custodian paths the install decisions name (D-OQ9); an auto-unseal
# seal for a customer KMS is added with fairctl's provisioning.
ui           = false
cluster_name = "fair"

listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"
  tls_cert_file   = "/openbao/tls/tls.crt"
  tls_key_file    = "/openbao/tls/tls.key"
  tls_min_version = "tls12"
  telemetry {
    unauthenticated_metrics_access = false
  }
}

storage "raft" {
  path = "/openbao/data"
  retry_join {
    leader_api_addr     = "https://openbao-0.openbao-internal.openbao.svc:8200"
    leader_ca_cert_file = "/openbao/tls/ca.crt"
  }
  retry_join {
    leader_api_addr     = "https://openbao-1.openbao-internal.openbao.svc:8200"
    leader_ca_cert_file = "/openbao/tls/ca.crt"
  }
  retry_join {
    leader_api_addr     = "https://openbao-2.openbao-internal.openbao.svc:8200"
    leader_ca_cert_file = "/openbao/tls/ca.crt"
  }
}

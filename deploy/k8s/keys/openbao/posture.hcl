# F-001 T-41: OpenBao Agent for the posture (self-hosted). Kubernetes auth with
# a projected service-account token for OpenBao's audience; renders the keys
# into the pod's in-memory /keys and refreshes them every minute.
vault {
  address = "https://openbao.openbao.svc:8200"
  ca_cert = "/etc/openbao/ca/ca.crt"
}
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role       = "fair-posture"
      token_path = "/var/run/secrets/openbao/token"
    }
  }
}
template_config {
  static_secret_render_interval = "1m"
  exit_on_retry_failure         = true
}
template {
  source      = "/etc/openbao/posture.ctmpl"
  destination = "/keys/.rendered"
  perms       = "0640"
}

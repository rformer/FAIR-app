package posture

import (
	"strings"
	"testing"
)

// T-37: the per-mode requirements (signing keys and outbound integrations).
func TestCheckInstall(t *testing.T) {
	key := "k1"
	full := map[string]string{"FAIR_EXPORT_SIGNING_KEY_FILE": "/s/export.key", "FAIR_JWT_KEYS_DIR": "/s/jwt"}
	with := func(extra map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return full[k]
		}
	}
	saas := map[string]string{"FAIR_SECOPS_WEBHOOK_URL": "https://secops", "FAIR_SECOPS_SECRET_FILE": "/s/secops", "FAIR_SCANNER_GRPC_ADDR": ":9443"}
	for _, c := range []struct {
		name string
		in   InstallCheck
		want []string // substrings of the errors; none means valid
	}{
		{"self-hosted complete", InstallCheck{"production", "self-hosted", with(nil), &key}, nil},
		{"air-gapped complete", InstallCheck{"production", "air-gapped", with(nil), &key}, nil},
		{"saas complete", InstallCheck{"production", "saas", with(saas), &key}, nil},
		{"no MAC key", InstallCheck{"production", "self-hosted", with(nil), nil}, []string{"no active posture MAC key"}},
		{"no export key", InstallCheck{"production", "air-gapped", with(map[string]string{"FAIR_EXPORT_SIGNING_KEY_FILE": ""}), &key},
			[]string{"FAIR_EXPORT_SIGNING_KEY_FILE is required"}},
		{"saas without SecOps or scanner", InstallCheck{"production", "saas", with(nil), &key},
			[]string{"FAIR_SECOPS_WEBHOOK_URL is required", "FAIR_SECOPS_SECRET_FILE is required", "FAIR_SCANNER_GRPC_ADDR is required"}},
		{"air-gapped with a webhook", InstallCheck{"production", "air-gapped", with(map[string]string{"FAIR_SECOPS_WEBHOOK_URL": "https://x"}), &key},
			[]string{"no outbound connections"}},
		{"air-gapped webhook refused in development too", InstallCheck{"development", "air-gapped", with(map[string]string{"FAIR_SECOPS_SECRET_FILE": "/s"}), nil},
			[]string{"no outbound connections"}},
		{"development needs no keys", InstallCheck{"development", "self-hosted", func(string) string { return "" }, nil}, nil},
	} {
		err := CheckInstall(c.in)
		if len(c.want) == 0 {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		for _, w := range c.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %v, want %q", c.name, err, w)
			}
		}
	}
}

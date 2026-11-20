package notify

import (
	"strings"
	"testing"
)

func TestCheckInstall(t *testing.T) {
	full := map[string]string{"FAIR_JWT_KEYS_DIR": "/keys/jwt", "FAIR_NOTIFY_SECRETS_DIR": "/keys/webhook-secrets", // #nosec G101 -- a test value, not a credential
		"FAIR_NOTIFY_BASE_URL": "https://fair.example.com", "FAIR_NOTIFY_CLUSTER_CIDRS": "10.96.0.0/12, 10.244.0.0/16"}
	env := func(m map[string]string, drop string, set map[string]string) func(string) string {
		return func(k string) string {
			if k == drop {
				return ""
			}
			if v, ok := set[k]; ok {
				return v
			}
			return m[k]
		}
	}
	for _, mode := range []string{"saas", "self-hosted", "air-gapped"} {
		if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: env(full, "", nil)}); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
		for k := range full {
			if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: env(full, k, nil)}); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s without %s: %v", mode, k, err)
			}
		}
	}
	if err := CheckInstall(InstallCheck{Env: "development", Getenv: func(string) string { return "" }}); err != nil {
		t.Errorf("development: %v", err)
	}
	for _, bad := range []string{"http://fair.example.com", "https://fair.example.com/app", "https://u:p@fair.example.com", "https://fair.example.com?x=1", "fair.example.com", "https://"} {
		if err := CheckInstall(InstallCheck{Env: "development", Getenv: env(nil, "", map[string]string{"FAIR_NOTIFY_BASE_URL": bad})}); err == nil {
			t.Errorf("base URL %q accepted", bad)
		}
	}
	if u, err := BaseURL("https://fair.example.com:8443/"); err != nil || u.String() != "https://fair.example.com:8443" {
		t.Errorf("BaseURL: %v %v", u, err)
	}
	for _, bad := range []string{"10.0.0.0", "10.0.0.0/33", ",", "x/8"} {
		if err := CheckInstall(InstallCheck{Env: "development", Getenv: env(nil, "", map[string]string{"FAIR_NOTIFY_CLUSTER_CIDRS": bad})}); err == nil {
			t.Errorf("cluster ranges %q accepted", bad)
		}
	}
	if p, err := ParsePrefixes("10.96.1.7/12,fd00::/8"); err != nil || len(p) != 2 || p[0].String() != "10.96.0.0/12" {
		t.Errorf("ParsePrefixes: %v %v", p, err)
	}
}

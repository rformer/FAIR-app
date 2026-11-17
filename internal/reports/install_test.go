package reports

import (
	"context"
	"strings"
	"testing"
)

func TestCheckInstall(t *testing.T) {
	full := map[string]string{StorePrefix + "_BUCKET": "fair-reports", StorePrefix + "_ENDPOINT": "s3.example.com:443",
		StorePrefix + "_ACCESS_KEY_FILE": "/secrets/report-store/access-key", StorePrefix + "_SECRET_KEY_FILE": "/secrets/report-store/secret-key",
		"FAIR_REPORT_CONTEXT_KEY_FILE": "/keys/secrets/report-context.key", "FAIR_REPORT_CONTEXT_KEY_ID_FILE": "/keys/secrets/report-context.id"}
	for _, mode := range []string{"saas", "self-hosted", "air-gapped"} {
		get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
		if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: get(full)}); err != nil {
			t.Errorf("%s: a complete install refused: %v", mode, err)
		}
		for k := range full {
			partial := map[string]string{}
			for kk, v := range full {
				if kk != k {
					partial[kk] = v
				}
			}
			if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: get(partial)}); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s without %s: %v", mode, k, err)
			}
		}
		if err := CheckInstall(InstallCheck{Env: "development", Mode: mode, Getenv: get(map[string]string{})}); err != nil {
			t.Errorf("%s in development: %v", mode, err)
		}
	}
}

func TestOpenStoreRefusesBadConfig(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no bucket":   {StorePrefix + "_ENDPOINT": "s3.example.com:443"},
		"a scheme":    {StorePrefix + "_ENDPOINT": "https://s3.example.com", StorePrefix + "_BUCKET": "b"},
		"plaintext":   {StorePrefix + "_ENDPOINT": "s3.example.com:443", StorePrefix + "_BUCKET": "b", StorePrefix + "_PLAINTEXT": "true"},
		"credentials": {StorePrefix + "_ENDPOINT": "s3.example.com:443", StorePrefix + "_BUCKET": "b"},
	} {
		if _, err := OpenStore(context.Background(), "production", func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

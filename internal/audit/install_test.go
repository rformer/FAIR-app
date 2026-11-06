package audit

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/config"
)

// F-002 T-05, T-15 (design §7): what each environment and mode needs at
// startup.
func TestCheckInstall(t *testing.T) {
	full := map[string]string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR": "/keys/checkpoint", "FAIR_JWT_KEYS_DIR": "/keys/jwt", "FAIR_AUDIT_WORM_BUCKET": "s3://worm",
		"FAIR_AUDIT_STORE_BUCKET": "fair-audit", "FAIR_AUDIT_STORAGE_QUOTA": "200GiB"}
	check := func(env, mode string, drop ...string) error {
		v := map[string]string{}
		for k, x := range full {
			v[k] = x
		}
		for _, k := range drop {
			delete(v, k)
		}
		return CheckInstall(InstallCheck{Env: env, Mode: mode, Getenv: func(k string) string { return v[k] }})
	}
	for _, mode := range []string{config.ModeSaaS, config.ModeSelfHosted, config.ModeAirGapped} {
		if err := check("production", mode); err != nil {
			t.Errorf("%s complete: %v", mode, err)
		}
		for _, k := range []string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR", "FAIR_JWT_KEYS_DIR", "FAIR_AUDIT_STORE_BUCKET", "FAIR_AUDIT_STORAGE_QUOTA"} {
			if err := check("production", mode, k); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s without %s: %v", mode, k, err)
			}
		}
		if err := check("development", mode, "FAIR_AUDIT_CHECKPOINT_KEYS_DIR", "FAIR_JWT_KEYS_DIR", "FAIR_AUDIT_WORM_BUCKET", "FAIR_AUDIT_STORE_BUCKET", "FAIR_AUDIT_STORAGE_QUOTA"); err != nil {
			t.Errorf("%s in development: %v", mode, err)
		}
	}
	if err := check("production", config.ModeSaaS, "FAIR_AUDIT_WORM_BUCKET"); err == nil || !strings.Contains(err.Error(), "write-once") {
		t.Errorf("SaaS without WORM: %v", err)
	}
	for _, mode := range []string{config.ModeSelfHosted, config.ModeAirGapped} {
		if err := check("production", mode, "FAIR_AUDIT_WORM_BUCKET"); err != nil {
			t.Errorf("%s without WORM: %v", mode, err)
		}
	}
}

// F-002 T-20: the quota's sizes, and a bad quota refused anywhere.
func TestParseSizeAndQuota(t *testing.T) {
	for in, want := range map[string]int64{"1": 1, "512B": 512, "2KiB": 2048, "3 MiB": 3 << 20, "200GiB": 200 << 30, "1TiB": 1 << 40,
		"5KB": 5000, "7MB": 7e6, "2GB": 2e9, "1TB": 1e12} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "-1GiB", "1.5GiB", "ten", "1PB", "9999999TiB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
	err := CheckInstall(InstallCheck{Env: "development", Mode: config.ModeSelfHosted, Getenv: func(k string) string {
		if k == "FAIR_AUDIT_STORAGE_QUOTA" {
			return "lots"
		}
		return ""
	}})
	if err == nil || !strings.Contains(err.Error(), "FAIR_AUDIT_STORAGE_QUOTA") {
		t.Fatalf("a bad quota in development: %v", err)
	}
}

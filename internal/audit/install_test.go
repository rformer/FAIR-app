package audit

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/config"
)

// F-002 T-05 (design §7): what each environment and mode needs at startup.
func TestCheckInstall(t *testing.T) {
	full := map[string]string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR": "/keys/checkpoint", "FAIR_JWT_KEYS_DIR": "/keys/jwt", "FAIR_AUDIT_WORM_BUCKET": "s3://worm"}
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
		for _, k := range []string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR", "FAIR_JWT_KEYS_DIR"} {
			if err := check("production", mode, k); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s without %s: %v", mode, k, err)
			}
		}
		if err := check("development", mode, "FAIR_AUDIT_CHECKPOINT_KEYS_DIR", "FAIR_JWT_KEYS_DIR", "FAIR_AUDIT_WORM_BUCKET"); err != nil {
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

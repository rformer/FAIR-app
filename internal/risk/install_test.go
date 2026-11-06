package risk

import (
	"testing"

	"github.com/rformer/fair-app/internal/config"
)

func TestCheckInstall(t *testing.T) {
	for _, mode := range []string{config.ModeSaaS, config.ModeSelfHosted, config.ModeAirGapped} {
		env := map[string]string{}
		get := func(k string) string { return env[k] }
		if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: get}); err == nil {
			t.Errorf("%s: production without FAIR_JWT_KEYS_DIR", mode)
		}
		if err := CheckInstall(InstallCheck{Env: "development", Mode: mode, Getenv: get}); err != nil {
			t.Errorf("%s: development: %v", mode, err)
		}
		env["FAIR_JWT_KEYS_DIR"] = "/keys/jwt"
		if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: get}); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
	}
}

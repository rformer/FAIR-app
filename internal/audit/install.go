package audit

import (
	"errors"
	"fmt"

	"github.com/rformer/fair-app/internal/config"
)

// InstallCheck is what the audit service checks at startup (design §7; the
// mode matrix, TestDeploymentModeMatrix).
type InstallCheck struct {
	Env    string // FAIR_ENV
	Mode   string // FAIR_DEPLOYMENT_MODE
	Getenv func(string) string
}

// CheckInstall refuses an install that lacks what its environment and
// deployment mode need:
//   - production: the checkpoint signing key (FAIR_AUDIT_CHECKPOINT_KEYS_DIR,
//     design §6.3), the gateway's internal-JWT public keys
//     (FAIR_JWT_KEYS_DIR, for the audit API) and the audit store
//     (FAIR_AUDIT_STORE_BUCKET: export bundles, T-15; archives, T-18), in
//     every mode (design §7);
//   - SaaS in production: write-once storage for the checkpoint copies
//     (FAIR_AUDIT_WORM_BUCKET, F-002-AC-10, design OQ3).
func CheckInstall(c InstallCheck) error {
	var errs []error
	set := func(k string) bool { return c.Getenv(k) != "" }
	if c.Env == "production" {
		for _, k := range []string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR", "FAIR_JWT_KEYS_DIR", "FAIR_AUDIT_STORE_BUCKET"} {
			if !set(k) {
				errs = append(errs, fmt.Errorf("%s is required in production", k))
			}
		}
	}
	if c.Env == "production" && c.Mode == config.ModeSaaS && !set("FAIR_AUDIT_WORM_BUCKET") {
		errs = append(errs, errors.New("FAIR_AUDIT_WORM_BUCKET is required in SaaS mode: checkpoints are copied to write-once storage (F-002 AC-10)"))
	}
	return errors.Join(errs...)
}

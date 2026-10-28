package posture

import (
	"errors"
	"fmt"

	"github.com/rformer/fair-app/internal/config"
)

// Per-mode installation requirements (F-015 T-37; design §11). The posture
// service checks them at startup and refuses to run without them:
//
//	                       saas   self-hosted   air-gapped
//	posture MAC key          ✓         ✓             ✓      in the database (row MACs)
//	export signing key       ✓         ✓             ✓      FAIR_EXPORT_SIGNING_KEY_FILE
//	gateway JWT keys         ✓         ✓             ✓      FAIR_JWT_KEYS_DIR
//	SecOps webhook + secret  ✓         -             ✗      FAIR_SECOPS_WEBHOOK_URL, FAIR_SECOPS_SECRET_FILE
//	scanner channel          ✓         optional      optional (AC-38, AC-39)
//
// (✓ required, ✗ refused: an air-gapped install makes no outbound
// connections.) The release public key that verifies profile packages is
// bundled and given to `posture import -pub`, in every mode; key custody
// (KMS or Vault) is D-OQ5.

// InstallCheck is what CheckInstall inspects.
type InstallCheck struct {
	Env, Mode    string
	Getenv       func(string) string
	ActiveMACKey *string // posture.mac_key_active()
}

// CheckInstall returns every unmet requirement of the mode, joined. Outside
// production only the mode's refusals apply.
func CheckInstall(c InstallCheck) error {
	var errs []error
	prod := c.Env == "production"
	set := func(k string) bool { return c.Getenv(k) != "" }
	if prod {
		if c.ActiveMACKey == nil {
			errs = append(errs, errors.New("no active posture MAC key: install one with posture.add_mac_key (row MACs, design §5)"))
		}
		for _, k := range []string{"FAIR_EXPORT_SIGNING_KEY_FILE", "FAIR_JWT_KEYS_DIR"} {
			if !set(k) {
				errs = append(errs, fmt.Errorf("%s is required in production", k))
			}
		}
	}
	switch c.Mode {
	case config.ModeSaaS:
		if prod {
			for _, k := range []string{"FAIR_SECOPS_WEBHOOK_URL", "FAIR_SECOPS_SECRET_FILE", "FAIR_SCANNER_GRPC_ADDR"} {
				if !set(k) {
					errs = append(errs, fmt.Errorf("%s is required in SaaS mode", k))
				}
			}
		}
	case config.ModeAirGapped:
		for _, k := range []string{"FAIR_SECOPS_WEBHOOK_URL", "FAIR_SECOPS_SECRET_FILE"} {
			if set(k) {
				errs = append(errs, fmt.Errorf("%s is set, but an air-gapped install makes no outbound connections", k))
			}
		}
	}
	return errors.Join(errs...)
}

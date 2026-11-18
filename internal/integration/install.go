package integration

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/rformer/fair-app/internal/notify"
)

// F-011 T-15 (design §1, §2, §11): what the integrate service checks at
// startup.

// LeaderLockKey is the advisory lock of the integrate service's leader,
// which claims due connector runs (design §3.3).
const LeaderLockKey int64 = 0x0FA1_0011_0000_0001

// InstallCheck is what the integrate service checks at startup (the mode
// matrix, TestDeploymentModeMatrix).
type InstallCheck struct {
	Env    string // FAIR_ENV
	Mode   string // FAIR_DEPLOYMENT_MODE
	Getenv func(string) string
}

// CheckInstall refuses an install that lacks what its environment needs:
//   - production, every mode: the gateway's internal-JWT public keys
//     (FAIR_JWT_KEYS_DIR, for the integrations API), the
//     connector-credentials keys (FAIR_INTEGRATE_SECRETS_DIR), the gateway's
//     URL connectors submit their batches to (FAIR_INTEGRATE_GATEWAY_URL)
//     and the cluster's address ranges, which no connector ever fetches
//     from (FAIR_INTEGRATE_CLUSTER_CIDRS, design §3.3);
//   - anywhere: a gateway URL that is set is https, absolute, without a
//     path beyond "/", a query or credentials; cluster ranges that are set
//     are CIDR prefixes.
func CheckInstall(c InstallCheck) error {
	var errs []error
	if c.Env == "production" {
		for _, k := range []string{"FAIR_JWT_KEYS_DIR", "FAIR_INTEGRATE_SECRETS_DIR", "FAIR_INTEGRATE_GATEWAY_URL", "FAIR_INTEGRATE_CLUSTER_CIDRS"} {
			if c.Getenv(k) == "" {
				errs = append(errs, fmt.Errorf("%s is required in production", k))
			}
		}
	}
	if s := c.Getenv("FAIR_INTEGRATE_GATEWAY_URL"); s != "" {
		if _, err := GatewayURL(s); err != nil {
			errs = append(errs, err)
		}
	}
	if s := c.Getenv("FAIR_INTEGRATE_CLUSTER_CIDRS"); s != "" {
		if _, err := notify.ParsePrefixes(s); err != nil {
			errs = append(errs, fmt.Errorf("FAIR_INTEGRATE_CLUSTER_CIDRS: %w", err))
		}
	}
	return errors.Join(errs...)
}

// GatewayURL parses the gateway's URL connectors submit to: https,
// absolute, no credentials, query, fragment or path beyond "/".
func GatewayURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("FAIR_INTEGRATE_GATEWAY_URL %q must be https://host[:port] with nothing after it", s)
	}
	u.Path = ""
	return u, nil
}

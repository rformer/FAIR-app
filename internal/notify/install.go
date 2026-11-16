package notify

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// F-009 T-03 (design §2, §11): what the notify service checks at startup.

// LeaderLockKey is the advisory lock of the notify service's leader, which
// collects, fans out, sends digests and keeps retention (design §1).
const LeaderLockKey int64 = 0x0FA1_0009_0000_0001

// InstallCheck is what the notify service checks at startup (the mode
// matrix, TestDeploymentModeMatrix).
type InstallCheck struct {
	Env    string // FAIR_ENV
	Mode   string // FAIR_DEPLOYMENT_MODE
	Getenv func(string) string
}

// CheckInstall refuses an install that lacks what its environment needs:
//   - production, every mode: the gateway's internal-JWT public keys
//     (FAIR_JWT_KEYS_DIR, for the notifications API), the webhook-secrets
//     keys (FAIR_NOTIFY_SECRETS_DIR), the platform's base URL for links
//     (FAIR_NOTIFY_BASE_URL) and the cluster's address ranges, which no
//     notice is ever sent to (FAIR_NOTIFY_CLUSTER_CIDRS, design §3.4);
//   - anywhere: a base URL that is set is https, absolute, without a path
//     beyond "/", a query or credentials; cluster ranges that are set are
//     CIDR prefixes.
func CheckInstall(c InstallCheck) error {
	var errs []error
	if c.Env == "production" {
		for _, k := range []string{"FAIR_JWT_KEYS_DIR", "FAIR_NOTIFY_SECRETS_DIR", "FAIR_NOTIFY_BASE_URL", "FAIR_NOTIFY_CLUSTER_CIDRS"} {
			if c.Getenv(k) == "" {
				errs = append(errs, fmt.Errorf("%s is required in production", k))
			}
		}
	}
	if s := c.Getenv("FAIR_NOTIFY_BASE_URL"); s != "" {
		if _, err := BaseURL(s); err != nil {
			errs = append(errs, err)
		}
	}
	if s := c.Getenv("FAIR_NOTIFY_CLUSTER_CIDRS"); s != "" {
		if _, err := ParsePrefixes(s); err != nil {
			errs = append(errs, fmt.Errorf("FAIR_NOTIFY_CLUSTER_CIDRS: %w", err))
		}
	}
	return errors.Join(errs...)
}

// BaseURL parses the platform's base URL, which every link in a notice is
// built from (design §3.3): https, absolute, no credentials, query,
// fragment or path beyond "/".
func BaseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("FAIR_NOTIFY_BASE_URL %q must be https://host[:port] with nothing after it", s)
	}
	u.Path = ""
	return u, nil
}

// ParsePrefixes parses a comma-separated list of CIDR prefixes.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pfx.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("no prefixes")
	}
	return out, nil
}

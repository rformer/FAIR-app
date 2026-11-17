// Package reports is F-010's reporting in the risk service: the report
// store, runs and their worker, the readers, the dashboard and trends,
// schedules and snapshots (design §1, §3).
package reports

import (
	"context"
	"errors"
	"fmt"

	"github.com/rformer/fair-app/internal/objstore"
)

// StorePrefix is the environment prefix of the report store
// (FAIR_REPORT_STORE_ENDPOINT, _BUCKET, _REGION, _ACCESS_KEY_FILE,
// _SECRET_KEY_FILE, _CA_FILE; objstore.FromEnv).
const StorePrefix = "FAIR_REPORT_STORE"

// InstallCheck is what the risk service checks for reports at startup
// (design §11; the mode matrix, TestDeploymentModeMatrix).
type InstallCheck struct {
	Env    string // FAIR_ENV
	Mode   string // FAIR_DEPLOYMENT_MODE
	Getenv func(string) string
}

// CheckInstall refuses, in production in every mode, an install without the
// report store (a versioned bucket and its credentials files) or the
// delegated report context key (design §3.3): reports are produced
// identically in SaaS, self-hosted and air-gapped installations.
func CheckInstall(c InstallCheck) error {
	if c.Env != "production" {
		return nil
	}
	var errs []error
	for _, k := range []string{StorePrefix + "_BUCKET", StorePrefix + "_ENDPOINT", StorePrefix + "_ACCESS_KEY_FILE", StorePrefix + "_SECRET_KEY_FILE",
		"FAIR_REPORT_CONTEXT_KEY_FILE", "FAIR_REPORT_CONTEXT_KEY_ID_FILE"} {
		if c.Getenv(k) == "" {
			errs = append(errs, fmt.Errorf("%s is required in production (F-010: the report store and the report context key)", k))
		}
	}
	return errors.Join(errs...)
}

// OpenStore opens the report store and checks that its bucket exists and
// is versioned (it need not be write-once: files are deleted after
// report.retention_days).
func OpenStore(ctx context.Context, env string, getenv func(string) string) (*objstore.Store, error) {
	s, err := objstore.New(objstore.FromEnv(StorePrefix, env, getenv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", StorePrefix, err)
	}
	if err := s.CheckVersioned(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", StorePrefix, err)
	}
	return s, nil
}

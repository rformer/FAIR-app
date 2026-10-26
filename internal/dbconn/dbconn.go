// Package dbconn builds PostgreSQL connection settings for FAIR services with
// the platform's rules (ADR-006): the login role is fixed by the caller, the
// password comes only from a mounted secret file, and in production the server
// certificate must be verified over TLS 1.2 or later with no plaintext
// fallback.
package dbconn

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/config"
)

// Config builds connection settings from the standard libpq variables
// (PGHOST, PGPORT, PGDATABASE, PGSSLMODE, PGSSLROOTCERT, ...). PGUSER and
// PGPASSWORD are ignored: user is fixed and the password is read from
// passwordFile.
func Config(env, user, passwordFile, appName string) (*pgx.ConnConfig, error) {
	if env == "production" && os.Getenv("PGSSLMODE") != "verify-full" {
		return nil, errors.New("PGSSLMODE=verify-full is required when FAIR_ENV=production")
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("connection settings: %w", err)
	}
	pw, err := config.ReadSecretFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("password file for %s: %w", user, err)
	}
	cfg.User, cfg.Password = user, pw
	cfg.RuntimeParams["application_name"] = appName
	if env == "production" {
		cfg.Fallbacks = nil // never retry without TLS
	}
	if cfg.TLSConfig != nil {
		cfg.TLSConfig.MinVersion = tls.VersionTLS12
	}
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig != nil {
			fb.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}
	return cfg, nil
}

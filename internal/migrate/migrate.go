// Package migrate is the embedded schema migration runner (F-001 T-02b). It
// replaces scripts/db-migrate.sh with the same semantics:
//
//   - it connects as app_migrator, with the password read from a file;
//   - each migration runs in its own transaction under SET LOCAL ROLE
//     fair_owner, so the migrator holds no privileges outside it;
//   - fair_meta.schema_migrations records each version with the SHA-256 of
//     its file, and a changed applied migration stops the run (tamper and
//     drift detection).
//
// After the migrations it applies the build's permission catalog and
// built-in roles with iam.sync_release (T-06), in the same privileged
// session, so every install and upgrade gets the catalog it ships with.
package migrate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/config"
)

// ErrChecksum means an applied migration's file has changed since it was
// applied. The run stops before applying anything later.
var ErrChecksum = errors.New("migrate: checksum mismatch")

// lockKey serializes concurrent runners (e.g. two Jobs started by an upgrade).
const lockKey int64 = 0x0FA1_0000_0000_0002

var nameRE = regexp.MustCompile(`^[0-9]{4}_[a-z0-9_]+\.sql$`)

// SyncResult is what iam.sync_release reports. AddedPermissions feeds the
// admin notice for new catalog permissions (AC-57, T-29).
type SyncResult struct {
	Version          int      `json:"version"`
	PreviousVersion  int      `json:"previous_version"`
	AddedPermissions []string `json:"added_permissions"`
	CreatedRoles     []string `json:"created_roles"`
	VersionedRoles   []string `json:"versioned_roles"`
}

// Result summarizes a run.
type Result struct {
	Applied []string // versions applied by this run, in order
	Sync    SyncResult
}

// ConnConfig builds the migrator's connection from the standard libpq
// variables (PGHOST, PGPORT, PGDATABASE, PGSSLMODE, PGSSLROOTCERT, ...). The
// user is always app_migrator and the password comes only from passwordFile;
// PGPASSWORD is ignored. In production the server certificate must be
// verified (PGSSLMODE=verify-full) and TLS 1.2 is the floor (ADR-006).
func ConnConfig(env, passwordFile string) (*pgx.ConnConfig, error) {
	if env == "production" && os.Getenv("PGSSLMODE") != "verify-full" {
		return nil, errors.New("migrate: PGSSLMODE=verify-full is required when FAIR_ENV=production")
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("migrate: connection settings: %w", err)
	}
	pw, err := config.ReadSecretFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("migrate: FAIR_MIGRATOR_PASSWORD_FILE: %w", err)
	}
	cfg.User, cfg.Password = "app_migrator", pw
	cfg.RuntimeParams["application_name"] = "fair-migrate"
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

// Run applies pending migrations from migrations (a directory of
// NNNN_name.sql files) and then syncs the release catalog from payload
// (catalog.SyncPayload). conn must be connected as app_migrator.
func Run(ctx context.Context, conn *pgx.Conn, migrations fs.FS, payload []byte) (Result, error) {
	var res Result
	names, err := fs.Glob(migrations, "*.sql")
	if err != nil {
		return res, err
	}
	if len(names) == 0 {
		return res, errors.New("migrate: no migrations found")
	}
	slices.Sort(names)
	for _, n := range names {
		if !nameRE.MatchString(n) {
			return res, fmt.Errorf("migrate: bad migration file name %q", n)
		}
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return res, fmt.Errorf("migrate: lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockKey) }()

	if err := asOwner(ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Conn().PgConn().Exec(ctx, `
CREATE SCHEMA IF NOT EXISTS fair_meta AUTHORIZATION fair_owner;
REVOKE ALL ON SCHEMA fair_meta FROM PUBLIC;
CREATE TABLE IF NOT EXISTS fair_meta.schema_migrations (
  version    text        PRIMARY KEY,
  sha256     text        NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON fair_meta.schema_migrations FROM PUBLIC;`).ReadAll()
		return err
	}); err != nil {
		return res, fmt.Errorf("migrate: bookkeeping: %w", err)
	}

	for _, n := range names {
		body, err := fs.ReadFile(migrations, n)
		if err != nil {
			return res, err
		}
		sum := sha256.Sum256(body)
		hexsum := hex.EncodeToString(sum[:])
		version := strings.TrimSuffix(n, ".sql")

		applied := false
		err = asOwner(ctx, conn, func(tx pgx.Tx) error {
			var recorded string
			switch err := tx.QueryRow(ctx, "SELECT sha256 FROM fair_meta.schema_migrations WHERE version = $1", version).Scan(&recorded); {
			case err == nil:
				if recorded != hexsum {
					return fmt.Errorf("%w for %s (applied %s, file %s); refusing to continue", ErrChecksum, version, recorded, hexsum)
				}
				return nil
			case !errors.Is(err, pgx.ErrNoRows):
				return err
			}
			if _, err := tx.Conn().PgConn().Exec(ctx, string(body)).ReadAll(); err != nil {
				return fmt.Errorf("migrate: %s: %w", version, err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO fair_meta.schema_migrations (version, sha256) VALUES ($1, $2)", version, hexsum); err != nil {
				return err
			}
			applied = true
			return nil
		})
		if err != nil {
			return res, err
		}
		if applied {
			res.Applied = append(res.Applied, version)
		}
	}

	err = asOwner(ctx, conn, func(tx pgx.Tx) error {
		var out []byte
		if err := tx.QueryRow(ctx, "SELECT iam.sync_release($1::jsonb)", string(payload)).Scan(&out); err != nil {
			return err
		}
		return json.Unmarshal(out, &res.Sync)
	})
	if err != nil {
		return res, fmt.Errorf("migrate: release catalog: %w", err)
	}
	return res, nil
}

// asOwner runs fn in a transaction that has switched to fair_owner. The role
// reverts when the transaction ends.
func asOwner(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE fair_owner"); err != nil {
			return err
		}
		return fn(tx)
	})
}

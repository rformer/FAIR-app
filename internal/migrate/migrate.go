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
// built-in roles with iam.sync_release (T-06) and loads the build's profile
// packages with posture.sync_packages (F-015 T-10), in one privileged
// transaction, so every install and upgrade gets the release it ships with.
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/dbconn"
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

// PackageSync is what posture.sync_packages reports, as "id@version".
type PackageSync struct {
	Imported  []string `json:"imported"`
	Unchanged []string `json:"unchanged"`
}

// Release is what a build ships besides its migrations.
type Release struct {
	Catalog         []byte   // catalog.SyncPayload, for iam.sync_release
	ProfilePackages [][]byte // profile packages, checked against their manifest (profilepkg.LoadRelease)
}

// Result summarizes a run.
type Result struct {
	Applied  []string // versions applied by this run, in order
	Sync     SyncResult
	Packages PackageSync
}

// ConnConfig builds the migrator's connection (see dbconn.Config). The user
// is always app_migrator and the password comes only from passwordFile.
func ConnConfig(env, passwordFile string) (*pgx.ConnConfig, error) {
	cfg, err := dbconn.Config(env, "app_migrator", passwordFile, "fair-migrate")
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return cfg, nil
}

// Run applies pending migrations from migrations (a directory of
// NNNN_name.sql files) and then syncs the release: its permission catalog
// and its profile packages. conn must be connected as app_migrator.
func Run(ctx context.Context, conn *pgx.Conn, migrations fs.FS, rel Release) (Result, error) {
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
		if err := tx.QueryRow(ctx, "SELECT iam.sync_release($1::jsonb)", string(rel.Catalog)).Scan(&out); err != nil {
			return fmt.Errorf("release catalog: %w", err)
		}
		if err := json.Unmarshal(out, &res.Sync); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT posture.sync_packages($1::bytea[])", rel.ProfilePackages).Scan(&out); err != nil {
			return fmt.Errorf("profile packages: %w", err)
		}
		return json.Unmarshal(out, &res.Packages)
	})
	if err != nil {
		return res, fmt.Errorf("migrate: %w", err)
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

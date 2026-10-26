package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/db"
	"github.com/rformer/fair-app/internal/access/catalog"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/profiles"
)

// exitChecksum is the exit status for a modified applied migration, kept from
// scripts/db-migrate.sh so operators' runbooks still apply.
const exitChecksum = 3

// runMigrate implements `iam migrate` (F-001 T-02b): apply the embedded
// migrations and the release catalog as app_migrator, then exit.
//
// Environment: FAIR_ENV (default production), FAIR_MIGRATOR_PASSWORD_FILE,
// FAIR_REQUIRE_FIPS, and the libpq connection variables.
func runMigrate() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "iam", "command", "migrate", "version", version)

	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production" {
		if !fips140.Enabled() {
			logger.Error("FIPS 140 mode is required but not enabled")
			return 1
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	res, err := migrateOnce(ctx, env)
	if err != nil {
		logger.Error("migration failed", "error", err.Error())
		if errors.Is(err, migrate.ErrChecksum) {
			return exitChecksum
		}
		return 1
	}

	// Audit failures fail closed (ADR-006): the run reports failure if its
	// evidence cannot be recorded.
	emitter := audit.NewJSONLines(os.Stdout) // replaced by the F-002 pipeline; see pkg/audit
	sev := audit.SeverityInfo
	if res.Sync.PreviousVersion > 0 && len(res.Sync.AddedPermissions) > 0 {
		sev = audit.SeverityHigh // an upgrade added permissions: admins are notified (AC-57)
	}
	if err := emitter.Emit(ctx, audit.Event{
		Type:     "db.migrated",
		Severity: sev,
		Actor:    "system:migrate",
		Attributes: map[string]string{
			"applied":           strings.Join(res.Applied, ","),
			"catalog_version":   fmt.Sprint(res.Sync.Version),
			"catalog_previous":  fmt.Sprint(res.Sync.PreviousVersion),
			"added_permissions": strings.Join(res.Sync.AddedPermissions, ","),
			"created_roles":     strings.Join(res.Sync.CreatedRoles, ","),
			"versioned_roles":   strings.Join(res.Sync.VersionedRoles, ","),
			"profiles_imported": strings.Join(res.Packages.Imported, ","),
		},
	}); err != nil {
		logger.Error("audit emit failed", "error", err.Error())
		return 1
	}
	logger.Info("migration complete", "applied", len(res.Applied), "catalog_version", res.Sync.Version)
	return 0
}

func migrateOnce(ctx context.Context, env string) (migrate.Result, error) {
	cfg, err := migrate.ConnConfig(env, os.Getenv("FAIR_MIGRATOR_PASSWORD_FILE"))
	if err != nil {
		return migrate.Result{}, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return migrate.Result{}, fmt.Errorf("migrate: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	c, roles, err := catalog.Release()
	if err != nil {
		return migrate.Result{}, err
	}
	payload, err := catalog.SyncPayload(c, roles)
	if err != nil {
		return migrate.Result{}, err
	}
	migrations, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return migrate.Result{}, err
	}
	pkgs, err := releasePackages()
	if err != nil {
		return migrate.Result{}, err
	}
	return migrate.Run(ctx, conn, migrations, migrate.Release{Catalog: payload, ProfilePackages: pkgs})
}

// releasePackages returns the embedded profile packages, each checked
// against the digest pinned in the embedded manifest (F-015 T-10).
func releasePackages() ([][]byte, error) {
	dir, err := fs.Sub(profiles.Packages, "packages")
	if err != nil {
		return nil, err
	}
	return profilepkg.LoadRelease(dir, "manifest.json")
}

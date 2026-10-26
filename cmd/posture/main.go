// Command posture runs the security posture service (F-015).
//
// T-08 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, and a
// database pool as app_posture (design §5 access model). The registry,
// change evaluator, exceptions, drift and export arrive with later tasks.
//
// Environment: as for iam (FAIR_ENV, FAIR_LISTEN_ADDR, FAIR_TLS_*_FILE,
// FAIR_REQUIRE_FIPS, ...), plus FAIR_DB_PASSWORD_FILE (app_posture's password)
// and the libpq connection variables.
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// dbRole is the posture service's own login role; it owns nothing and has no
// table privileges (design §5 access model).
const dbRole = "app_posture"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "posture:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "posture", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("posture")
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	// Constitution S2: refuse to run without the FIPS 140 module when required.
	if cfg.RequireFIPS && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled (build with GOFIPS140 and run with GODEBUG=fips140=on)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cc, err := dbconn.Config(cfg.Env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-posture")
	if err != nil {
		return err
	}
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return err
	}
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	emitter := audit.NewJSONLines(os.Stdout) // replaced by the F-002 pipeline; see pkg/audit
	if err := emitter.Emit(ctx, audit.Event{
		Type:       "service.started",
		Severity:   audit.SeverityInfo,
		Actor:      "system:posture",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env},
	}); err != nil {
		return fmt.Errorf("audit: %w", err) // audit failures fail closed (ADR-006)
	}

	srv := server.New(server.Options{
		Addr:        cfg.ListenAddr,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		Plaintext:   cfg.AllowPlaintext,
		Logger:      logger,
	})
	srv.AddReadinessCheck(server.ReadinessCheck{Name: "database", Check: func(ctx context.Context) error {
		return schemaReady(ctx, pool)
	}})

	err = srv.Run(ctx, cfg.ShutdownTimeout)
	_ = emitter.Emit(context.Background(), audit.Event{
		Type:     "service.stopped",
		Severity: audit.SeverityInfo,
		Actor:    "system:posture",
	})
	return err
}

// schemaReady checks that the database is reachable, the posture schema is
// migrated, and the connection really is the locked-down role: it may use the
// schema but read no posture table directly.
func schemaReady(ctx context.Context, pool *pgxpool.Pool) error {
	var user string
	var usage, direct bool
	err := pool.QueryRow(ctx, `SELECT current_user,
		has_schema_privilege('posture', 'USAGE'),
		has_table_privilege('posture.setting_value', 'SELECT')`).Scan(&user, &usage, &direct)
	switch {
	case err != nil:
		return err
	case user != dbRole:
		return fmt.Errorf("connected as %s, want %s", user, dbRole)
	case !usage:
		return errors.New("posture schema is not usable; run the migrations")
	case direct:
		return errors.New("app_posture can read posture tables directly; the database grants are wrong (design §5)")
	}
	return nil
}

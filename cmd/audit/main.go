// Command audit runs the audit service (F-002): the tamper-evident audit
// trail's sequencer, checkpoints, verification, forwarding, retention and
// API (design §2).
//
// T-05 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, a
// database pool as app_audit, the install checks of design §7, and leader
// election (one replica leads; the work it leads arrives with T-07).
//
// Environment: as for every service (FAIR_ENV, FAIR_DEPLOYMENT_MODE,
// FAIR_LISTEN_ADDR, FAIR_TLS_CERT_FILE, FAIR_TLS_KEY_FILE, FAIR_REQUIRE_FIPS,
// ...), plus:
//
//	FAIR_DB_PASSWORD_FILE            app_audit's password (and the libpq variables)
//	FAIR_AUDIT_CHECKPOINT_KEYS_DIR   the checkpoint signing key (one private
//	                                 ECDSA P-256 key, from iam keys init or
//	                                 upgrade); required in production
//	FAIR_JWT_KEYS_DIR                the gateway's internal-JWT public keys,
//	                                 for the audit API; required in production
//	FAIR_AUDIT_WORM_BUCKET           write-once storage for checkpoint copies;
//	                                 required in SaaS (F-002 AC-10)
//	POD_NAME                         this replica's name, in leader logs
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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const dbRole = "app_audit"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "audit:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "audit", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("audit")
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	// F-001 T-41: key files are not open to other users.
	if err := keys.CheckMounted(cfg.Env, os.Getenv); err != nil {
		return err
	}
	// Constitution S2: refuse to run without the FIPS 140 module when required.
	if cfg.RequireFIPS && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled (build with GOFIPS140 and run with GODEBUG=fips140=on)")
	}
	// Design §7: what the environment and deployment mode need.
	if err := auditsvc.CheckInstall(auditsvc.InstallCheck{Env: cfg.Env, Mode: cfg.DeploymentMode, Getenv: os.Getenv}); err != nil {
		return err
	}
	if dir := os.Getenv("FAIR_AUDIT_CHECKPOINT_KEYS_DIR"); dir != "" {
		_, id, err := keys.CheckpointKey(dir)
		if err != nil {
			return fmt.Errorf("FAIR_AUDIT_CHECKPOINT_KEYS_DIR: %w", err)
		}
		logger.Info("checkpoint signing key", "key", id)
	}
	if dir := os.Getenv("FAIR_JWT_KEYS_DIR"); dir != "" {
		if _, err := authz.LoadLocalKeys(dir); err != nil {
			return fmt.Errorf("FAIR_JWT_KEYS_DIR: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := connect(ctx, cfg.Env)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := schemaReady(ctx, pool); err != nil {
		return err
	}

	emitter, err := auditSink(cfg.Env, pool)
	if err != nil {
		return err
	}
	if err := emitter.Emit(ctx, audit.Event{Type: "service.started", Severity: audit.SeverityInfo, Actor: "system:audit",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env, "deployment_mode": cfg.DeploymentMode}}); err != nil {
		return fmt.Errorf("audit: %w", err) // audit failures fail closed (ADR-006)
	}

	// F-002's settings (design §4.4): registered with posture (retried until
	// the install is seeded) and read as every service reads settings.
	replica := os.Getenv("POD_NAME")
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "audit", Instance: replica})
	if err := sc.Register(settings.F002Defs()...); err != nil {
		return err
	}
	go registerF002(ctx, pool, logger)
	if err := sc.Refresh(ctx); err != nil {
		logger.Warn("settings not loaded yet; defaults apply until they are", "error", err.Error())
	}
	go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })

	// One replica leads (design §2) and sequences the trail (T-07).
	seq := auditsvc.Sequencer{DB: pool, MaxSkew: func() time.Duration {
		d, err := sc.Duration(settings.KeyAuditMaxClockSkew, "")
		if err != nil {
			return 5 * time.Minute // the default of every built-in profile
		}
		return d
	}}
	leader := auditsvc.Leader{Pool: pool, OnChange: func(leading bool) {
		logger.Info("leader", "leading", leading, "replica", replica)
	}}
	go leader.Run(ctx, func(ctx context.Context) error {
		return seq.Run(ctx, 0, func(err error) { logger.Error("sequencer", "error", err.Error()) })
	}, func(err error) { logger.Error("leader", "error", err.Error()) })

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
	_ = emitter.Emit(context.Background(), audit.Event{Type: "service.stopped", Severity: audit.SeverityInfo, Actor: "system:audit"})
	return err
}

// schemaReady checks that the database is reachable, the audit schema is
// migrated, and the connection really is the locked-down role: it may use
// the schema but read no audit table directly (design §4.3).
func schemaReady(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user string
	var usage, direct bool
	err := pool.QueryRow(ctx, `SELECT current_user, has_schema_privilege('audit', 'USAGE'),
		has_table_privilege('audit.record', 'SELECT') OR has_table_privilege('audit.intake', 'SELECT')`).Scan(&user, &usage, &direct)
	switch {
	case err != nil:
		return fmt.Errorf("database: %w", err)
	case user != dbRole:
		return fmt.Errorf("connected as %s, want %s", user, dbRole)
	case !usage:
		return errors.New("audit schema is not usable; run the migrations")
	case direct:
		return errors.New("app_audit can read audit tables directly; the database grants are wrong (design §4.3)")
	}
	return nil
}

func connect(ctx context.Context, env string) (*pgxpool.Pool, error) {
	cc, err := dbconn.Config(env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-audit")
	if err != nil {
		return nil, err
	}
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	return pool, nil
}

// auditSink is the service's own event emitter (F-001 T-37): the audit
// trail first, then the logs (F-002 T-06).
func auditSink(env string, db audit.Beginner) (audit.Emitter, error) {
	e, err := audit.FromEnv(env, "fair-audit", os.Getenv)
	if err != nil {
		return nil, err
	}
	return audit.WithTrail(e, audit.Trail{DB: db}), nil
}

// registerF002 registers F-002's setting definitions, retrying every 30
// seconds until it succeeds (posture refuses before the install is seeded).
func registerF002(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	for {
		err := settings.DBRegistrar{DB: pool}.Register(ctx, "F-002", version, settings.F002Defs())
		if err == nil {
			return
		}
		logger.Warn("registering F-002 settings", "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

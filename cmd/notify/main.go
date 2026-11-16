// Command notify runs the notification service (F-009): it collects the
// notices the features queue, resolves their recipients, and delivers them
// in the app, by email and to webhooks (design §1). It is the only service
// with egress to SMTP relays and webhooks (deploy/k8s/notify.yaml).
//
// T-03 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, a
// database pool as app_notify, the install checks of design §11, F-009's
// settings registered, and leader election (one replica leads). The
// leader collects the outboxes (T-04); its other work (fan out, digests,
// retention: T-05, T-10)
// and the delivery workers on every replica (T-10) arrive with their tasks,
// as does the notifications API (T-06, T-11).
//
// Environment: as for every service (FAIR_ENV, FAIR_DEPLOYMENT_MODE,
// FAIR_LISTEN_ADDR, FAIR_TLS_CERT_FILE, FAIR_TLS_KEY_FILE, FAIR_REQUIRE_FIPS,
// ...), plus:
//
//	FAIR_DB_PASSWORD_FILE       app_notify's password (and the libpq variables)
//	FAIR_JWT_KEYS_DIR           the gateway's internal-JWT public keys, for the
//	                            notifications API; required in production
//	FAIR_NOTIFY_SECRETS_DIR     the webhook-secrets keys (iam keys init or
//	                            upgrade); required in production
//	FAIR_NOTIFY_BASE_URL        the platform's https base URL, which every link
//	                            in a notice is built from; required in production
//	FAIR_NOTIFY_CLUSTER_CIDRS   the cluster's pod and service ranges, never a
//	                            destination; required in production
//	FAIR_NOTIFY_SMTP_DIR        where the SMTP relay's password files are
//	                            (default /keys/smtp)
//	POD_NAME                    this replica's name, in leader logs
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
	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const dbRole = "app_notify"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "notify:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "notify", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("notify")
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
	// Design §11: what the environment and deployment mode need.
	if err := notify.CheckInstall(notify.InstallCheck{Env: cfg.Env, Mode: cfg.DeploymentMode, Getenv: os.Getenv}); err != nil {
		return err
	}
	if dir := os.Getenv("FAIR_NOTIFY_SECRETS_DIR"); dir != "" {
		ks, err := keys.WebhookSecretKeys(dir)
		if err != nil || len(ks) == 0 {
			return fmt.Errorf("FAIR_NOTIFY_SECRETS_DIR: no webhook-secrets key (%v)", err)
		}
		logger.Info("webhook-secrets keys", "keys", len(ks))
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
	if err := emitter.Emit(ctx, audit.Event{Type: "service.started", Severity: audit.SeverityInfo, Actor: "system:notify",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env, "deployment_mode": cfg.DeploymentMode}}); err != nil {
		return fmt.Errorf("audit: %w", err) // audit failures fail closed (ADR-006)
	}

	// F-009's settings (design §4): registered with posture (retried until
	// the install is seeded) and read as every service reads settings.
	replica := os.Getenv("POD_NAME")
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "notify", Instance: replica})
	if err := sc.Register(settings.F009Defs()...); err != nil {
		return err
	}
	go registerF009(ctx, pool, logger)
	if err := sc.Refresh(ctx); err != nil {
		logger.Warn("settings not loaded yet; defaults apply until they are", "error", err.Error())
	}
	go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })

	// One replica leads (design §1): it collects the features' outboxes
	// into notices every 10 seconds (T-04); fan-out, digests and retention
	// follow (T-05, T-10).
	collector := notify.Collector{DB: pool, Titles: func() bool {
		d, err := sc.Enum(settings.KeyNotificationDetail, "")
		return err == nil && d == "titles" // minimal unless the setting says otherwise
	}}
	leader := auditsvc.Leader{Pool: pool, Key: notify.LeaderLockKey, OnChange: func(leading bool) {
		logger.Info("leader", "leading", leading, "replica", replica)
	}}
	go leader.Run(ctx, func(ctx context.Context) error {
		for {
			n, unknown, err := collector.Collect(ctx)
			switch {
			case err != nil && ctx.Err() == nil:
				logger.Error("collect", "error", err.Error())
			case unknown > 0:
				logger.Error("collect: outbox rows of kinds this release does not know are left pending", "unknown", unknown)
			case n > 0:
				logger.Info("collected", "notices", n)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(notify.Every):
			}
		}
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
	_ = emitter.Emit(context.Background(), audit.Event{Type: "service.stopped", Severity: audit.SeverityInfo, Actor: "system:notify"})
	return err
}

// schemaReady checks that the database is reachable, the notify schema is
// migrated, and the connection really is the locked-down role: it may use
// the schema but read no notify table directly (design §5).
func schemaReady(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user string
	var usage, direct bool
	err := pool.QueryRow(ctx, `SELECT current_user, has_schema_privilege('notify', 'USAGE'),
		has_table_privilege('notify.notice', 'SELECT') OR has_table_privilege('notify.channel', 'SELECT') OR has_table_privilege('notify.delivery', 'SELECT')`).
		Scan(&user, &usage, &direct)
	switch {
	case err != nil:
		return fmt.Errorf("database: %w", err)
	case user != dbRole:
		return fmt.Errorf("connected as %s, want %s", user, dbRole)
	case !usage:
		return errors.New("notify schema is not usable; run the migrations")
	case direct:
		return errors.New("app_notify can read notify tables directly; the database grants are wrong (design §5)")
	}
	return nil
}

func connect(ctx context.Context, env string) (*pgxpool.Pool, error) {
	cc, err := dbconn.Config(env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-notify")
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
	e, err := audit.FromEnv(env, "fair-notify", os.Getenv)
	if err != nil {
		return nil, err
	}
	return audit.WithTrail(e, audit.Trail{DB: db}), nil
}

// registerF009 registers F-009's setting definitions, retrying every 30
// seconds until it succeeds (posture refuses before the install is seeded).
func registerF009(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	for {
		err := settings.DBRegistrar{DB: pool}.Register(ctx, "F-009", version, settings.F009Defs())
		if err == nil {
			return
		}
		logger.Warn("registering F-009 settings", "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

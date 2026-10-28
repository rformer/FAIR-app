// Command iam runs the identity and access service (F-001).
//
// Phase 0: hardened server skeleton with health/readiness, FIPS enforcement,
// structured logging, and audit emission of lifecycle events. T-15: the SAML
// service provider under /api/v1/auth/saml/ (behind the gateway), when
// FAIR_PUBLIC_ORIGIN is set (required in production) with
// FAIR_DB_PASSWORD_FILE (app_rw) and FAIR_LOGIN_TICKET_KEYS_DIR (the ES256
// key that signs login tickets for the gateway). `iam migrate`
// applies the embedded schema migrations and release catalog (T-02b);
// `iam worker` runs the scope worker (T-08). Domain modules
// (authn, scim, directory, org, access, approvals, reviews) arrive in Phases 1–4.
package main

import (
	"context"
	"crypto/fips140"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			os.Exit(runMigrate())
		case "worker":
			os.Exit(runWorker())
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "iam:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "iam", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("iam")
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	// Constitution S2: refuse to run without the FIPS 140 module when required.
	if cfg.RequireFIPS && !fips140.Enabled() {
		return fmt.Errorf("FIPS 140 mode is required but not enabled (build with GOFIPS140 and run with GODEBUG=fips140=on)")
	}

	emitter := audit.NewJSONLines(os.Stdout) // replaced by the F-002 pipeline; see pkg/audit
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_ = emitter.Emit(ctx, audit.Event{
		Type:     "service.started",
		Severity: audit.SeverityInfo,
		Actor:    "system:iam",
		Attributes: map[string]string{
			"fips140": fmt.Sprint(fips140.Enabled()),
			"env":     cfg.Env,
		},
	})

	srv := server.New(server.Options{
		Addr:        cfg.ListenAddr,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		Plaintext:   cfg.AllowPlaintext,
		Logger:      logger,
	})

	// SAML login (T-15), behind the gateway.
	if origin := os.Getenv("FAIR_PUBLIC_ORIGIN"); origin != "" {
		keys, err := authz.LoadLocalKeys(os.Getenv("FAIR_LOGIN_TICKET_KEYS_DIR"))
		if err != nil {
			return fmt.Errorf("FAIR_LOGIN_TICKET_KEYS_DIR: %w", err)
		}
		if _, _, err := keys.SigningKey(); err != nil {
			return fmt.Errorf("FAIR_LOGIN_TICKET_KEYS_DIR has no signing key: %w", err)
		}
		cc, err := dbconn.Config(cfg.Env, "app_rw", os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-iam")
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
		sp := &authn.SAML{DB: pool, Origin: strings.TrimSuffix(origin, "/"), Tickets: keys, Logger: logger}
		srv.Mux().Handle(authn.Prefix, server.SecurityHeaders(sp.Handler()))
		srv.AddReadinessCheck(server.ReadinessCheck{Name: "database", Check: func(ctx context.Context) error { return pool.Ping(ctx) }})
	} else if cfg.Env == "production" {
		return fmt.Errorf("FAIR_PUBLIC_ORIGIN is required in production (the SAML service provider, F-001 T-15)")
	}

	err = srv.Run(ctx, cfg.ShutdownTimeout)

	_ = emitter.Emit(context.Background(), audit.Event{
		Type:     "service.stopped",
		Severity: audit.SeverityInfo,
		Actor:    "system:iam",
	})
	return err
}

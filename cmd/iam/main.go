// Command iam runs the identity and access service (F-001).
//
// Phase 0: hardened server skeleton with health/readiness, FIPS enforcement,
// structured logging, and audit emission of lifecycle events. T-15: the SAML
// service provider under /api/v1/auth/saml/ (behind the gateway), when
// FAIR_PUBLIC_ORIGIN is set (required in production), and OIDC (T-16) under
// /api/v1/auth/oidc/; T-17 adds home-realm discovery and the IdP API
// (/api/v1/idps, FAIR_JWT_KEYS_DIR), with
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
	"github.com/rformer/fair-app/internal/iamapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
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
		// Whether a login must show MFA evidence (T-18), read as every service
		// reads settings; a stale snapshot requires MFA (fail closed).
		sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "iam", Instance: os.Getenv("POD_NAME")})
		var defs []settings.Def
		for _, d := range settings.F001Defs() {
			if d.Key == settings.KeyAuthMFAAll || d.Key == settings.KeyAuthMFAPrivileged || d.Key == settings.KeySessionNetworkBinding {
				defs = append(defs, d)
			}
		}
		if err := sc.Register(defs...); err != nil {
			return err
		}
		if err := sc.Refresh(ctx); err != nil {
			return fmt.Errorf("settings: %w", err)
		}
		go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })
		logins := authn.Logins{DB: pool, Origin: strings.TrimSuffix(origin, "/"), Tickets: keys, Logger: logger, Settings: sc}
		sp := &authn.SAML{Logins: logins}
		srv.Mux().Handle(authn.Prefix, server.SecurityHeaders(sp.Handler()))
		rp := &authn.OIDC{Logins: logins}
		srv.Mux().Handle(authn.OIDCPrefix, server.SecurityHeaders(rp.Handler()))
		// Home-realm discovery (T-17), unauthenticated and rate-limited.
		srv.Mux().Handle(authn.DiscoverPath, server.SecurityHeaders(&authn.Discovery{Logins: logins}))
		// The IdP administration API (T-17): internal JWTs verified with the
		// gateway's public keys (FAIR_JWT_KEYS_DIR, required in production).
		if dir := os.Getenv("FAIR_JWT_KEYS_DIR"); dir != "" {
			jwtKeys, err := authz.LoadLocalKeys(dir)
			if err != nil {
				return fmt.Errorf("FAIR_JWT_KEYS_DIR: %w", err)
			}
			grants := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool),
				NetworkBinding: func(bu string) (string, error) { return sc.Enum(settings.KeySessionNetworkBinding, bu) }})
			api := &iamapi.API{DB: pool, Authz: grants, DeploymentMode: cfg.DeploymentMode, Dev: cfg.Env == "development"}
			h := server.SecurityHeaders(api.Handler(jwtKeys, nil))
			for _, p := range iamapi.Prefixes {
				srv.Mux().Handle(p, h)
				srv.Mux().Handle(p+"/", h)
			}
		} else if cfg.Env == "production" {
			return fmt.Errorf("FAIR_JWT_KEYS_DIR is required in production (the iam API verifies the gateway's internal JWTs)")
		}
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

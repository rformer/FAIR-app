// Command iam runs the identity and access service (F-001).
//
// Phase 0: hardened server skeleton with health/readiness, FIPS enforcement,
// structured logging, and audit emission of lifecycle events. T-15: the SAML
// service provider under /api/v1/auth/saml/ (behind the gateway), when
// FAIR_PUBLIC_ORIGIN is set (required in production), and OIDC (T-16) under
// /api/v1/auth/oidc/; T-17 adds home-realm discovery and the IdP API
// (/api/v1/idps, FAIR_JWT_KEYS_DIR); T-33 service-account client secrets
// need FAIR_TOKEN_PEPPER_FILE (the gateway's too); with
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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/breakglass"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/iamapi"
	"github.com/rformer/fair-app/internal/scim"
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
		case "breakglass":
			os.Exit(runBreakglass(os.Args[2:]))
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
			if d.Key == settings.KeyAuthMFAAll || d.Key == settings.KeyAuthMFAPrivileged || d.Key == settings.KeySessionNetworkBinding ||
				d.Key == settings.KeyAuthJIT {
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
		// iam owns F-001's settings: it registers their definitions with
		// posture (F-015 T-12), which records changes only of registered
		// keys (break-glass, T-34). Retried until posture is seeded.
		go registerF001(ctx, pool, logger)
		logins := authn.Logins{DB: pool, Origin: strings.TrimSuffix(origin, "/"), Tickets: keys, Logger: logger, Settings: sc}
		sp := &authn.SAML{Logins: logins}
		srv.Mux().Handle(authn.Prefix, server.SecurityHeaders(sp.Handler()))
		rp := &authn.OIDC{Logins: logins}
		srv.Mux().Handle(authn.OIDCPrefix, server.SecurityHeaders(rp.Handler()))
		// Break-glass sign-in (T-34): WebAuthn, only while breakglass.enabled.
		bg, err := breakglass.New(pool, keys, strings.TrimSuffix(origin, "/"), logger)
		if err != nil {
			return fmt.Errorf("break-glass WebAuthn: %w", err)
		}
		srv.Mux().Handle(breakglass.Prefix, server.SecurityHeaders(bg))
		// The SCIM 2.0 service provider (T-21): bearer tokens per IdP.
		sp2 := &scim.Server{Store: scim.Store{DB: pool}, Origin: strings.TrimSuffix(origin, "/"), Logger: logger}
		srv.Mux().Handle(scim.Prefix+"/", server.SecurityHeaders(sp2.Handler()))
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
			// Service-account client secrets (T-33) are stored as HMACs under
			// the token pepper the gateway holds too.
			if f := os.Getenv("FAIR_TOKEN_PEPPER_FILE"); f != "" {
				b, err := os.ReadFile(f) // #nosec G304 G703 -- operator-supplied secret file
				if err != nil {
					return fmt.Errorf("FAIR_TOKEN_PEPPER_FILE: %w", err)
				}
				if api.TokenPepper = []byte(strings.TrimSpace(string(b))); len(api.TokenPepper) < authn.MinTokenPepperLen {
					return fmt.Errorf("FAIR_TOKEN_PEPPER_FILE must hold at least %d bytes", authn.MinTokenPepperLen)
				}
			}
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

// registerF001 registers F-001's setting definitions, retrying every 30
// seconds until it succeeds (posture refuses before the install is seeded).
func registerF001(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	for {
		err := settings.DBRegistrar{DB: pool}.Register(ctx, "F-001", version, settings.F001Defs())
		if err == nil {
			return
		}
		logger.Warn("registering F-001 settings", "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

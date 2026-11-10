// Command risk runs the risk service (F-003): the Open FAIR data model's
// scenarios, library and controls (design §2).
//
// T-04 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, a
// database pool as app_rw (every risk table is under row-level security;
// design §2), and the install checks of design §7. Every replica serves
// the risk API (internal/riskapi; T-05).
//
//	risk                                  run the service
//	risk currency set CODE -operator NAME record the installation currency
//	                                      (ISO 4217; design §3.4), audited;
//	                                      refused once amounts are stored
//	risk currency show                    print it
//
// The currency commands run at install, as app_migrator acting as
// fair_owner (FAIR_MIGRATOR_PASSWORD_FILE and the libpq variables).
//
// Environment: as for every service (FAIR_ENV, FAIR_DEPLOYMENT_MODE,
// FAIR_LISTEN_ADDR, FAIR_TLS_CERT_FILE, FAIR_TLS_KEY_FILE, FAIR_REQUIRE_FIPS,
// ...), plus:
//
//	FAIR_DB_PASSWORD_FILE   app_rw's password (and the libpq variables)
//	FAIR_JWT_KEYS_DIR       the gateway's internal-JWT public keys, for the
//	                        risk API; required in production
//	FAIR_NATS_URL           NATS, for scope changes (the API's grant cache
//	                        otherwise refreshes on its own);
//	                        FAIR_NATS_CREDS_FILE optional
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/estimateapi"
	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const dbRole = "app_rw"

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "currency" {
		err = currency(os.Args[2:], os.Stdout)
	} else {
		err = run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "risk:", err)
		os.Exit(1)
	}
}

const currencyUsage = "usage: risk currency set CODE -operator NAME | risk currency show"

// currency records or shows the installation currency (design §3.4).
func currency(args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "set" && args[0] != "show") {
		return errors.New(currencyUsage)
	}
	cmd := args[0]
	var code string
	rest := args[1:]
	if cmd == "set" {
		if len(rest) == 0 || rest[0] == "" || rest[0][0] == '-' {
			return errors.New(currencyUsage)
		}
		code, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("currency", flag.ContinueOnError)
	operator := fs.String("operator", "", "who records the currency (the install log and the audit trail)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New(currencyUsage)
	}
	if cmd == "set" && *operator == "" {
		return errors.New("-operator is required")
	}
	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, err := migrate.ConnConfig(env, os.Getenv("FAIR_MIGRATOR_PASSWORD_FILE"))
	if err != nil {
		return err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if cmd == "show" {
		var c string
		if err := conn.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&c); err != nil {
			return err
		}
		if c == "" {
			c = "(not set)"
		}
		_, err := fmt.Fprintln(out, c)
		return err
	}
	c, err := audit.DefaultCatalog()
	if err != nil {
		return err
	}
	// The install log, and the audit trail as fair_owner (F-002 T-06).
	emit := audit.WithTrail(audit.Validating{Next: audit.NewJSONLines(out), Catalog: c}, audit.Trail{DB: conn, Role: "fair_owner"})
	prev, err := risk.SetCurrency(ctx, conn, emit, code, *operator)
	if err != nil {
		return err
	}
	if prev == code {
		_, err = fmt.Fprintf(out, "the currency is %s already\n", code)
	}
	return err
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "risk", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("risk")
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
	if err := risk.CheckInstall(risk.InstallCheck{Env: cfg.Env, Mode: cfg.DeploymentMode, Getenv: os.Getenv}); err != nil {
		return err
	}
	// The risk API (T-05) verifies the gateway's internal JWTs.
	var jwtKeys *authz.LocalKeys
	if dir := os.Getenv("FAIR_JWT_KEYS_DIR"); dir != "" {
		k, err := authz.LoadLocalKeys(dir)
		if err != nil {
			return fmt.Errorf("FAIR_JWT_KEYS_DIR: %w", err)
		}
		jwtKeys = k
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
	if c, err := risk.Currency(ctx, pool); err != nil {
		return err
	} else if c == "" {
		logger.Warn("the installation currency is not set (risk currency set CODE): amounts cannot be saved until it is")
	} else {
		logger.Info("installation currency", "currency", c)
	}

	emitter, err := auditSink(cfg.Env, pool)
	if err != nil {
		return err
	}
	if err := emitter.Emit(ctx, audit.Event{Type: "service.started", Severity: audit.SeverityInfo, Actor: "system:risk",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env, "deployment_mode": cfg.DeploymentMode}}); err != nil {
		return fmt.Errorf("audit: %w", err) // audit failures fail closed (ADR-006)
	}

	// F-004's settings (design §7): registered with posture (retried until
	// the install is seeded), read as every service reads settings; the
	// service refuses to start while one of them is unbound.
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "risk", Instance: os.Getenv("POD_NAME")})
	// F-005's (design §7) likewise.
	riskDefs := append(settings.F004Defs(), settings.F005Defs()...)
	if err := sc.Register(riskDefs...); err != nil {
		return err
	}
	go registerDefs(ctx, pool, logger, "F-004", settings.F004Defs())
	go registerDefs(ctx, pool, logger, "F-005", settings.F005Defs())
	if err := sc.Refresh(ctx); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	for _, d := range riskDefs {
		if _, err := sc.Get(d.Key, ""); err != nil {
			return fmt.Errorf("settings: %s is not bound by the active profile: %w", d.Key, err)
		}
	}
	go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })

	// One replica leads and runs the estimate jobs (F-004 design §6.7):
	// requests close at their due date, reminders go out before it.
	jobs := estimate.Jobs{DB: pool, ReminderLead: func() time.Duration {
		d, err := sc.Duration(settings.KeyEstimateReminderLead, "")
		if err != nil {
			return 48 * time.Hour // the default of every built-in profile
		}
		return d
	}, OnError: func(err error) { logger.Error("estimate jobs", "error", err.Error()) },
		Window: func() time.Duration {
			if d, err := sc.Duration(settings.KeyCalibrationWindow, ""); err == nil {
				return d
			}
			return 365 * 24 * time.Hour
		},
		MinAnswers: func() int {
			if n, err := sc.Int(settings.KeyCalibrationMinAnswers, ""); err == nil {
				return n
			}
			return 20
		},
		Retention: func() time.Duration {
			if d, err := sc.Duration(settings.KeyCalibrationRetention, ""); err == nil {
				return d
			}
			return 3 * 365 * 24 * time.Hour
		}}
	leader := auditsvc.Leader{Pool: pool, Key: estimate.RiskLeaderLockKey, OnChange: func(leading bool) {
		logger.Info("leader", "leading", leading, "replica", os.Getenv("POD_NAME"))
	}}
	go leader.Run(ctx, jobs.Run, func(err error) { logger.Error("leader", "error", err.Error()) })

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

	// The risk API (T-05): every replica serves it.
	if jwtKeys != nil {
		grants := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
		if url := os.Getenv("FAIR_NATS_URL"); url != "" {
			nc, err := natspub.Connect(ctx, natspub.Options{Env: cfg.Env, URL: url, CredsFile: os.Getenv("FAIR_NATS_CREDS_FILE"), Name: "fair-risk"})
			if err != nil {
				return err
			}
			defer nc.Close()
			if _, err := nc.Subscribe(authz.SubjectScopeChanged, func(data []byte) {
				if err := grants.HandleScopeChanged(data); err != nil {
					logger.Warn("scope change event", "error", err.Error())
				}
			}); err != nil {
				return fmt.Errorf("nats: %w", err)
			}
		}
		api := &riskapi.API{DB: pool, Authz: grants, Audit: emitter}
		h := server.SecurityHeaders(api.Handler(jwtKeys, nil))
		for _, prefix := range riskapi.Prefixes {
			srv.Mux().Handle(prefix, h)
			srv.Mux().Handle(prefix+"/", h)
		}
		// The estimate API (F-004 design §5), on the same grants.
		eh := server.SecurityHeaders((&estimateapi.API{DB: pool, Authz: grants, Audit: emitter, Settings: sc}).Handler(jwtKeys, nil))
		for _, prefix := range estimateapi.Prefixes {
			srv.Mux().Handle(prefix, eh)
			srv.Mux().Handle(prefix+"/", eh)
		}
	} else {
		logger.Warn("the risk API is off: it needs the gateway's JWT keys (FAIR_JWT_KEYS_DIR)")
	}

	err = srv.Run(ctx, cfg.ShutdownTimeout)
	_ = emitter.Emit(context.Background(), audit.Event{Type: "service.stopped", Severity: audit.SeverityInfo, Actor: "system:risk"})
	return err
}

// schemaReady checks that the database is reachable, the risk schema is
// migrated, and the connection is app_rw, which never bypasses RLS and
// cannot write versions' bookkeeping columns itself (design §4.4).
func schemaReady(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user string
	var usage, bypass, author bool
	err := pool.QueryRow(ctx, `SELECT current_user, has_schema_privilege('risk', 'USAGE'),
		(SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user),
		has_column_privilege('risk.scenario_version', 'author', 'INSERT')`).Scan(&user, &usage, &bypass, &author)
	switch {
	case err != nil:
		return fmt.Errorf("database: %w", err)
	case user != dbRole:
		return fmt.Errorf("connected as %s, want %s", user, dbRole)
	case !usage:
		return errors.New("risk schema is not usable; run the migrations")
	case bypass:
		return errors.New("app_rw bypasses row-level security; the database roles are wrong (ADR-006)")
	case author:
		return errors.New("app_rw can set a version's author; the database grants are wrong (design §4.4)")
	}
	return nil
}

func connect(ctx context.Context, env string) (*pgxpool.Pool, error) {
	cc, err := dbconn.Config(env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-risk")
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

// registerDefs registers a feature's setting definitions, retrying every
// 30 seconds until it succeeds (posture refuses before the install is
// seeded).
func registerDefs(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, feature string, defs []settings.Def) {
	for {
		err := settings.DBRegistrar{DB: pool}.Register(ctx, feature, version, defs)
		if err == nil {
			return
		}
		logger.Warn("registering settings", "feature", feature, "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// auditSink is the service's own event emitter (F-001 T-37): the audit
// trail first, then the logs (F-002 T-06).
func auditSink(env string, db audit.Beginner) (audit.Emitter, error) {
	e, err := audit.FromEnv(env, "fair-risk", os.Getenv)
	if err != nil {
		return nil, err
	}
	return audit.WithTrail(e, audit.Trail{DB: db}), nil
}

// Command posture runs the security posture service (F-015).
//
// T-08 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, and a
// database pool as app_posture (design §5 access model). The registry,
// change evaluator, exceptions, drift and export arrive with later tasks.
//
//	posture                              run the service
//	posture seed [-profile ID] [-version V]
//	                                     install-time seed from the selected
//	                                     built-in profile (default FedRAMP
//	                                     Moderate; AC-09, AC-10); run once by
//	                                     the installer
//	posture import -pub FILE -dir DIR    load a signed release directory of
//	                                     profile packages (offline; AC-05)
//
// Environment: as for iam (FAIR_ENV, FAIR_DEPLOYMENT_MODE, FAIR_LISTEN_ADDR, FAIR_TLS_*_FILE,
// FAIR_REQUIRE_FIPS, ...), plus FAIR_DB_PASSWORD_FILE (app_posture's password)
// and the libpq connection variables; in SaaS mode FAIR_SECOPS_WEBHOOK_URL and
// FAIR_SECOPS_SECRET_FILE (vendor SecOps notifications, F-015 AC-23).
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// dbRole is the posture service's own login role; it owns nothing and has no
// table privileges (design §5 access model).
const dbRole = "app_posture"

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "seed":
		fs := flag.NewFlagSet("seed", flag.ExitOnError)
		profile := fs.String("profile", posture.DefaultProfile, "built-in profile to seed from")
		version := fs.String("version", "", "profile version (default: the only loaded version)")
		actor := fs.String("actor", "system:installer", "audit actor")
		_ = fs.Parse(os.Args[2:])
		err = seed(*profile, *version, *actor)
	case len(os.Args) > 1 && os.Args[1] == "import":
		fs := flag.NewFlagSet("import", flag.ExitOnError)
		pub := fs.String("pub", "", "PEM release public key file (bundled with the install)")
		dir := fs.String("dir", "", "signed release directory (profilegen sign)")
		actor := fs.String("actor", "system:installer", "audit actor")
		_ = fs.Parse(os.Args[2:])
		if *pub == "" || *dir == "" {
			fmt.Fprintln(os.Stderr, "usage: posture import -pub FILE -dir DIR")
			os.Exit(2)
		}
		err = importDir(*pub, *dir, *actor)
	default:
		err = run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "posture:", err)
		os.Exit(1)
	}
}

// command prepares a one-shot subcommand: configuration, the FIPS check and
// a pool as app_posture.
func command(ctx context.Context) (*pgxpool.Pool, error) {
	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return nil, errors.New("FIPS 140 mode is required but not enabled")
	}
	return connect(ctx, env)
}

func connect(ctx context.Context, env string) (*pgxpool.Pool, error) {
	cc, err := dbconn.Config(env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-posture")
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

func seed(profile, version, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := command(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	s, err := posture.Seed(ctx, pool, audit.NewJSONLines(os.Stdout), actor, profile, version)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "seeded %d settings from %s %s (package %s)\n", s.Settings, s.Profile, s.Version, s.Digest)
	return nil
}

func importDir(pubFile, dir, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pub, err := profilepkg.LoadPublicKey(pubFile)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- operator-named release directory
			if err != nil {
				return err
			}
			files[e.Name()] = b
		}
	}
	pool, err := command(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	res, err := posture.Import(ctx, pool, audit.NewJSONLines(os.Stdout), pub, actor, files)
	if err != nil {
		return err
	}
	for _, r := range res {
		fmt.Fprintf(os.Stderr, "%s %s %s (package %s)\n", r.Outcome, r.Profile, r.Version, r.Digest)
	}
	return nil
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

	pool, err := connect(ctx, cfg.Env)
	if err != nil {
		return err
	}
	defer pool.Close()

	// AC-23: the configured deployment mode must be the one the installer
	// recorded, and SaaS mode needs the SecOps webhook (fail closed).
	secops, err := secOpsSender(ctx, pool, cfg)
	if err != nil {
		return err
	}
	if secops != nil {
		go posture.RunSecOps(ctx, pool, secops, 10*time.Second, func(err error) {
			logger.Error("SecOps notification delivery", "error", err.Error())
		})
	}

	emitter := audit.NewJSONLines(os.Stdout) // replaced by the F-002 pipeline; see pkg/audit
	// AC-25: 14-, 7- and 1-day exception expiry notices.
	go posture.RunNotices(ctx, pool, emitter, time.Minute, func(err error) {
		logger.Error("exception expiry notices", "error", err.Error())
	})
	// AC-27 - AC-29: revert expired exceptions every 10 s (effect within 60 s
	// once caches refresh); failures retry and keep a critical finding open.
	go posture.RunReverts(ctx, pool, emitter, nil, 10*time.Second, func(err error) {
		logger.Error("exception revert", "error", err.Error())
	})
	if err := emitter.Emit(ctx, audit.Event{
		Type:     "service.started",
		Severity: audit.SeverityInfo,
		Actor:    "system:posture",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env,
			"deployment_mode": cfg.DeploymentMode},
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

// secOpsSender checks the deployment mode against the one recorded at
// install (posture.set_deployment_mode) and, in SaaS mode, builds the SecOps
// webhook sender from FAIR_SECOPS_WEBHOOK_URL and FAIR_SECOPS_SECRET_FILE.
// It returns nil outside SaaS mode.
func secOpsSender(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) (posture.SecOpsSender, error) {
	var recorded *string
	if err := pool.QueryRow(ctx, "SELECT posture.deployment_mode()").Scan(&recorded); err != nil {
		return nil, fmt.Errorf("deployment mode: %w", err)
	}
	if err := posture.CheckDeploymentMode(cfg.Env, cfg.DeploymentMode, recorded); err != nil {
		return nil, err
	}
	if cfg.DeploymentMode != config.ModeSaaS {
		return nil, nil
	}
	return posture.NewSecOpsWebhook(cfg.Env, os.Getenv("FAIR_SECOPS_WEBHOOK_URL"), os.Getenv("FAIR_SECOPS_SECRET_FILE"))
}

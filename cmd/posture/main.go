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
//	posture export-key -out FILE -pub FILE
//	                                     generate the installation's OSCAL
//	                                     export signing key (install time,
//	                                     F-015 T-35; no database)
//	posture verify-export -pub FILE -document FILE -statement FILE -signature FILE
//	                                     verify an export as its recipient
//	                                     would (no database)
//
// Environment: as for iam (FAIR_ENV, FAIR_DEPLOYMENT_MODE, FAIR_LISTEN_ADDR, FAIR_TLS_*_FILE,
// FAIR_REQUIRE_FIPS, ...), plus FAIR_DB_PASSWORD_FILE (app_posture's password)
// and the libpq connection variables; in SaaS mode FAIR_SECOPS_WEBHOOK_URL and
// FAIR_SECOPS_SECRET_FILE (vendor SecOps notifications, F-015 AC-23);
// FAIR_EXPORT_SIGNING_KEY_FILE (PEM ECDSA P-256; signs OSCAL exports,
// F-015 AC-47; required in production).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/postureapi"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
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
	case len(os.Args) > 1 && os.Args[1] == "k8s-access":
		// The installer's record of the customer's Kubernetes-access decision
		// (F-015 T-30): grant | decline | request | revoke | status.
		fs := flag.NewFlagSet("k8s-access", flag.ExitOnError)
		reason := fs.String("reason", "", "why access is declined or revoked (required for those)")
		actor := fs.String("actor", posture.InstallerActor, "audit actor")
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: posture k8s-access grant|decline|request|revoke|status [-reason TEXT]")
			os.Exit(2)
		}
		_ = fs.Parse(os.Args[3:])
		err = k8sAccess(os.Args[2], *reason, *actor)
	case len(os.Args) > 1 && os.Args[1] == "export-key":
		fs := flag.NewFlagSet("export-key", flag.ExitOnError)
		out := fs.String("out", "", "private key file to create (PEM PKCS#8, mode 0600)")
		pub := fs.String("pub", "", "public key file to create (PEM PKIX), given to export recipients")
		_ = fs.Parse(os.Args[2:])
		if *out == "" || *pub == "" {
			fmt.Fprintln(os.Stderr, "usage: posture export-key -out FILE -pub FILE")
			os.Exit(2)
		}
		err = exportKey(*out, *pub)
	case len(os.Args) > 1 && os.Args[1] == "verify-export":
		fs := flag.NewFlagSet("verify-export", flag.ExitOnError)
		pub := fs.String("pub", "", "the installation's export public key (PEM)")
		doc := fs.String("document", "", "the OSCAL document")
		st := fs.String("statement", "", "the signed statement")
		sig := fs.String("signature", "", "the signature (base64)")
		_ = fs.Parse(os.Args[2:])
		if *pub == "" || *doc == "" || *st == "" || *sig == "" {
			fmt.Fprintln(os.Stderr, "usage: posture verify-export -pub FILE -document FILE -statement FILE -signature FILE")
			os.Exit(2)
		}
		err = verifyExport(*pub, *doc, *st, *sig)
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

func k8sAccess(cmd, reason, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := command(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	k := posture.K8sAccess{DB: pool, Audit: audit.NewJSONLines(os.Stdout)}
	state := map[string]string{"grant": posture.AccessGranted, "decline": posture.AccessDeclined,
		"request": posture.AccessRequested, "revoke": posture.AccessRevoked}[cmd]
	if cmd != "status" {
		if state == "" {
			return fmt.Errorf("unknown k8s-access command %q", cmd)
		}
		prev, err := k.Decide(ctx, state, reason, actor)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Kubernetes access: %s -> %s\n", orUndecided(prev), state)
	}
	st, err := k.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "state %s, permissions %s (this release %s)\n", st.State, st.Digest, st.CurrentDigest)
	if st.Warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", st.Warning)
	}
	return nil
}

func orUndecided(s string) string {
	if s == "" {
		return posture.AccessUndecided
	}
	return s
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

	// Application drift (F-015 T-25): heartbeats and change events arrive on
	// NATS, which production requires (otherwise check 4 would never run).
	wake := make(chan struct{}, 1)
	// The Posture API's permission checks (T-31): the caller's grants,
	// refreshed on iam.scope.changed and at least every 60 s.
	grants := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	if url := os.Getenv("FAIR_NATS_URL"); url != "" {
		nc, err := natspub.Connect(ctx, natspub.Options{Env: cfg.Env, URL: url, CredsFile: os.Getenv("FAIR_NATS_CREDS_FILE"), Name: "fair-posture"})
		if err != nil {
			return err
		}
		defer nc.Close()
		if _, err := nc.Subscribe(settings.SubjectHeartbeat, func(data []byte) {
			if err := posture.RecordHeartbeat(ctx, pool, data); err != nil && ctx.Err() == nil {
				logger.Warn("settings heartbeat", "error", err.Error())
			}
		}); err != nil {
			return fmt.Errorf("nats: %w", err)
		}
		if _, err := nc.Subscribe(authz.SubjectScopeChanged, func(data []byte) {
			if err := grants.HandleScopeChanged(data); err != nil {
				logger.Warn("scope change event", "error", err.Error())
			}
		}); err != nil {
			return fmt.Errorf("nats: %w", err)
		}
		if _, err := nc.Subscribe(settings.SubjectChanged, func([]byte) {
			select {
			case wake <- struct{}{}:
			default:
			}
		}); err != nil {
			return fmt.Errorf("nats: %w", err)
		}
	} else if cfg.Env == "production" {
		return errors.New("FAIR_NATS_URL is required in production (settings heartbeats for drift detection)")
	}
	go posture.RunDrift(ctx, posture.Drift{DB: pool, Audit: emitter}, 10*time.Second, wake, func(err error) {
		logger.Error("drift scan", "error", err.Error())
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

	// Deployment scan reports from posture-scanner (F-015 T-27): mTLS gRPC.
	// Always on in SaaS mode (AC-38); in self-hosted mode only when the
	// customer granted Kubernetes access (AC-39; the consent model is T-30).
	if addr := os.Getenv("FAIR_SCANNER_GRPC_ADDR"); addr != "" {
		tlsConf, err := posture.ScannerTLS(os.Getenv("FAIR_SCANNER_GRPC_CERT_FILE"), os.Getenv("FAIR_SCANNER_GRPC_KEY_FILE"),
			os.Getenv("FAIR_SCANNER_CLIENT_CA_FILE"))
		if err != nil {
			return err
		}
		lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("scanner channel: %w", err)
		}
		g := posture.NewScannerServer(&posture.ScannerService{DB: pool, Audit: emitter, Identity: os.Getenv("FAIR_SCANNER_IDENTITY"), Logger: logger}, tlsConf)
		go func() {
			if err := g.Serve(lis); err != nil {
				logger.Error("scanner channel", "error", err.Error())
			}
		}()
		defer g.GracefulStop()
	} else if cfg.DeploymentMode == config.ModeSaaS {
		return errors.New("FAIR_SCANNER_GRPC_ADDR is required in SaaS mode: deployment drift detection is always on (F-015 AC-38)")
	}

	srv := server.New(server.Options{
		Addr:        cfg.ListenAddr,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		Plaintext:   cfg.AllowPlaintext,
		Logger:      logger,
	})
	// OSCAL exports are signed with the installation's key (T-35).
	var exportKey *ecdsa.PrivateKey
	if f := os.Getenv("FAIR_EXPORT_SIGNING_KEY_FILE"); f != "" {
		if exportKey, err = profilepkg.LoadPrivateKey(f); err != nil {
			return fmt.Errorf("FAIR_EXPORT_SIGNING_KEY_FILE: %w", err)
		}
		if exportKey.Curve.Params().Name != "P-256" {
			return errors.New("FAIR_EXPORT_SIGNING_KEY_FILE: the export signing key must be ECDSA P-256")
		}
	} else if cfg.Env == "production" {
		return errors.New("FAIR_EXPORT_SIGNING_KEY_FILE is required in production (OSCAL exports are signed, F-015 AC-47)")
	}
	// The Posture API (T-31): internal JWTs verified with the gateway's public
	// keys (FAIR_JWT_KEYS_DIR, required in production).
	if dir := os.Getenv("FAIR_JWT_KEYS_DIR"); dir != "" {
		keys, err := authz.LoadLocalKeys(dir)
		if err != nil {
			return err
		}
		api := &postureapi.API{DB: pool, Authz: grants, Audit: emitter, ExportKey: exportKey}
		srv.Mux().Handle(postureapi.Prefix+"/", server.SecurityHeaders(api.Handler(keys, nil)))
	} else if cfg.Env == "production" {
		return errors.New("FAIR_JWT_KEYS_DIR is required in production (the Posture API verifies the gateway's internal JWTs)")
	}
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

// exportKey creates the installation's export signing key pair. It never
// overwrites a file: replacing a key is a deliberate act (old exports stay
// verifiable only with the old public key).
func exportKey(out, pubOut string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		path, typ string
		der       []byte
		mode      os.FileMode
	}{{out, "PRIVATE KEY", der, 0o600}, {pubOut, "PUBLIC KEY", pubDER, 0o644}} {
		fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode) // #nosec G304 -- operator-chosen output path
		if err != nil {
			return err
		}
		if err := pem.Encode(fh, &pem.Block{Type: f.typ, Bytes: f.der}); err != nil {
			_ = fh.Close()
			return err
		}
		if err := fh.Close(); err != nil {
			return err
		}
	}
	kid, err := posture.KeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Println("export signing key", kid)
	return nil
}

// verifyExport checks a downloaded export against the installation's
// public key.
func verifyExport(pubFile, docFile, stFile, sigFile string) error {
	pub, err := profilepkg.LoadPublicKey(pubFile)
	if err != nil {
		return err
	}
	var b [3][]byte
	for i, f := range []string{docFile, stFile, sigFile} {
		if b[i], err = os.ReadFile(f); err != nil { // #nosec G304 -- operator-supplied files
			return err
		}
	}
	if err := posture.VerifyExport(pub, b[0], b[1], strings.TrimSpace(string(b[2]))); err != nil {
		return err
	}
	fmt.Println("export verified")
	return nil
}

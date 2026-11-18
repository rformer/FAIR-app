// Command integrate runs the integrate service (F-011): it holds the
// connectors' configuration and sealed credentials, runs scheduled
// connector fetches and submits their batches through the gateway as each
// integration's service account (design §1, §3.3). It is the only service
// with egress to the hosts integration.allowed_hosts names
// (deploy/k8s/integrate.yaml); it never writes risk data itself.
//
// T-15 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, a
// database pool as app_integrate, the install checks of design §11, F-011's
// settings registered, and leader election (one replica leads). T-16: the
// integrations API (internal/integrateapi), served by every replica. T-17:
// the connectors (integration.Fetcher, also the API's tests) and the
// connector runner on the leader, submitting through the gateway.
//
// Environment: as for every service (FAIR_ENV, FAIR_DEPLOYMENT_MODE,
// FAIR_LISTEN_ADDR, FAIR_TLS_CERT_FILE, FAIR_TLS_KEY_FILE, FAIR_REQUIRE_FIPS,
// ...), plus:
//
//	FAIR_DB_PASSWORD_FILE         app_integrate's password (and the libpq variables)
//	FAIR_JWT_KEYS_DIR             the gateway's internal-JWT public keys, for the
//	                              integrations API; required in production
//	FAIR_INTEGRATE_SECRETS_DIR    the connector-credentials keys (iam keys init or
//	                              upgrade); required in production
//	FAIR_INTEGRATE_GATEWAY_URL    the gateway's https URL connectors submit to;
//	                              required in production
//	FAIR_INTEGRATE_GATEWAY_CA_FILE the CA of the gateway's certificate (optional)
//	FAIR_INTEGRATE_CA_FILE        CAs of the sources' certificates, added to the
//	                              system's (optional)
//	FAIR_INTEGRATE_CLUSTER_CIDRS  the cluster's pod and service ranges, never a
//	                              source; required in production
//	POD_NAME                      this replica's name, in leader logs
package main

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/integrateapi"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const dbRole = "app_integrate"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "integrate:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "integrate", "version", version)
	slog.SetDefault(logger)

	cfg, err := config.Load("integrate")
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
	if err := integration.CheckInstall(integration.InstallCheck{Env: cfg.Env, Mode: cfg.DeploymentMode, Getenv: os.Getenv}); err != nil {
		return err
	}
	var keyring *integration.Keyring
	if dir := os.Getenv("FAIR_INTEGRATE_SECRETS_DIR"); dir != "" {
		ks, err := keys.IntegrateSecretKeys(dir)
		if err != nil || len(ks) == 0 {
			return fmt.Errorf("FAIR_INTEGRATE_SECRETS_DIR: no connector-credentials key (%v)", err)
		}
		if keyring, err = integration.NewKeyring(ks); err != nil {
			return fmt.Errorf("FAIR_INTEGRATE_SECRETS_DIR: %w", err)
		}
		logger.Info("connector-credentials keys", "keys", len(ks))
	} else {
		logger.Warn("no connector-credentials keys (FAIR_INTEGRATE_SECRETS_DIR): credentials cannot be set")
	}
	var cluster []netip.Prefix
	if s := os.Getenv("FAIR_INTEGRATE_CLUSTER_CIDRS"); s != "" {
		if cluster, err = notify.ParsePrefixes(s); err != nil {
			return fmt.Errorf("FAIR_INTEGRATE_CLUSTER_CIDRS: %w", err)
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
	if err := emitter.Emit(ctx, audit.Event{Type: "service.started", Severity: audit.SeverityInfo, Actor: "system:integrate",
		Attributes: map[string]string{"fips140": fmt.Sprint(fips140.Enabled()), "env": cfg.Env, "deployment_mode": cfg.DeploymentMode}}); err != nil {
		return fmt.Errorf("audit: %w", err) // audit failures fail closed (ADR-006)
	}

	// F-011's settings (design §4): registered with posture (retried until
	// the install is seeded) and read as every service reads settings.
	replica := os.Getenv("POD_NAME")
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "integrate", Instance: replica})
	if err := sc.Register(settings.F011Defs()...); err != nil {
		return err
	}
	go registerF011(ctx, pool, logger)
	if err := sc.Refresh(ctx); err != nil {
		logger.Warn("settings not loaded yet; defaults apply until they are", "error", err.Error())
	}
	go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })

	// Sources pass the guard (design §3.1, AC-04): integration.allowed_hosts
	// as in force, the cluster's ranges refused, private ranges only when
	// air-gapped; their certificates verified against the system's roots
	// and FAIR_INTEGRATE_CA_FILE.
	guard := egress.Guard{Setting: settings.KeyIntegrationAllowedHosts, Cluster: cluster, AirGapped: cfg.DeploymentMode == config.ModeAirGapped,
		Allowed: func() []string {
			hosts, err := sc.Set(settings.KeyIntegrationAllowedHosts, "")
			if err != nil {
				return nil // nothing is allowed until the setting is read
			}
			return hosts
		}}
	sourceTLS, err := tlsWithCA(os.Getenv("FAIR_INTEGRATE_CA_FILE"), true)
	if err != nil {
		return fmt.Errorf("FAIR_INTEGRATE_CA_FILE: %w", err)
	}
	fetcher := integration.Fetcher{Guard: guard, TLS: sourceTLS}

	// One replica leads (design §3.3): every 30 seconds it claims due
	// connector integrations, fetches them and submits each batch through
	// the gateway as the integration's service account (T-17).
	var runner *integration.Runner
	if gw := os.Getenv("FAIR_INTEGRATE_GATEWAY_URL"); gw != "" && keyring != nil {
		u, err := integration.GatewayURL(gw)
		if err != nil {
			return err
		}
		gwTLS, err := tlsWithCA(os.Getenv("FAIR_INTEGRATE_GATEWAY_CA_FILE"), false)
		if err != nil {
			return fmt.Errorf("FAIR_INTEGRATE_GATEWAY_CA_FILE: %w", err)
		}
		client := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil, TLSClientConfig: gwTLS, TLSHandshakeTimeout: 10 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		runner = &integration.Runner{DB: pool, Keys: keyring, Fetch: fetcher, Submit: integration.GatewaySubmitter{URL: u, Client: client}}
	} else {
		logger.Warn("connectors do not run: they need FAIR_INTEGRATE_GATEWAY_URL and the connector-credentials keys")
	}
	leader := auditsvc.Leader{Pool: pool, Key: integration.LeaderLockKey, OnChange: func(leading bool) {
		logger.Info("leader", "leading", leading, "replica", replica)
	}}
	// T-17b: the leader also purges staged records past
	// integration.records_retention_days, daily.
	purger := integration.Purger{DB: pool, Retention: func() (int, error) {
		return sc.Int(settings.KeyIntegrationRecordRetention, "")
	}}
	go leader.Run(ctx, func(ctx context.Context) error {
		go func() { _ = purger.Run(ctx, func(err error) { logger.Error("purging staged records", "error", err.Error()) }) }()
		if runner == nil {
			<-ctx.Done()
			return ctx.Err()
		}
		return runner.Run(ctx, 30*time.Second, func(err error) { logger.Error("connector run", "error", err.Error()) })
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

	// The integrations API (T-16): every replica serves it.
	if dir := os.Getenv("FAIR_JWT_KEYS_DIR"); dir != "" {
		jwtKeys, err := authz.LoadLocalKeys(dir)
		if err != nil {
			return fmt.Errorf("FAIR_JWT_KEYS_DIR: %w", err)
		}
		api := &integrateapi.API{DB: pool, Keys: keyring, Guard: guard, Tester: fetcher}
		h := server.SecurityHeaders(api.Handler(jwtKeys, nil))
		for _, prefix := range integrateapi.Prefixes {
			srv.Mux().Handle(prefix, h)
			srv.Mux().Handle(prefix+"/", h)
		}
	} else {
		logger.Warn("the integrations API is off: it needs the gateway's JWT keys (FAIR_JWT_KEYS_DIR)")
	}

	err = srv.Run(ctx, cfg.ShutdownTimeout)
	_ = emitter.Emit(context.Background(), audit.Event{Type: "service.stopped", Severity: audit.SeverityInfo, Actor: "system:integrate"})
	return err
}

// tlsWithCA is a TLS 1.2+ client configuration whose roots are the CA file's
// certificates, added to the system's when withSystem (no file: the
// system's).
func tlsWithCA(file string, withSystem bool) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if file == "" {
		return c, nil
	}
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if withSystem {
		if sys, err := x509.SystemCertPool(); err == nil {
			pool = sys
		}
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate in the file")
	}
	c.RootCAs = pool
	return c, nil
}

// schemaReady checks that the database is reachable, the integration schema
// is migrated, and the connection really is the locked-down role: it may
// use the schema but read no integration table directly (design §5).
func schemaReady(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user string
	var usage, direct bool
	err := pool.QueryRow(ctx, `SELECT current_user, has_schema_privilege('integration', 'USAGE'),
		has_table_privilege('integration.integration', 'SELECT') OR has_table_privilege('integration.secret', 'SELECT') OR has_table_privilege('integration.run', 'SELECT')`).
		Scan(&user, &usage, &direct)
	switch {
	case err != nil:
		return fmt.Errorf("database: %w", err)
	case user != dbRole:
		return fmt.Errorf("connected as %s, want %s", user, dbRole)
	case !usage:
		return errors.New("integration schema is not usable; run the migrations")
	case direct:
		return errors.New("app_integrate can read integration tables directly; the database grants are wrong (design §5)")
	}
	return nil
}

func connect(ctx context.Context, env string) (*pgxpool.Pool, error) {
	cc, err := dbconn.Config(env, dbRole, os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-integrate")
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
	e, err := audit.FromEnv(env, "fair-integrate", os.Getenv)
	if err != nil {
		return nil, err
	}
	return audit.WithTrail(e, audit.Trail{DB: db}), nil
}

// registerF011 registers F-011's setting definitions, retrying every 30
// seconds until it succeeds (posture refuses before the install is seeded).
func registerF011(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	for {
		err := settings.DBRegistrar{DB: pool}.Register(ctx, "F-011", version, settings.F011Defs())
		if err == nil {
			return
		}
		logger.Warn("registering F-011 settings", "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

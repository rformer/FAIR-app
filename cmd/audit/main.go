// Command audit runs the audit service (F-002): the tamper-evident audit
// trail's sequencer, checkpoints, verification, forwarding, retention and
// API (design §2).
//
// T-05 scaffold: hardened server with health and readiness, FIPS
// enforcement, structured logging, audit emission of lifecycle events, a
// database pool as app_audit, the install checks of design §7, and leader
// election (one replica leads). The leader sequences the trail (T-07),
// closes segments with signed checkpoints every 15 minutes (T-09), and
// verifies the trail every 15 minutes and in full daily (T-11), and
// forwards it to the syslog (T-16) and OTLP (T-17) destinations, and
// archives segments past the online retention (T-18), applies legal holds
// and destroys what is past the total retention (T-19). Every
// replica serves the Audit API (T-12) and works the evidence export queue
// (T-15, River in schema audit_river).
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
//	                                 required in SaaS (F-002 AC-10), with
//	                                 FAIR_AUDIT_WORM_ENDPOINT, _REGION,
//	                                 _ACCESS_KEY_FILE, _SECRET_KEY_FILE,
//	                                 _CA_FILE (internal/objstore)
//	FAIR_AUDIT_STORE_BUCKET          the audit store: evidence export bundles
//	                                 (T-15) and, from T-18, archives; required
//	                                 in production, with FAIR_AUDIT_STORE_
//	                                 ENDPOINT, _REGION, _ACCESS_KEY_FILE,
//	                                 _SECRET_KEY_FILE, _CA_FILE (versioning
//	                                 and Object Lock, as for the WORM bucket);
//	                                 bundles are spooled in TMPDIR first
//	FAIR_AUDIT_SYSLOG_CA_FILE        the syslog destination's CA (T-16; else the
//	                                 system roots). The destination itself is
//	                                 the setting audit.syslog_destination
//	                                 (F-015); FAIR_AUDIT_SYSLOG_PLAINTEXT=true
//	                                 (plain TCP) is for development only
//	FAIR_AUDIT_OTLP_CA_FILE          the OTLP destination's CA (T-17; the
//	                                 destination is audit.otlp_destination);
//	                                 FAIR_AUDIT_OTLP_PLAINTEXT=true for
//	                                 development only
//	FAIR_AUDIT_STORAGE_QUOTA         the audit trail's storage quota (T-20; e.g.
//	                                 200GiB): alerts at 75% and 90%, and at
//	                                 100% other services' events are refused;
//	                                 required in production
//	FAIR_NATS_URL                    NATS, for scope changes (the API's grant
//	                                 cache otherwise refreshes on its own);
//	                                 FAIR_NATS_CREDS_FILE optional
//	POD_NAME                         this replica's name, in leader logs
package main

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/rformer/fair-app/internal/auditapi"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/objstore"
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
	// The checkpoint key (T-09). Outside production a missing key means no
	// checkpoints; production refuses to start without one (CheckInstall).
	var cpKey *ecdsa.PrivateKey
	if dir := os.Getenv("FAIR_AUDIT_CHECKPOINT_KEYS_DIR"); dir != "" {
		k, id, err := keys.CheckpointKey(dir)
		if err != nil {
			return fmt.Errorf("FAIR_AUDIT_CHECKPOINT_KEYS_DIR: %w", err)
		}
		cpKey = k
		logger.Info("checkpoint signing key", "key", id)
	} else {
		logger.Warn("no checkpoint key (FAIR_AUDIT_CHECKPOINT_KEYS_DIR): segments are not checkpointed")
	}
	// Write-once copies of checkpoints (AC-10), required in SaaS.
	var worm *objstore.Store
	if os.Getenv("FAIR_AUDIT_WORM_BUCKET") != "" {
		s, err := objstore.New(objstore.FromEnv("FAIR_AUDIT_WORM", cfg.Env, os.Getenv))
		if err != nil {
			return fmt.Errorf("FAIR_AUDIT_WORM: %w", err)
		}
		worm = s
	}
	// The audit store (T-15): export bundles.
	var store *objstore.Store
	if os.Getenv("FAIR_AUDIT_STORE_BUCKET") != "" {
		s, err := objstore.New(objstore.FromEnv("FAIR_AUDIT_STORE", cfg.Env, os.Getenv))
		if err != nil {
			return fmt.Errorf("FAIR_AUDIT_STORE: %w", err)
		}
		store = s
	}
	// The storage quota (T-20; required in production, CheckInstall).
	var quota int64
	if q := os.Getenv("FAIR_AUDIT_STORAGE_QUOTA"); q != "" {
		if quota, err = auditsvc.ParseSize(q); err != nil {
			return fmt.Errorf("FAIR_AUDIT_STORAGE_QUOTA: %w", err)
		}
	}
	// The syslog forwarder's TLS (T-16): TLS 1.2 or later; plain TCP only in
	// development.
	syslogTLS, err := auditsvc.SyslogTLS(cfg.Env, os.Getenv)
	if err != nil {
		return err
	}
	otlpTLS, err := auditsvc.OTLPTLS(cfg.Env, os.Getenv)
	if err != nil {
		return err
	}
	// The Audit API (T-12) verifies the gateway's internal JWTs.
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
	if worm != nil {
		if err := worm.CheckBucket(ctx); err != nil {
			return fmt.Errorf("FAIR_AUDIT_WORM_BUCKET: %w", err) // not write-once: refuse (AC-10)
		}
	}
	if store != nil {
		if err := store.CheckBucket(ctx); err != nil {
			return fmt.Errorf("FAIR_AUDIT_STORE_BUCKET: %w", err)
		}
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
	// The API's step-up and network-binding checks read F-001's settings.
	for _, d := range settings.F001Defs() {
		if d.Key == settings.KeySessionNetworkBinding || d.Key == settings.KeyBUReauthMaxAge {
			if err := sc.Register(d); err != nil {
				return err
			}
		}
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
	// ...and closes segments with signed checkpoints (T-09).
	var cp *auditsvc.Checkpointer
	if cpKey != nil {
		cp = &auditsvc.Checkpointer{DB: pool, Key: cpKey, Audit: emitter, WORM: worm, Retain: func() time.Duration {
			d, err := sc.Duration(settings.KeyAuditRetentionTotal, "")
			if err != nil {
				return 7 * 365 * 24 * time.Hour // the longest built-in retention
			}
			return d
		}}
		if err := cp.RegisterKey(ctx); err != nil {
			return err
		}
	}
	leader := auditsvc.Leader{Pool: pool, OnChange: func(leading bool) {
		logger.Info("leader", "leading", leading, "replica", replica)
	}}
	// ...and verifies the trail continuously (T-11).
	ver := auditsvc.Verifier{DB: pool, Audit: emitter, WORM: worm}
	if store != nil {
		ver.Archive = store // archived segments (T-18)
	}
	// ...and forwards it to the SIEM destinations named by the settings
	// audit.syslog_destination (T-16) and audit.otlp_destination (T-17);
	// air-gapped installs send inside the enclave only (design §7).
	host, _ := os.Hostname()
	thresholds := func() (int, time.Duration) {
		n, err := sc.Int(settings.KeyAuditBacklogRecords, "")
		if err != nil {
			n = 10_000 // the default of every built-in profile
		}
		d, err := sc.Duration(settings.KeyAuditBacklogAge, "")
		if err != nil {
			d = 15 * time.Minute
		}
		return n, d
	}
	internalOnly := auditsvc.DestinationCheck(cfg.DeploymentMode, nil)
	forwarders := []*auditsvc.Forwarder{
		{DB: pool, Audit: emitter, Name: auditsvc.SyslogDestination, Transport: &auditsvc.SyslogTransport{TLS: syslogTLS, Hostname: host},
			Address: func() (string, error) { return sc.Enum(settings.KeyAuditSyslogDestination, "") }, Thresholds: thresholds, Check: internalOnly},
		{DB: pool, Audit: emitter, Name: auditsvc.OTLPDestination, Transport: &auditsvc.OTLPTransport{TLS: otlpTLS, Hostname: host},
			Address: func() (string, error) { return sc.Enum(settings.KeyAuditOTLPDestination, "") }, Thresholds: thresholds, Check: internalOnly},
	}
	loops := []func(context.Context) error{
		func(ctx context.Context) error {
			return seq.Run(ctx, 0, func(err error) { logger.Error("sequencer", "error", err.Error()) })
		},
		func(ctx context.Context) error {
			return ver.Run(ctx, 0, 0, func(r auditsvc.VerifyResult) {
				if r.OK {
					logger.Info("audit trail verified", "kind", r.Kind, "to_seq", r.ToSeq, "to_segment", r.ToSegment, "finding", r.Finding)
				} else {
					logger.Error("audit trail verification failed", "kind", r.Kind, "seq", r.FailedSeq, "segment", r.FailedSegment, "reason", r.Reason)
				}
			}, func(err error) { logger.Error("verification", "error", err.Error()) })
		},
	}
	for _, f := range forwarders {
		loops = append(loops, func(ctx context.Context) error {
			return f.Run(ctx, 0, func(err error) { logger.Error("forwarding", "destination", f.Name, "error", err.Error()) })
		})
	}
	if cp != nil {
		loops = append(loops, func(ctx context.Context) error {
			return cp.Run(ctx, 0, func(err error) { logger.Error("checkpoint", "error", err.Error()) })
		})
	}
	// ...and measures audit storage against the quota (T-20).
	if quota > 0 {
		capm := auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: quota}
		loops = append(loops, func(ctx context.Context) error {
			return capm.Run(ctx, 0, func(err error) { logger.Error("capacity", "error", err.Error()) })
		})
	} else {
		logger.Warn("audit storage is not measured: set FAIR_AUDIT_STORAGE_QUOTA")
	}
	// ...and moves segments past the online retention to the archive (T-18).
	if store != nil {
		arc := auditsvc.Archiver{DB: pool, Store: store, Audit: emitter, Retention: func() (time.Duration, time.Duration) {
			online, err := sc.Duration(settings.KeyAuditRetentionOnline, "")
			if err != nil {
				online = 365 * 24 * time.Hour // the default of every built-in profile
			}
			total, err := sc.Duration(settings.KeyAuditRetentionTotal, "")
			if err != nil {
				total = 2557 * 24 * time.Hour
			}
			return online, total
		}}
		loops = append(loops, func(ctx context.Context) error {
			return arc.Run(ctx, 0, func(err error) { logger.Error("archive", "error", err.Error()) })
		})
		// ...and applies legal holds and destroys what is past the total
		// retention (T-19).
		ret := auditsvc.Retainer{DB: pool, Store: store, Audit: emitter, Retention: arc.Retention}
		loops = append(loops, func(ctx context.Context) error {
			return ret.Run(ctx, 0, func(err error) { logger.Error("retention", "error", err.Error()) })
		})
	} else {
		logger.Warn("archiving is off: it needs the audit store (FAIR_AUDIT_STORE_BUCKET)")
	}
	go leader.Run(ctx, func(ctx context.Context) error { return runAll(ctx, loops) },
		func(err error) { logger.Error("leader", "error", err.Error()) })

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

	// The Audit API (T-12): every replica serves it.
	if jwtKeys != nil {
		grants := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool),
			NetworkBinding: func(bu string) (string, error) { return sc.Enum(settings.KeySessionNetworkBinding, bu) },
			ReauthMaxAge:   sc.ReauthMaxAge})
		if url := os.Getenv("FAIR_NATS_URL"); url != "" {
			nc, err := natspub.Connect(ctx, natspub.Options{Env: cfg.Env, URL: url, CredsFile: os.Getenv("FAIR_NATS_CREDS_FILE"), Name: "fair-audit"})
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
		api := &auditapi.API{DB: pool, Authz: grants, Audit: emitter}
		// Evidence exports (T-15): with a checkpoint key and the audit store.
		if cp != nil && store != nil {
			exporter := &auditsvc.Exporter{DB: pool, Checkpointer: cp, Store: store, Archives: store, Audit: emitter}
			rc, err := auditsvc.NewExportClient(pool, exporter, logger)
			if err != nil {
				return fmt.Errorf("export jobs: %w", err)
			}
			if err := rc.Start(ctx); err != nil {
				return fmt.Errorf("export jobs: %w", err)
			}
			defer func() {
				sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = rc.Stop(sctx)
			}()
			api.Enqueue, api.Bundles = auditsvc.Enqueuer(rc), store
		} else {
			logger.Warn("evidence exports are off: they need the checkpoint key and the audit store (FAIR_AUDIT_STORE_BUCKET)")
		}
		srv.Mux().Handle(auditapi.Prefix+"/", server.SecurityHeaders(api.Handler(jwtKeys, nil)))
	}

	err = srv.Run(ctx, cfg.ShutdownTimeout)
	_ = emitter.Emit(context.Background(), audit.Event{Type: "service.stopped", Severity: audit.SeverityInfo, Actor: "system:audit"})
	return err
}

// runAll runs loops until ctx ends or one of them stops, which stops the
// others (leadership lost or the database gone: the leader retries).
func runAll(ctx context.Context, loops []func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, len(loops))
	for _, l := range loops {
		go func() {
			defer cancel()
			done <- l(ctx)
		}()
	}
	errs := make([]error, 0, len(loops))
	for range loops {
		errs = append(errs, <-done)
	}
	return errors.Join(errs...)
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

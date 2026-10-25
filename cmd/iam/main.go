// Command iam is the identity, BU hierarchy and RBAC service (F-001).
//
//	iam serve     run the HTTP service (default)
//	iam migrate   apply database migrations as app_migrator
//	iam version   print the build version
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/iam/config"
	"github.com/rformer/fair-app/internal/iam/server"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/internal/platform/health"
	"github.com/rformer/fair-app/internal/platform/otelx"
	"github.com/rformer/fair-app/migrations"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "dev-" + s.Value[:12]
			}
		}
	}
	return version
}

var systemActor = audit.Actor{Kind: audit.ActorSystem, ID: "system:iam"}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("service", "iam")
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "migrate":
		err = runMigrate(log)
	case "version":
		fmt.Println(buildVersion())
	default:
		err = fmt.Errorf("unknown command %q (want serve, migrate or version)", cmd)
	}
	if err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func buildAudit(ctx context.Context, cfg config.Config) (*audit.Multi, func(context.Context) error, error) {
	m := audit.NewMulti()
	var natsPing func(context.Context) error
	for _, s := range cfg.AuditSinks {
		switch s {
		case "log":
			m.Add("log", audit.NewWriterSink(os.Stdout))
		case "nats":
			ns, err := audit.DialNATS(ctx, cfg.NATSURL, "audit")
			if err != nil {
				return nil, nil, err
			}
			m.Add("nats", ns)
			natsPing = ns.Ping
		case "otlp":
			m.Add("otlp", audit.NewOTLPSink(audit.OTLPConfig{Endpoint: cfg.AuditOTLP, ServiceName: "iam"}))
		case "syslog":
			ss, err := audit.NewSyslogSink(audit.SyslogConfig{Network: cfg.SyslogNetwork, Addr: cfg.SyslogAddr, AppName: "fair-iam"})
			if err != nil {
				return nil, nil, err
			}
			m.Add("syslog", ss)
		}
	}
	return m, natsPing, nil
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ver := buildVersion()

	em, natsPing, err := buildAudit(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = em.Close(context.WithoutCancel(ctx)) }()

	profile, _ := settings.LookupProfile(cfg.Profile)
	st, err := settings.New(ctx, settings.Config{Profile: profile, Defs: settings.AllDefs(), Audit: em})
	if err != nil {
		return err
	}

	// Hard floor: FIPS mode is mandatory under FedRAMP- and CMMC-derived
	// profiles (ADR-006). Refuse to start rather than run out of compliance.
	if fipsReq, _ := st.Bool("crypto.fips_required"); fipsReq && !fips140.Enabled() {
		e := audit.New("service.start_refused", audit.SeverityCritical, audit.OutcomeDenied, systemActor,
			audit.Target{Kind: "service", ID: "iam"})
		e.Reason = "profile requires FIPS 140 mode but the binary is not running in FIPS mode (build with GOFIPS140 or set GODEBUG=fips140=on)"
		_ = em.Emit(ctx, e)
		return errors.New(e.Reason)
	}

	shutdownOtel, otelOn, err := otelx.Setup(ctx, "iam", ver)
	if err != nil {
		return err
	}
	defer func() { _ = shutdownOtel(context.WithoutCancel(ctx)) }()

	reg := health.New(2*time.Second, log)
	if cfg.DatabaseURL != "" {
		pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer pool.Close()
		reg.Add("database", pool.Ping)
	} else {
		log.Warn("IAM_DATABASE_URL not set; running without a database (Phase 0 only)")
	}
	if natsPing != nil {
		reg.Add("nats", natsPing)
	}

	// Expired setting exceptions revert automatically (ADR-006 Amendment 1).
	go func() {
		t := time.NewTicker(cfg.RevertInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if keys, err := st.RevertExpired(ctx); err != nil {
					log.Error("exception revert failed; will retry", "error", err)
				} else if len(keys) > 0 {
					log.Warn("expired setting exceptions reverted", "keys", keys)
				}
			}
		}
	}()

	srv := server.New(cfg.HTTPAddr, server.Handler(server.Deps{Log: log, Health: reg, Version: ver, Profile: st.Profile()}))
	errCh := make(chan error, 1)
	go func() {
		log.Info("iam listening", "addr", cfg.HTTPAddr, "version", ver, "profile", st.Profile(),
			"fips140", fips140.Enabled(), "otel_export", otelOn, "audit_sinks", cfg.AuditSinks)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	started := audit.New("service.started", audit.SeverityInfo, audit.OutcomeSuccess, systemActor, audit.Target{Kind: "service", ID: "iam"})
	started.Attributes = map[string]string{"version": ver, "profile": st.Profile(), "fips140": fmt.Sprint(fips140.Enabled())}
	if err := em.Emit(ctx, started); err != nil {
		return fmt.Errorf("audit unavailable at startup: %w", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	err = srv.Shutdown(sctx)
	stopped := audit.New("service.stopped", audit.SeverityInfo, audit.OutcomeSuccess, systemActor, audit.Target{Kind: "service", ID: "iam"})
	_ = em.Emit(sctx, stopped)
	return err
}

func runMigrate(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.MigratorURL == "" {
		return errors.New("IAM_MIGRATOR_DATABASE_URL (or _FILE) is required for migrate")
	}
	migs, err := migrate.Load(migrations.FS)
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, cfg.MigratorURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	em, _, err := buildAudit(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = em.Close(context.WithoutCancel(ctx)) }()

	ran, err := migrate.Up(ctx, conn, migs, log)
	outcome := audit.OutcomeSuccess
	sev := audit.SeverityMedium
	if err != nil {
		outcome, sev = audit.OutcomeFailure, audit.SeverityHigh
	}
	e := audit.New("db.migrated", sev, outcome, systemActor, audit.Target{Kind: "database", ID: "fair"})
	e.Attributes = map[string]string{"applied": fmt.Sprint(ran), "version": buildVersion()}
	if err != nil {
		e.Reason = err.Error()
	}
	if aerr := em.Emit(ctx, e); aerr != nil {
		return errors.Join(err, aerr)
	}
	if err != nil {
		return err
	}
	log.Info("migrations complete", "applied", ran)
	return nil
}

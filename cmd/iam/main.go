// Command iam runs the identity and access service (F-001).
//
// Phase 0: hardened server skeleton with health/readiness, FIPS enforcement,
// structured logging, and audit emission of lifecycle events. Domain modules
// (authn, scim, directory, org, access, approvals, reviews) arrive in Phases 1–4.
package main

import (
	"context"
	"crypto/fips140"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
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

	err = srv.Run(ctx, cfg.ShutdownTimeout)

	_ = emitter.Emit(context.Background(), audit.Event{
		Type:     "service.stopped",
		Severity: audit.SeverityInfo,
		Actor:    "system:iam",
	})
	return err
}

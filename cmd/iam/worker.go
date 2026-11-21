package main

import (
	"context"
	"crypto/fips140"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/pkg/telemetry"
)

// runWorker implements `iam worker` (F-001 T-08): the scope worker that keeps
// materialized user scope current and delivers iam.scope.changed and audit
// events.
//
// Environment: FAIR_ENV (default production), FAIR_REQUIRE_FIPS,
// FAIR_DB_PASSWORD_FILE (app_rw), the libpq connection variables,
// FAIR_NATS_URL and optional FAIR_NATS_CREDS_FILE.
func runWorker() int {
	logger := slog.New(telemetry.Logs(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))).
		With("service", "iam", "command", "worker", "version", version)
	// F-012 T-09: metrics and traces when FAIR_OTEL_ENDPOINT is set (off otherwise).
	tel, err := telemetry.Setup(context.Background(), "iam-worker", version)
	if err != nil {
		logger.Error("telemetry", "error", err.Error())
		return 1
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()
	if err := worker(logger); err != nil {
		logger.Error("worker stopped", "error", err.Error())
		return 1
	}
	return 0
}

func worker(logger *slog.Logger) error {
	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return fmt.Errorf("FIPS 140 mode is required but not enabled")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cc, err := dbconn.Config(env, "app_rw", os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-scope-worker")
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

	pub, err := natspub.Connect(ctx, natspub.Options{
		Env: env, URL: os.Getenv("FAIR_NATS_URL"), CredsFile: os.Getenv("FAIR_NATS_CREDS_FILE"),
		Name: "fair-scope-worker", Subjects: scope.Subjects,
	})
	if err != nil {
		return err
	}
	defer pub.Close()

	// The worker's database functions record their audit events to the
	// trail themselves (F-002 T-06); it relays only the NATS topics.
	w := scope.New(scope.Options{Pool: pool, Publisher: pub, Logger: logger})
	client, err := w.RiverClient()
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("river: %w", err)
	}
	logger.Info("scope worker started")
	<-ctx.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return client.Stop(stopCtx)
}

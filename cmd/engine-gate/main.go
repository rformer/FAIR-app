// Command engine-gate terminates the simulation engine's mutual TLS (F-005
// T-10, design §2, §11; ADR-013). It runs as a second container in the
// engine pod (deploy/k8s/engine.yaml), built with the platform's FIPS 140
// module, and forwards authenticated connections to the engine's Unix
// socket; the engine itself listens on no network port.
//
// Configuration (environment):
//
//	FAIR_ENV                  production (default) requires FIPS 140 mode and the keys below
//	FAIR_ENGINE_GATE_TLS_DIR  tls.crt, tls.key and client.sha256 (internal/keys: engine-gate/tls)
//	FAIR_ENGINE_SOCKET        the engine's socket (default /run/engine/engine.sock)
//	FAIR_ENGINE_GATE_ADDR     the mTLS listener (default :8444)
//	FAIR_ENGINE_HEALTH_ADDR   the probes' plain HTTP listener (default :8081)
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rformer/fair-app/internal/enginegate"
	"github.com/rformer/fair-app/internal/enginetls"
	"github.com/rformer/fair-app/internal/keys"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "engine-gate:", err)
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "engine-gate", "version", version)
	env := getenv("FAIR_ENV", "production")
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled")
	}
	socket := getenv("FAIR_ENGINE_SOCKET", enginegate.SocketPath)
	lookup := func(k string) string {
		if k == "FAIR_ENGINE_SOCKET" {
			return socket
		}
		return os.Getenv(k)
	}
	if err := enginegate.CheckInstall(enginegate.InstallCheck{Env: env, Getenv: lookup}); err != nil {
		return err
	}
	if err := keys.CheckMounted(env, os.Getenv); err != nil {
		return err
	}
	conf, err := enginetls.ServerConfig(os.Getenv("FAIR_ENGINE_GATE_TLS_DIR"), time.Now)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", getenv("FAIR_ENGINE_GATE_ADDR", enginegate.ListenAddr))
	if err != nil {
		return err
	}
	health := &http.Server{
		Addr:              getenv("FAIR_ENGINE_HEALTH_ADDR", enginegate.HealthAddr),
		Handler:           enginegate.Health(socket),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("engine-gate: health listener", "error", err.Error())
			stop()
		}
	}()
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = health.Shutdown(sctx)
	}()
	logger.Info("engine-gate: serving", "addr", ln.Addr().String(), "socket", socket)
	g := &enginegate.Gate{TLS: conf, Socket: socket, Log: logger}
	return g.Serve(ctx, ln)
}

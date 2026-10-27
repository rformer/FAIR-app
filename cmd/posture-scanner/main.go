// Command posture-scanner is the deployment drift scanner (F-015 T-27,
// design §6.8). It runs in its own Deployment with its own ServiceAccount
// and read-only RBAC (deploy/k8s/posture-scanner.yaml), reads the cluster
// through internal/scanner/kube, and reports scans to the posture service
// over mTLS gRPC.
//
// Configuration (environment):
//
//	FAIR_ENV                    production (default) requires FIPS 140 mode
//	FAIR_POSTURE_GRPC_ADDR      posture's scanner channel, e.g. posture.fair-platform:9443
//	FAIR_POSTURE_SERVER_NAME    TLS name of posture (default: the host of the address)
//	FAIR_POSTURE_CA_FILE        CA that signed posture's certificate
//	FAIR_SCANNER_TLS_CERT_FILE  the scanner's client certificate (URI SAN spiffe://fair-platform/posture-scanner)
//	FAIR_SCANNER_TLS_KEY_FILE   its key
//	FAIR_PLATFORM_NAMESPACES    comma-separated platform namespaces (default fair-platform)
//	FAIR_SCAN_INTERVAL          default 15m
//	POD_NAME                    instance name (downward API)
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "posture-scanner:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "posture-scanner", "version", version)
	env := getenv("FAIR_ENV", "production")
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled")
	}
	addr := os.Getenv("FAIR_POSTURE_GRPC_ADDR")
	if addr == "" {
		return errors.New("FAIR_POSTURE_GRPC_ADDR is required")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("FAIR_POSTURE_GRPC_ADDR: %w", err)
	}
	interval, err := time.ParseDuration(getenv("FAIR_SCAN_INTERVAL", "15m"))
	if err != nil || interval < time.Minute {
		return fmt.Errorf("FAIR_SCAN_INTERVAL must be a duration of at least 1m: %q", os.Getenv("FAIR_SCAN_INTERVAL"))
	}
	tlsConf, err := scanner.ClientTLS(os.Getenv("FAIR_SCANNER_TLS_CERT_FILE"), os.Getenv("FAIR_SCANNER_TLS_KEY_FILE"),
		os.Getenv("FAIR_POSTURE_CA_FILE"), getenv("FAIR_POSTURE_SERVER_NAME", host))
	if err != nil {
		return err
	}
	kc, err := kube.InCluster()
	if err != nil {
		return err
	}
	k, err := kube.New(kc)
	if err != nil {
		return err
	}
	conn, report, err := scanner.Dial(addr, tlsConf)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	var namespaces []string
	for _, ns := range strings.Split(getenv("FAIR_PLATFORM_NAMESPACES", "fair-platform"), ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			namespaces = append(namespaces, ns)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	s := &scanner.Scanner{Kube: k, Checks: nil, // the check catalog is F-015 T-28
		Scope: scanner.Scope{Namespaces: namespaces}, Instance: getenv("POD_NAME", "posture-scanner"),
		Report: report, Interval: interval, Logger: logger}
	logger.Info("scanner started", "posture", addr, "namespaces", strings.Join(namespaces, ","), "fips140", fips140.Enabled())
	s.Run(ctx)
	return nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

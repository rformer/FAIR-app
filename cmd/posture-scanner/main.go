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
//	FAIR_FIPS_PROBE_NAMESPACE   fips-probe's namespace (default fair-fips-probe; T-29)
//	FAIR_SCAN_INTERVAL          default 15m
//	FAIR_RELEASE_MANIFEST_FILE  signed release manifest (FILE and FILE.sig; T-28)
//	FAIR_RELEASE_PUBLIC_KEY_FILE release signing public key (PEM)
//	FAIR_PSA_DEFAULT            cluster-wide pod security level attested at install (e.g. restricted on RKE2)
//	FAIR_INGRESS_ENDPOINTS      comma-separated host:port of the platform ingress, probed for TLS
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

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
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

	// The check catalog (T-28). Without the release manifest and key the
	// image and RBAC checks report errors (never "passed"); the others run.
	cfg := checks.Config{PSADefault: os.Getenv("FAIR_PSA_DEFAULT"), IngressEndpoints: list(os.Getenv("FAIR_INGRESS_ENDPOINTS")),
		ReleaseManifest: os.Getenv("FAIR_RELEASE_MANIFEST_FILE")}
	if f := os.Getenv("FAIR_RELEASE_PUBLIC_KEY_FILE"); f != "" {
		if cfg.ReleaseKey, err = profilepkg.LoadPublicKey(f); err != nil {
			return err
		}
	}
	namespaces := list(getenv("FAIR_PLATFORM_NAMESPACES", "fair-platform"))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	s := &scanner.Scanner{Kube: k, Checks: checks.Catalog(cfg),
		Scope: scanner.Scope{Namespaces: namespaces, ProbeNamespace: getenv("FAIR_FIPS_PROBE_NAMESPACE", "fair-fips-probe")}, Instance: getenv("POD_NAME", "posture-scanner"),
		Report: report, Interval: interval, Logger: logger}
	logger.Info("scanner started", "posture", addr, "namespaces", strings.Join(namespaces, ","), "fips140", fips140.Enabled())
	s.Run(ctx)
	return nil
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Package telemetry sets up OpenTelemetry metrics and traces for a service
// (F-012 T-09, F-012-AC-22, AC-25; design §3.7; ADR-017).
//
// Telemetry is off by default. Without FAIR_OTEL_ENDPOINT, Setup installs
// nothing: the global providers stay OpenTelemetry's no-op ones, nothing is
// exported and nothing leaves the process (AC-25: self-hosted and air-gapped
// installations never call home; an administrator points the endpoint at
// their own Collector). With an endpoint, metrics and traces go over
// OTLP/gRPC with TLS 1.2 or later (the platform's TLS configuration, FIPS
// 140 in our builds); there is no plaintext option.
//
//	FAIR_OTEL_ENDPOINT      host:port of the Collector (off when empty)
//	FAIR_OTEL_CA_FILE       the Collector's CA (PEM); the system roots otherwise
//	FAIR_OTEL_SAMPLE_RATIO  the share of traces sampled, 0 to 1 (default 0.1)
//
// Instrumentation reads the global providers, so instruments made before
// Setup start recording once it runs. Every attribute passes the allow-list
// Allowed (AC-23): names of routes, operations, queues and outcomes, never
// ids from paths, arguments, bodies, tokens or personal data.
package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc/credentials"
)

// Scope is the instrumentation scope of every instrument and tracer.
const Scope = "github.com/rformer/fair-app"

// Config is the telemetry configuration.
type Config struct {
	Endpoint    string
	CAFile      string
	SampleRatio float64
}

// DefaultSampleRatio is the share of traces sampled when none is set.
const DefaultSampleRatio = 0.1

// ConfigFromEnv reads FAIR_OTEL_*.
func ConfigFromEnv() (Config, error) {
	c := Config{Endpoint: strings.TrimSpace(os.Getenv("FAIR_OTEL_ENDPOINT")), CAFile: os.Getenv("FAIR_OTEL_CA_FILE"), SampleRatio: DefaultSampleRatio}
	if v := os.Getenv("FAIR_OTEL_SAMPLE_RATIO"); v != "" {
		r, err := strconv.ParseFloat(v, 64)
		if err != nil || r < 0 || r > 1 {
			return c, fmt.Errorf("FAIR_OTEL_SAMPLE_RATIO must be a number from 0 to 1, got %q", v)
		}
		c.SampleRatio = r
	}
	if c.Endpoint != "" && (strings.Contains(c.Endpoint, "://") || !strings.Contains(c.Endpoint, ":")) {
		return c, fmt.Errorf("FAIR_OTEL_ENDPOINT must be host:port (TLS is always used), got %q", c.Endpoint)
	}
	return c, nil
}

// Telemetry is what Setup installed.
type Telemetry struct {
	// Enabled is false when no endpoint is set: nothing is exported.
	Enabled  bool
	shutdown []func(context.Context) error
}

// Shutdown flushes and stops the exporters (nothing when disabled).
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error
	for _, f := range t.shutdown {
		errs = append(errs, f(ctx))
	}
	return errors.Join(errs...)
}

// Setup reads the environment and installs the global providers.
func Setup(ctx context.Context, service, version string) (*Telemetry, error) {
	c, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return SetupWith(ctx, c, service, version)
}

// SetupWith is Setup with the configuration given.
func SetupWith(ctx context.Context, c Config, service, version string) (*Telemetry, error) {
	t := &Telemetry{}
	if c.Endpoint == "" {
		return t, nil // off: the global providers stay no-op
	}
	tc, err := tlsConfig(c.CAFile)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewTLS(tc)
	res := resource.NewSchemaless(attribute.String("service.name", service), attribute.String("service.version", version))

	traces, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(c.Endpoint), otlptracegrpc.WithTLSCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("telemetry: traces: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(c.SampleRatio))),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(Filtered(traces))),
	)
	metrics, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpoint(c.Endpoint), otlpmetricgrpc.WithTLSCredentials(creds))
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, fmt.Errorf("telemetry: metrics: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metrics, sdkmetric.WithInterval(30*time.Second))),
		sdkmetric.WithView(AllowedView))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	t.Enabled = true
	t.shutdown = append(t.shutdown, tp.Shutdown, mp.Shutdown)
	return t, nil
}

// tlsConfig is the platform's TLS client configuration (TLS 1.2 or later)
// with the Collector's CA when one is given.
func tlsConfig(caFile string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-supplied CA file
	if err != nil {
		return nil, fmt.Errorf("FAIR_OTEL_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("FAIR_OTEL_CA_FILE holds no PEM certificate")
	}
	tc.RootCAs = pool
	return tc, nil
}

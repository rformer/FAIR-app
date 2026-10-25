// Package otelx configures OpenTelemetry tracing. Export is optional: with no
// OTLP endpoint configured the service runs with a no-op provider, so there is
// no mandatory runtime dependency (constitution A7).
package otelx

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

// Setup installs the global tracer provider and propagators. The OTLP
// exporter is configured from the standard OTEL_EXPORTER_OTLP_* variables.
// It returns a shutdown function and whether export is enabled.
func Setup(ctx context.Context, service, version string) (func(context.Context) error, bool, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, false, nil
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("otel: exporter: %w", err)
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(service), semconv.ServiceVersion(version)))
	if err != nil {
		return nil, false, fmt.Errorf("otel: resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, true, nil
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Middleware starts a server span per request, continuing any incoming
// W3C trace context. The span name uses the matched route pattern, never the
// raw path, so IDs in URLs do not leak into trace names.
func Middleware(service string, next http.Handler) http.Handler {
	tracer := otel.Tracer("github.com/rformer/fair-app/" + service)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, r.Method, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(semconv.HTTPRequestMethodKey.String(r.Method)))
		defer span.End()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		r = r.WithContext(ctx)
		next.ServeHTTP(rec, r)
		if r.Pattern != "" {
			span.SetName(r.Pattern)
			span.SetAttributes(attribute.String("http.route", r.Pattern))
		}
		span.SetAttributes(semconv.HTTPResponseStatusCode(rec.code))
		if rec.code >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.code))
		}
	})
}

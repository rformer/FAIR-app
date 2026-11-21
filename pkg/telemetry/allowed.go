package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Allowed are the only attribute keys telemetry may carry (F-012-AC-23;
// design §3.7). Each names a route, an operation, a queue or an outcome;
// none can hold an id from a path, an argument, a body, a token or personal
// data. A new key needs a reason here and a case in the redaction test (T-10).
var Allowed = map[attribute.Key]string{
	"http.request.method":       "GET, POST, ...",
	"http.route":                "the route pattern, never the path with its ids",
	"http.response.status_code": "the status code",
	"db.operation.name":         "the statement's first word (SELECT, INSERT, ...), never the statement",
	"db.result":                 "ok or error",
	"job.queue":                 "the River queue",
	"job.kind":                  "the River job kind",
	"job.outcome":               "completed, failed, cancelled, snoozed",
	"messaging.destination":     "the NATS subject (fixed names, no ids)",
	"messaging.operation":       "publish or consume",
	"engine.method":             "the engine RPC (Simulate, Aggregate, Info)",
	"outcome":                   "ok, error or a fixed failure code",
	"channel":                   "email, webhook or in_app",
	"backlog":                   "the backlog measured (audit_forwarding, ...)",
}

// Attr is an attribute when its key is allowed; others are dropped.
func Attr(kv ...attribute.KeyValue) []attribute.KeyValue {
	out := kv[:0:0]
	for _, a := range kv {
		if _, ok := Allowed[a.Key]; ok {
			out = append(out, a)
		}
	}
	return out
}

func allowedKey(kv attribute.KeyValue) bool {
	_, ok := Allowed[kv.Key]
	return ok
}

// AllowedView drops every metric attribute not in Allowed.
var AllowedView = sdkmetric.NewView(sdkmetric.Instrument{Name: "*"}, sdkmetric.Stream{AttributeFilter: allowedKey})

// Filtered wraps a span exporter so exported spans carry only allowed
// attributes, no events (which can hold error text) and no links.
func Filtered(next sdktrace.SpanExporter) sdktrace.SpanExporter { return filtered{next} }

type filtered struct{ next sdktrace.SpanExporter }

func (f filtered) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	stubs := tracetest.SpanStubsFromReadOnlySpans(spans)
	for i := range stubs {
		stubs[i].Attributes = Attr(stubs[i].Attributes...)
		stubs[i].Events = nil
		stubs[i].Links = nil
		stubs[i].Status.Description = ""
	}
	return f.next.ExportSpans(ctx, stubs.Snapshots())
}

func (f filtered) Shutdown(ctx context.Context) error { return f.next.Shutdown(ctx) }

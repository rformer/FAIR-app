package telemetry

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// instruments are made once, from the global providers (which bind late).
type instruments struct {
	httpDur     metric.Float64Histogram
	dbDur       metric.Float64Histogram
	jobDur      metric.Float64Histogram
	messages    metric.Int64Counter
	engineDur   metric.Float64Histogram
	deliveries  metric.Int64Counter
	backlogOnce sync.Mutex
}

// SecondBuckets are the bucket boundaries of every duration histogram, in
// seconds: OpenTelemetry's HTTP boundaries (the SDK's default ones are meant
// for milliseconds) extended to fifteen minutes for jobs and engine calls.
// The latency alerts in deploy/observability/alerts read the 1 second
// bucket (F-012 T-11).
var SecondBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10, 30, 60, 300, 900}

var (
	instOnce sync.Once
	inst     instruments
)

func get() *instruments {
	instOnce.Do(func() {
		m := otel.GetMeterProvider().Meter(Scope)
		s := metric.WithUnit("s")
		b := metric.WithExplicitBucketBoundaries(SecondBuckets...)
		inst.httpDur, _ = m.Float64Histogram("http.server.request.duration", s, b, metric.WithDescription("HTTP requests served"))
		inst.dbDur, _ = m.Float64Histogram("db.client.operation.duration", s, b, metric.WithDescription("Database statements"))
		inst.jobDur, _ = m.Float64Histogram("job.duration", s, b, metric.WithDescription("Background jobs run (River)"))
		inst.messages, _ = m.Int64Counter("messaging.messages", metric.WithDescription("NATS messages published and consumed"))
		inst.engineDur, _ = m.Float64Histogram("engine.call.duration", s, b, metric.WithDescription("Simulation engine calls"))
		inst.deliveries, _ = m.Int64Counter("notification.deliveries", metric.WithDescription("Notification delivery attempts"))
	})
	return &inst
}

func tracer() trace.Tracer { return otel.GetTracerProvider().Tracer(Scope) }

// HTTP instruments a handler: one span and one duration per request, named
// and labelled by the route pattern the mux matched (never the path, its
// ids, the query or the body).
func HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, span := tracer().Start(r.Context(), "HTTP "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
		matched := &route{}
		ctx = context.WithValue(ctx, routeKey{}, matched)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		req := r.WithContext(ctx)
		next.ServeHTTP(sw, req)
		route := matched.get() // the innermost mux's pattern (Routed)
		if route == "" {
			route = req.Pattern // set by http.ServeMux on the request it routed
		}
		if route == "" {
			route = "unmatched"
		} else if i := strings.IndexByte(route, ' '); i >= 0 {
			route = route[i+1:]
		}
		attrs := Attr(attribute.String("http.request.method", r.Method), attribute.String("http.route", route),
			attribute.Int("http.response.status_code", sw.status))
		span.SetName(r.Method + " " + route)
		span.SetAttributes(attrs...)
		if sw.status >= 500 {
			span.SetStatus(codes.Error, "")
		}
		span.End()
		get().httpDur.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	})
}

// Routed wraps a mux mounted below another (each API's own routes) so the
// pattern it matched names the request's span and metrics, not the prefix
// the outer mux matched.
func Routed(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r) // http.ServeMux sets r.Pattern on this request
		if m, ok := r.Context().Value(routeKey{}).(*route); ok && r.Pattern != "" {
			m.set(r.Pattern)
		}
	})
}

type routeKey struct{}

type route struct {
	mu      sync.Mutex
	pattern string
}

func (r *route) set(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pattern == "" { // the innermost mux returns first
		r.pattern = p
	}
}

func (r *route) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pattern
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Flush passes through, for streamed responses.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// PGX is a pgx query tracer: a span and a duration per statement, labelled
// by the statement's first word only (never the statement or its arguments).
type PGX struct{}

type pgxKey struct{}

type pgxStart struct {
	at   time.Time
	op   string
	span trace.Span
}

// TraceQueryStart implements pgx.QueryTracer.
func (PGX) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	op := Operation(data.SQL)
	ctx, span := tracer().Start(ctx, "db "+op, trace.WithSpanKind(trace.SpanKindClient))
	return context.WithValue(ctx, pgxKey{}, pgxStart{at: time.Now(), op: op, span: span})
}

// TraceQueryEnd implements pgx.QueryTracer.
func (PGX) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	st, ok := ctx.Value(pgxKey{}).(pgxStart)
	if !ok {
		return
	}
	result := "ok"
	if data.Err != nil {
		result = "error"
		st.span.SetStatus(codes.Error, "")
	}
	attrs := Attr(attribute.String("db.operation.name", st.op), attribute.String("db.result", result))
	st.span.SetAttributes(attrs...)
	st.span.End()
	get().dbDur.Record(ctx, time.Since(st.at).Seconds(), metric.WithAttributes(attrs...))
}

// Operation is a statement's first word, upper-cased (SELECT, INSERT, ...),
// or OTHER.
func Operation(sql string) string {
	var b strings.Builder
	for _, l := range strings.Split(sql, "\n") {
		if i := strings.Index(l, "--"); i >= 0 {
			l = l[:i] // a line comment
		}
		b.WriteString(l)
		b.WriteByte(' ')
	}
	f := strings.Fields(b.String())
	if len(f) == 0 {
		return "OTHER"
	}
	switch w := strings.ToUpper(strings.Trim(f[0], "(;")); w {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CALL", "BEGIN", "COMMIT", "ROLLBACK", "SET", "LISTEN", "NOTIFY", "COPY", "SAVEPOINT", "RELEASE":
		return w
	}
	return "OTHER"
}

// Job records a background job that finished.
func Job(ctx context.Context, queue, kind, outcome string, d time.Duration) {
	get().jobDur.Record(ctx, d.Seconds(), metric.WithAttributes(Attr(attribute.String("job.queue", queue),
		attribute.String("job.kind", kind), attribute.String("job.outcome", outcome))...))
}

// Message counts a NATS message published or consumed on a subject.
func Message(ctx context.Context, operation, subject string) {
	get().messages.Add(ctx, 1, metric.WithAttributes(Attr(attribute.String("messaging.operation", operation),
		attribute.String("messaging.destination", subject))...))
}

// EngineCall records a call to the simulation engine.
func EngineCall(ctx context.Context, method string, err error, d time.Duration) {
	get().engineDur.Record(ctx, d.Seconds(), metric.WithAttributes(Attr(attribute.String("engine.method", method),
		attribute.String("outcome", outcomeOf(err)))...))
}

// Delivery counts a notification delivery attempt and its outcome (ok,
// retry, failed).
func Delivery(ctx context.Context, channel, outcome string) {
	get().deliveries.Add(ctx, 1, metric.WithAttributes(Attr(attribute.String("channel", channel), attribute.String("outcome", outcome))...))
}

func outcomeOf(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// Backlog registers a gauge read by fn at each collection (the audit
// trail's forwarding backlog and capacity, River queue depth). name must be
// a fixed string.
func Backlog(name string, fn func(context.Context) (int64, error)) error {
	i := get()
	i.backlogOnce.Lock()
	defer i.backlogOnce.Unlock()
	_, err := otel.GetMeterProvider().Meter(Scope).Int64ObservableGauge("backlog."+name,
		metric.WithInt64Callback(func(ctx context.Context, o metric.Int64Observer) error {
			n, err := fn(ctx)
			if err != nil {
				return nil //nolint:nilerr // a failed read is a missing point, not an error of the collection
			}
			o.Observe(n, metric.WithAttributes(Attr(attribute.String("backlog", name))...))
			return nil
		}))
	return err
}

// Logs adds the current span's trace_id and span_id to every log record
// with a context (slog's ...Context functions).
func Logs(h slog.Handler) slog.Handler { return logHandler{h} }

type logHandler struct{ next slog.Handler }

func (l logHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return l.next.Enabled(ctx, lvl)
}

func (l logHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r = r.Clone()
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return l.next.Handle(ctx, r)
}

func (l logHandler) WithAttrs(as []slog.Attr) slog.Handler { return logHandler{l.next.WithAttrs(as)} }

func (l logHandler) WithGroup(n string) slog.Handler { return logHandler{l.next.WithGroup(n)} }

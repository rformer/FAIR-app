package audit

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// OTLPScope is the instrumentation scope of forwarded records.
const OTLPScope = "fair-audit-trail"

// OTLPTransport sends records as OTLP logs over gRPC with TLS (F-002 T-17,
// AC-22; design §6.4): one ExportLogsServiceRequest per batch, each record
// a log record whose body is the record exactly as recorded, with its
// event time, severity and type (event_name) and the attributes fair.seq,
// fair.chain and fair.segment. The export response is the acknowledgement:
// a batch counts as delivered only when the export succeeds and the
// receiver rejects none of it (partial success), so delivery is at least
// once and never lost.
type OTLPTransport struct {
	TLS      *tls.Config // nil: plaintext (OTLPTLS allows it in development only)
	Hostname string
	// Timeout bounds one export (30 seconds when zero).
	Timeout time.Duration
	Now     func() time.Time

	conn     *grpc.ClientConn
	connAddr string
}

// Kind implements Transport.
func (o *OTLPTransport) Kind() string { return "otlp" }

// Send implements Transport.
func (o *OTLPTransport) Send(ctx context.Context, addr string, recs []ForwardRecord) error {
	req, err := OTLPRequest(recs, o.Hostname, o.now())
	if err != nil {
		return err
	}
	if o.conn != nil && o.connAddr != addr {
		o.Close()
	}
	if o.conn == nil {
		creds := insecure.NewCredentials()
		if o.TLS != nil {
			creds = credentials.NewTLS(o.TLS.Clone())
		}
		c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return err
		}
		o.conn, o.connAddr = c, addr
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := collogspb.NewLogsServiceClient(o.conn).Export(ctx, req)
	if err != nil {
		// A fresh client next time: gRPC's own reconnection backoff would
		// otherwise fail the forwarder's next attempts after an outage.
		o.Close()
		return err
	}
	if ps := resp.GetPartialSuccess(); ps != nil && ps.GetRejectedLogRecords() > 0 {
		return fmt.Errorf("the receiver rejected %d of %d records: %s", ps.GetRejectedLogRecords(), len(recs), ps.GetErrorMessage())
	}
	return nil
}

func (o *OTLPTransport) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Close implements Transport.
func (o *OTLPTransport) Close() {
	if o.conn != nil {
		_ = o.conn.Close()
		o.conn = nil
	}
}

// OTLPRequest is one batch as an OTLP logs export: resource service.name
// fair-audit and host.name, scope fair-audit-trail, a log record per
// record in order.
func OTLPRequest(recs []ForwardRecord, hostname string, observed time.Time) (*collogspb.ExportLogsServiceRequest, error) {
	lrs := make([]*logspb.LogRecord, 0, len(recs))
	for _, r := range recs {
		ev, err := recordHeader(r.Seq, r.Body)
		if err != nil {
			return nil, err
		}
		lr := &logspb.LogRecord{
			ObservedTimeUnixNano: uint64(observed.UnixNano()), // #nosec G115 -- after 1970
			SeverityNumber:       otlpSeverity(ev.Severity),
			SeverityText:         ev.Severity,
			EventName:            ev.Type,
			Body:                 &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(r.Body)}},
			Attributes: []*commonpb.KeyValue{
				{Key: "fair.seq", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: r.Seq}}},
				{Key: "fair.chain", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: hex.EncodeToString(r.Chain)}}},
				{Key: "fair.segment", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: r.Segment}}},
			},
		}
		if !ev.time.IsZero() {
			lr.TimeUnixNano = uint64(ev.time.UnixNano()) // #nosec G115 -- after 1970
		}
		lrs = append(lrs, lr)
	}
	str := func(k, v string) *commonpb.KeyValue {
		return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
	}
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", "fair-audit")}}
	if hostname != "" {
		res.Attributes = append(res.Attributes, str("host.name", hostname))
	}
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  res,
		ScopeLogs: []*logspb.ScopeLogs{{Scope: &commonpb.InstrumentationScope{Name: OTLPScope}, LogRecords: lrs}},
	}}}, nil
}

// otlpSeverity maps the catalog's severities as syslog does: info and low
// informational, high a warning, critical an error.
func otlpSeverity(s string) logspb.SeverityNumber {
	switch s {
	case "critical":
		return logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
	case "high":
		return logspb.SeverityNumber_SEVERITY_NUMBER_WARN
	case "low":
		return logspb.SeverityNumber_SEVERITY_NUMBER_INFO4
	default:
		return logspb.SeverityNumber_SEVERITY_NUMBER_INFO
	}
}

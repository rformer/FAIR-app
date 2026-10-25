package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OTLPSink exports events as OTLP/HTTP JSON log records to a collector
// (POST {endpoint}/v1/logs). It uses only the standard library so it works in
// air-gapped installs with any OTLP-capable collector.
//
// Stub behaviour: one request per event, no batching or retry queue. The
// F-002 audit service will replace this with a buffered exporter.
type OTLPSink struct {
	endpoint string
	service  string
	headers  map[string]string
	client   *http.Client
	mu       sync.RWMutex
	closed   bool
}

// OTLPConfig configures the OTLP sink.
type OTLPConfig struct {
	Endpoint    string            // e.g. https://otel-collector:4318
	ServiceName string            // resource service.name
	Headers     map[string]string // e.g. authorization
	TLS         *tls.Config       // optional; MinVersion is forced to >= TLS 1.2
	Timeout     time.Duration
}

// NewOTLPSink builds the sink.
func NewOTLPSink(cfg OTLPConfig) *OTLPSink {
	tcfg := cfg.TLS
	if tcfg == nil {
		tcfg = &tls.Config{}
	}
	tcfg = tcfg.Clone()
	if tcfg.MinVersion < tls.VersionTLS12 {
		tcfg.MinVersion = tls.VersionTLS12 // hard floor (F-015 AC-30)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &OTLPSink{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		service:  cfg.ServiceName,
		headers:  cfg.Headers,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tcfg, Proxy: http.ProxyFromEnvironment},
		},
	}
}

// OTLP severity numbers (logs data model).
func otlpSeverity(s Severity) (int, string) {
	switch s {
	case SeverityCritical:
		return 21, "FATAL"
	case SeverityHigh:
		return 17, "ERROR"
	case SeverityMedium:
		return 13, "WARN"
	case SeverityLow:
		return 10, "INFO2"
	default:
		return 9, "INFO"
	}
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue"`
}

type otlpKV struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

func kv(k, v string) otlpKV { return otlpKV{Key: k, Value: otlpAnyValue{StringValue: v}} }

// OTLPLogsRequest is the subset of ExportLogsServiceRequest we produce. It is
// exported so tests (and the collector contract test) can decode it.
type OTLPLogsRequest struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []otlpKV `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			LogRecords []OTLPLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

// OTLPLogRecord is one exported log record; Body.StringValue holds the event JSON.
type OTLPLogRecord struct {
	TimeUnixNano   string       `json:"timeUnixNano"`
	SeverityNumber int          `json:"severityNumber"`
	SeverityText   string       `json:"severityText"`
	EventName      string       `json:"eventName"`
	Body           otlpAnyValue `json:"body"`
	Attributes     []otlpKV     `json:"attributes"`
}

// Emit implements Emitter.
func (s *OTLPSink) Emit(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit otlp: marshal: %w", err)
	}
	num, text := otlpSeverity(e.Severity)
	rec := OTLPLogRecord{
		TimeUnixNano:   strconv.FormatInt(e.Time.UnixNano(), 10),
		SeverityNumber: num,
		SeverityText:   text,
		EventName:      e.Type,
		Body:           otlpAnyValue{StringValue: string(body)},
		Attributes: []otlpKV{
			kv("event.id", e.ID), kv("event.type", e.Type), kv("event.severity", string(e.Severity)),
			kv("event.outcome", string(e.Outcome)), kv("actor.id", e.Actor.ID),
			kv("target.kind", e.Target.Kind), kv("target.id", e.Target.ID),
		},
	}
	payload := map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []otlpKV{kv("service.name", s.service)}},
			"scopeLogs": []any{map[string]any{
				"scope":      map[string]string{"name": "fair.audit"},
				"logRecords": []OTLPLogRecord{rec},
			}},
		}},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("audit otlp: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/logs", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("audit otlp: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit otlp: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("audit otlp: collector returned %s", resp.Status)
	}
	return nil
}

// Close implements Emitter.
func (s *OTLPSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.client.CloseIdleConnections()
	return nil
}

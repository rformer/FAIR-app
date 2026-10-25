// Package audit defines the security event contract used by every service
// (F-001 AC-50, F-001 T-00a). Phase 0 provides the Emitter interface and stub
// sinks; the tamper-evident, hash-chained audit trail is F-002, and NATS
// publication is added when the event bus lands (F-001 Phase 1).
//
// Emit never drops events silently: sink failures are returned to the caller
// so services can fail closed on audit-critical operations.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

// Severity of a security event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event is a structured security event.
type Event struct {
	ID         string            `json:"id"`
	Time       time.Time         `json:"time"`
	Type       string            `json:"type"`     // e.g. "setting.changed", "authn.login.success"
	Severity   Severity          `json:"severity"` // info|low|high|critical
	Actor      string            `json:"actor"`    // user ID or "system:<service>"
	Target     string            `json:"target,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Before     any               `json:"before,omitempty"`
	After      any               `json:"after,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Emitter publishes security events.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// ErrInvalidEvent is returned when required fields are missing.
var ErrInvalidEvent = errors.New("audit: event requires Type, Severity and Actor")

// Normalize fills ID and Time and validates required fields.
func Normalize(e Event, now time.Time) (Event, error) {
	if e.Type == "" || e.Severity == "" || e.Actor == "" {
		return e, ErrInvalidEvent
	}
	switch e.Severity {
	case SeverityInfo, SeverityLow, SeverityHigh, SeverityCritical:
	default:
		return e, ErrInvalidEvent
	}
	if e.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return e, err
		}
		e.ID = hex.EncodeToString(b[:])
	}
	if e.Time.IsZero() {
		e.Time = now.UTC()
	}
	return e, nil
}

// JSONLines writes one JSON object per line (for log shipping to OTLP/SIEM collectors).
type JSONLines struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

// NewJSONLines returns a sink writing to w.
func NewJSONLines(w io.Writer) *JSONLines { return &JSONLines{w: w, now: time.Now} }

// Emit implements Emitter.
func (j *JSONLines) Emit(_ context.Context, e Event) error {
	e, err := Normalize(e, j.now())
	if err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Kind string `json:"kind"`
		Event
	}{"audit", e})
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(append(b, '\n'))
	return err
}

// Memory records events in memory (tests and in-process inspection).
type Memory struct {
	mu     sync.Mutex
	events []Event
	now    func() time.Time
}

// NewMemory returns an empty in-memory sink.
func NewMemory() *Memory { return &Memory{now: time.Now} }

// Emit implements Emitter.
func (m *Memory) Emit(_ context.Context, e Event) error {
	e, err := Normalize(e, m.now())
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

// Events returns a copy of recorded events.
func (m *Memory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// OfType returns recorded events of the given type.
func (m *Memory) OfType(t string) []Event {
	var out []Event
	for _, e := range m.Events() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// Multi fans an event out to several sinks and returns every failure.
type Multi []Emitter

// Emit implements Emitter.
func (m Multi) Emit(ctx context.Context, e Event) error {
	e, err := Normalize(e, time.Now())
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range m {
		if err := s.Emit(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

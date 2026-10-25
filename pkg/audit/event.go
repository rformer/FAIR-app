// Package audit defines the security event schema and the Emitter interface
// that every Go service uses to record audit events (F-001 AC-50).
//
// This is the F-001 T-00a stub: events fan out to NATS JetStream, OTLP and
// syslog sinks. The tamper-evident, hash-chained store is F-002; when it
// lands it becomes one more Emitter behind the same interface.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SchemaVersion is the version of the Event wire format.
const SchemaVersion = 1

// Severity of a security event. High and Critical are used for loosening,
// break-glass, hard-floor refusals and privileged-permission changes.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Outcome of the audited action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomePending Outcome = "pending"
)

// Valid reports whether o is a known outcome.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomePending:
		return true
	}
	return false
}

// ActorKind identifies what kind of principal performed the action.
type ActorKind string

const (
	ActorUser    ActorKind = "user"
	ActorService ActorKind = "service"
	ActorSystem  ActorKind = "system"
)

// Actor is who performed the action.
type Actor struct {
	Kind ActorKind `json:"kind"`
	ID   string    `json:"id"`
	IP   string    `json:"ip,omitempty"`
}

// Target is what the action was performed on.
type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	BU   string `json:"bu,omitempty"`
}

// Event is one security-relevant occurrence. Field names are stable: the
// F-002 hash chain and SIEM parsers depend on them.
type Event struct {
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	Time          time.Time         `json:"time"`
	Severity      Severity          `json:"severity"`
	Outcome       Outcome           `json:"outcome"`
	Actor         Actor             `json:"actor"`
	Target        Target            `json:"target"`
	Reason        string            `json:"reason,omitempty"`
	Before        json.RawMessage   `json:"before,omitempty"`
	After         json.RawMessage   `json:"after,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// typeRe: dotted lowercase, at least two segments, e.g. "authn.login.success".
var typeRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// ErrInvalidEvent is returned (wrapped) by Validate and by every Emitter for
// events that fail validation. Invalid events are never written.
var ErrInvalidEvent = errors.New("audit: invalid event")

// ErrClosed is returned by Emit after Close.
var ErrClosed = errors.New("audit: emitter closed")

// Validate checks required fields.
func (e *Event) Validate() error {
	var errs []error
	if e.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("schema_version %d != %d", e.SchemaVersion, SchemaVersion))
	}
	if e.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if !typeRe.MatchString(e.Type) {
		errs = append(errs, fmt.Errorf("type %q must be dotted lowercase (e.g. authn.login.success)", e.Type))
	}
	if e.Time.IsZero() {
		errs = append(errs, errors.New("time is required"))
	}
	if !e.Severity.Valid() {
		errs = append(errs, fmt.Errorf("severity %q is not valid", e.Severity))
	}
	if !e.Outcome.Valid() {
		errs = append(errs, fmt.Errorf("outcome %q is not valid", e.Outcome))
	}
	switch e.Actor.Kind {
	case ActorUser, ActorService, ActorSystem:
	default:
		errs = append(errs, fmt.Errorf("actor.kind %q is not valid", e.Actor.Kind))
	}
	if e.Actor.ID == "" {
		errs = append(errs, errors.New("actor.id is required"))
	}
	if e.Target.Kind == "" || e.Target.ID == "" {
		errs = append(errs, errors.New("target.kind and target.id are required"))
	}
	for _, raw := range []json.RawMessage{e.Before, e.After} {
		if len(raw) > 0 && !json.Valid(raw) {
			errs = append(errs, errors.New("before/after must be valid JSON"))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, errors.Join(errs...))
	}
	return nil
}

// New returns an Event with schema version, ID and UTC time filled in.
func New(eventType string, sev Severity, outcome Outcome, actor Actor, target Target) Event {
	return Event{
		SchemaVersion: SchemaVersion,
		ID:            NewID(),
		Type:          eventType,
		Time:          time.Now().UTC(),
		Severity:      sev,
		Outcome:       outcome,
		Actor:         actor,
		Target:        target,
	}
}

// NewID returns a random UUIDv4 string.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// JSON is a helper for Before/After payloads.
func JSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

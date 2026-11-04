package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	yaml "go.yaml.in/yaml/v3"
)

// The security event catalog (F-001 T-37; AC-50, AC-54): every event type
// the platform emits, its AC-50 category, the severities it may carry and
// the fields it must have, plus the JSON Schema of the event envelope.
// Validating refuses an event the catalog does not describe (audit fails
// closed, ADR-006); tests check that the code emits exactly the catalog's
// types (catalog_test.go).

//go:embed catalog.yaml
var catalogYAML []byte

//go:embed event.schema.json
var eventSchemaJSON []byte

// Categories are AC-50's event classes.
var Categories = []string{
	"authentication", "session", "role_permission", "bu_restriction", "breakglass", "token", "scim", "configuration",
	"access", "approval", "service_account", "system",
}

// CatalogEntry describes one event type.
type CatalogEntry struct {
	Type       string     `yaml:"type"`
	Category   string     `yaml:"category"`
	Severities []Severity `yaml:"severities"`
	Requires   []string   `yaml:"requires"` // target, reason
	// BU is "required" when every event of the type concerns one BU (it must
	// carry bu_id), else "optional" (F-002 T-03, design §3).
	BU string `yaml:"bu"`
	// Attributes are the attribute names the type may carry; nothing else is
	// accepted (F-002-AC-06). Every entry declares the list, empty or not.
	Attributes  []string `yaml:"attributes"`
	Description string   `yaml:"description"`
}

// BURequired and BUOptional are the values of CatalogEntry.BU.
const (
	BURequired = "required"
	BUOptional = "optional"
)

// ReservedAttributes may appear on any event: FromOutbox adds event_id.
var ReservedAttributes = []string{"event_id"}

// deniedNames are attribute-name fragments that would carry a secret
// (F-002-AC-06): the catalog refuses such names.
var deniedNames = []string{"password", "passwd", "secret", "token", "cookie", "authorization", "private_key", "api_key", "bearer"}

// secretValueRE matches values that look like secrets: JWTs, PEM private
// keys, bearer or basic credentials, and the session cookie.
var secretValueRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}|__Host-sid=`)

// LooksSecret reports whether s looks like a secret value (F-002-AC-06).
func LooksSecret(s string) bool { return secretValueRE.MatchString(s) }

var attrNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Catalog is the loaded catalog.
type Catalog struct {
	Entries map[string]CatalogEntry
	schema  *jsonschema.Schema
}

var (
	catalogOnce sync.Once
	catalog     *Catalog
	catalogErr  error
)

// DefaultCatalog is the embedded catalog.
func DefaultCatalog() (*Catalog, error) {
	catalogOnce.Do(func() { catalog, catalogErr = ParseCatalog(catalogYAML) })
	return catalog, catalogErr
}

// ParseCatalog parses and checks a catalog document.
func ParseCatalog(doc []byte) (*Catalog, error) {
	var raw struct {
		Events []CatalogEntry `yaml:"events"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("audit: catalog: %w", err)
	}
	c := &Catalog{Entries: map[string]CatalogEntry{}}
	for _, e := range raw.Events {
		switch {
		case e.Type == "" || !typeRE(e.Type):
			return nil, fmt.Errorf("audit: catalog: bad type %q", e.Type)
		case !slices.Contains(Categories, e.Category):
			return nil, fmt.Errorf("audit: catalog: %s: unknown category %q", e.Type, e.Category)
		case len(e.Severities) == 0 || strings.TrimSpace(e.Description) == "":
			return nil, fmt.Errorf("audit: catalog: %s needs severities and a description", e.Type)
		}
		for _, s := range e.Severities {
			if !validSeverity(s) {
				return nil, fmt.Errorf("audit: catalog: %s: severity %q", e.Type, s)
			}
		}
		for _, r := range e.Requires {
			if r != "target" && r != "reason" {
				return nil, fmt.Errorf("audit: catalog: %s: requires %q", e.Type, r)
			}
		}
		switch e.BU {
		case "":
			e.BU = BUOptional
		case BURequired, BUOptional:
		default:
			return nil, fmt.Errorf("audit: catalog: %s: bu %q (required or optional)", e.Type, e.BU)
		}
		if e.Attributes == nil {
			return nil, fmt.Errorf("audit: catalog: %s declares no attributes list (use [] for none)", e.Type)
		}
		for i, a := range e.Attributes {
			switch {
			case !attrNameRE.MatchString(a):
				return nil, fmt.Errorf("audit: catalog: %s: attribute %q", e.Type, a)
			case slices.Contains(ReservedAttributes, a):
				return nil, fmt.Errorf("audit: catalog: %s: attribute %q is reserved", e.Type, a)
			case slices.Contains(e.Attributes[:i], a):
				return nil, fmt.Errorf("audit: catalog: %s: attribute %q listed twice", e.Type, a)
			}
			for _, d := range deniedNames {
				if strings.Contains(a, d) {
					return nil, fmt.Errorf("audit: catalog: %s: attribute %q would carry a secret (AC-06)", e.Type, a)
				}
			}
		}
		if _, dup := c.Entries[e.Type]; dup {
			return nil, fmt.Errorf("audit: catalog: %s listed twice", e.Type)
		}
		c.Entries[e.Type] = e
	}
	comp := jsonschema.NewCompiler()
	s, err := jsonschema.UnmarshalJSON(bytes.NewReader(eventSchemaJSON))
	if err != nil {
		return nil, fmt.Errorf("audit: event schema: %w", err)
	}
	if err := comp.AddResource("event.schema.json", s); err != nil {
		return nil, err
	}
	if c.schema, err = comp.Compile("event.schema.json"); err != nil {
		return nil, fmt.Errorf("audit: event schema: %w", err)
	}
	return c, nil
}

func typeRE(t string) bool {
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return false
			}
		}
	}
	return true
}

func validSeverity(s Severity) bool {
	return s == SeverityInfo || s == SeverityLow || s == SeverityHigh || s == SeverityCritical
}

// Types lists the catalog's types, sorted.
func (c *Catalog) Types() []string {
	out := make([]string, 0, len(c.Entries))
	for t := range c.Entries {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// SyncPayload is the catalog as audit.sync_event_types takes it (F-002
// T-02): {"events": [{type, category, severities, requires, description}]},
// sorted by type, so iam migrate makes audit.event_type equal to the build's
// catalog.
func (c *Catalog) SyncPayload() ([]byte, error) {
	type entry struct {
		Type        string     `json:"type"`
		Category    string     `json:"category"`
		Severities  []Severity `json:"severities"`
		Requires    []string   `json:"requires"`
		BU          string     `json:"bu"`
		Attributes  []string   `json:"attributes"`
		Description string     `json:"description"`
	}
	events := make([]entry, 0, len(c.Entries))
	for _, t := range c.Types() {
		e := c.Entries[t]
		req := e.Requires
		if req == nil {
			req = []string{}
		}
		events = append(events, entry{e.Type, e.Category, e.Severities, req, e.BU, e.Attributes, e.Description})
	}
	return json.Marshal(map[string]any{"events": events})
}

// ErrUncatalogued means the event is not what the catalog describes.
var ErrUncatalogued = errors.New("audit: event not in the catalog")

// Validate checks a normalized event against the schema and the catalog.
func (c *Catalog) Validate(e Event) error {
	ent, ok := c.Entries[e.Type]
	if !ok {
		return fmt.Errorf("%w: unknown type %q", ErrUncatalogued, e.Type)
	}
	if !slices.Contains(ent.Severities, e.Severity) {
		return fmt.Errorf("%w: %s with severity %q (allowed %v)", ErrUncatalogued, e.Type, e.Severity, ent.Severities)
	}
	for _, r := range ent.Requires {
		if (r == "target" && strings.TrimSpace(e.Target) == "") || (r == "reason" && strings.TrimSpace(e.Reason) == "") {
			return fmt.Errorf("%w: %s without %s", ErrUncatalogued, e.Type, r)
		}
	}
	if ent.BU == BURequired && e.BUID == "" {
		return fmt.Errorf("%w: %s without bu_id", ErrUncatalogued, e.Type)
	}
	for k, v := range e.Attributes {
		if !slices.Contains(ent.Attributes, k) && !slices.Contains(ReservedAttributes, k) {
			return fmt.Errorf("%w: %s with attribute %q (allowed %v)", ErrUncatalogued, e.Type, k, ent.Attributes)
		}
		if LooksSecret(v) {
			return fmt.Errorf("%w: %s: attribute %q looks like a secret", ErrUncatalogued, e.Type, k)
		}
	}
	for name, v := range map[string]any{"target": e.Target, "reason": e.Reason, "before": e.Before, "after": e.After} {
		s, ok := v.(string)
		if !ok && v != nil {
			b, _ := json.Marshal(v)
			s = string(b)
		}
		if LooksSecret(s) {
			return fmt.Errorf("%w: %s: %s looks like a secret", ErrUncatalogued, e.Type, name)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	if err := c.schema.Validate(v); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUncatalogued, e.Type, err)
	}
	return nil
}

// Validating refuses events the catalog does not describe, then passes
// them to Next.
type Validating struct {
	Next    Emitter
	Catalog *Catalog
}

// Emit implements Emitter.
func (v Validating) Emit(ctx context.Context, e Event) error {
	e, err := Normalize(e, time.Now())
	if err != nil {
		return err
	}
	if err := v.Catalog.Validate(e); err != nil {
		v.recordInvalid(ctx, e, err)
		return err
	}
	return v.Next.Emit(ctx, e)
}

// recordInvalid records an event the catalog refused as audit.invalid_event
// (critical, with the original attached; F-002 design §6.1), best effort:
// the refusal is returned to the caller either way, so the operation
// fails. It is recorded outside the caller's transaction, which is about
// to roll back.
func (v Validating) recordInvalid(ctx context.Context, e Event, cause error) {
	raw, _ := json.Marshal(e)
	if len(raw) > 8192 {
		raw = raw[:8192]
	}
	inv, err := Normalize(Event{Type: "audit.invalid_event", Severity: SeverityCritical, Actor: "system:audit",
		Target: "event:" + e.ID, Reason: cause.Error(), Attributes: map[string]string{"payload": string(raw)}}, time.Now())
	if err != nil || v.Catalog.Validate(inv) != nil {
		return // e.g. the original looks like a secret: not copied anywhere
	}
	_ = v.Next.Emit(context.WithValue(ctx, txKey{}, nil), inv)
}

// strict makes Memory validate against the catalog (tests of the whole
// platform turn it on, so every event they cause is checked).
var strict atomic.Bool

// SetStrict turns catalog validation of Memory sinks on or off.
func SetStrict(on bool) { strict.Store(on) }

// FromOutbox maps an audit row of iam.event_outbox (topic 'audit') to an
// event. Attributes become strings; target, reason, before, after,
// request_id and source_ip are kept as fields.
func FromOutbox(id int64, payload []byte) (Event, error) {
	var p struct {
		Type       string         `json:"type"`
		Severity   string         `json:"severity"`
		Actor      string         `json:"actor"`
		Target     string         `json:"target"`
		BUID       string         `json:"bu_id"`
		Reason     *string        `json:"reason"`
		Before     any            `json:"before"`
		After      any            `json:"after"`
		RequestID  string         `json:"request_id"`
		SourceIP   string         `json:"source_ip"`
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return Event{}, err
	}
	attrs := make(map[string]string, len(p.Attributes)+1)
	for k, v := range p.Attributes {
		switch x := v.(type) {
		case nil:
		case string:
			attrs[k] = x
		case map[string]any, []any:
			b, _ := json.Marshal(x)
			attrs[k] = string(b)
		default:
			attrs[k] = fmt.Sprint(x)
		}
	}
	attrs["event_id"] = fmt.Sprint(id)
	e := Event{Type: p.Type, Severity: Severity(p.Severity), Actor: p.Actor, Target: p.Target, BUID: p.BUID, Before: p.Before, After: p.After,
		RequestID: p.RequestID, SourceIP: p.SourceIP, Attributes: attrs}
	if p.Reason != nil {
		e.Reason = *p.Reason
	}
	return e, nil
}

// FromEnv builds a service's emitter (AC-50): JSON lines on stdout (for an
// OpenTelemetry collector's filelog receiver or any log shipper) and, when
// FAIR_AUDIT_SYSLOG_ADDR is set, RFC 5424 syslog over TLS (RFC 5425; the
// server's CA in FAIR_AUDIT_SYSLOG_CA_FILE, or the system roots). Plain TCP
// syslog (FAIR_AUDIT_SYSLOG_PLAINTEXT=true, a local relay) is refused outside
// development. Every event is checked against the catalog first, and an
// event is accepted only when every sink took it.
func FromEnv(env, appName string, getenv func(string) string) (Emitter, error) {
	c, err := DefaultCatalog()
	if err != nil {
		return nil, err
	}
	sinks := Multi{NewJSONLines(os.Stdout)}
	if addr := getenv("FAIR_AUDIT_SYSLOG_ADDR"); addr != "" {
		var tc *tls.Config
		if getenv("FAIR_AUDIT_SYSLOG_PLAINTEXT") == "true" {
			if env != "development" {
				return nil, errors.New("audit: plain TCP syslog is for development only; give FAIR_AUDIT_SYSLOG_ADDR a TLS listener")
			}
		} else {
			tc = &tls.Config{MinVersion: tls.VersionTLS12}
			if f := getenv("FAIR_AUDIT_SYSLOG_CA_FILE"); f != "" {
				pem, err := os.ReadFile(f) // #nosec G304 -- operator-supplied CA file
				if err != nil {
					return nil, fmt.Errorf("FAIR_AUDIT_SYSLOG_CA_FILE: %w", err)
				}
				tc.RootCAs = x509.NewCertPool()
				if !tc.RootCAs.AppendCertsFromPEM(pem) {
					return nil, errors.New("FAIR_AUDIT_SYSLOG_CA_FILE holds no certificate")
				}
			}
		}
		sinks = append(sinks, NewSyslog(addr, appName, tc))
	}
	return Validating{Next: sinks, Catalog: c}, nil
}

// CheckDeclaredEvents checks one API operation's x-audit-events (T-37):
// every mutating operation declares the events it can emit (nil: not
// declared), each a catalog type, and an empty list carries a note saying
// why nothing is audited.
func CheckDeclaredEvents(events *[]string, note string) error {
	c, err := DefaultCatalog()
	if err != nil {
		return err
	}
	if events == nil {
		return errors.New("no x-audit-events")
	}
	if len(*events) == 0 && strings.TrimSpace(note) == "" {
		return errors.New("x-audit-events is empty without an x-audit-note")
	}
	for _, t := range *events {
		if _, ok := c.Entries[t]; !ok {
			return fmt.Errorf("x-audit-events names %q, which is not in the catalog", t)
		}
	}
	return nil
}

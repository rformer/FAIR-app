package notify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func sampleEnvelope() Envelope {
	var e Envelope
	id := "8f0c2a1e-1b7e-4c55-9a1d-2f4f8c3b9d10"
	e.ID, e.Kind, e.At = "0b6c7e9a-3c1d-4e2f-8a5b-6d7e8f9a0b1c", "acceptance.decision_needed", time.Date(2026, 11, 16, 9, 30, 0, 0, time.UTC)
	e.BU.ID, e.BU.Name = "4d3c2b1a-0f9e-4d8c-b7a6-5e4d3c2b1a0f", "Claims"
	e.Item.Type, e.Item.ID, e.Item.Link = "acceptance", &id, "/acceptances/"+id
	return e
}

var composer = Composer{Base: "https://fair.example.com", Banner: "Authorized use only."}

// golden compares got with testdata/name, or writes it with FAIR_UPDATE_GOLDEN=1.
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p) // #nosec G304 -- the package's own test data
	if err != nil {
		t.Fatalf("%v (FAIR_UPDATE_GOLDEN=1 writes it)", err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("%s changed:\n%s", name, got)
	}
}

func TestEmailGolden(t *testing.T) {
	k, _ := KindOf("acceptance.decision_needed")
	m, err := composer.Email(sampleEnvelope(), k.Label)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "decision_needed.subject", m.Subject)
	golden(t, "decision_needed.txt", m.Text)
	golden(t, "decision_needed.html", m.HTML)
	b, err := composer.WebhookBody(sampleEnvelope(), "d-1")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "decision_needed.json", string(b))
}

// Minimal (AC-05): without a title the messages carry the kind, the BU,
// the time and the link, nothing of the item; the webhook body has exactly
// the envelope's fields.
func TestMinimalContent(t *testing.T) {
	m, err := composer.Email(sampleEnvelope(), "A risk acceptance waits for your decision")
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "[FAIR] A risk acceptance waits for your decision" {
		t.Errorf("subject %q", m.Subject)
	}
	for _, s := range []string{m.Text, m.HTML} {
		for _, want := range []string{"Claims", "2026-11-16 09:30 UTC", "https://fair.example.com/acceptances/8f0c2a1e-1b7e-4c55-9a1d-2f4f8c3b9d10", "Authorized use only."} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q", want)
			}
		}
	}
	b, _ := composer.WebhookBody(sampleEnvelope(), "d-1")
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "at,bu,delivery,format,item,kind,notice" {
		t.Errorf("webhook keys %v", keys)
	}
	// A title appears only when the envelope has one.
	e := sampleEnvelope()
	e.Title = "Claims ransomware"
	m, _ = composer.Email(e, "A risk acceptance waits for your decision")
	if !strings.Contains(m.Subject, "Claims ransomware") || !strings.Contains(m.Text, "Claims ransomware") {
		t.Errorf("title missing: %q", m.Subject)
	}
	if b, _ := composer.WebhookBody(e, "d-1"); !strings.Contains(string(b), `"title":"Claims ransomware"`) {
		t.Errorf("webhook title: %s", b)
	}
}

// Injection (AC-07): markup is escaped in HTML, control characters cannot
// break headers or lines, and links are only paths in the platform.
func TestInjection(t *testing.T) {
	e := sampleEnvelope()
	e.BU.Name = `<script>alert(1)</script>`
	e.Title = "Fraud\r\nBcc: attacker@example.com <img src=x onerror=alert(1)>"
	m, err := composer.Email(e, "Label\nInjected: header")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		t.Fatalf("subject breaks the header: %q", m.Subject)
	}
	if strings.Contains(m.HTML, "<script>") || strings.Contains(m.HTML, "<img") {
		t.Errorf("markup reached the HTML part:\n%s", m.HTML)
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") {
		t.Errorf("not escaped:\n%s", m.HTML)
	}
	if strings.Contains(m.Text, "\r") || strings.Contains(m.Text, "Fraud\n") {
		t.Errorf("a control character kept in the text part:\n%q", m.Text)
	}
	if _, err := HeaderValue("a\r\nBcc: x"); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a header value with CRLF: %v", err)
	}
	for _, bad := range []string{"https://evil.example/x", "//evil.example/x", "javascript:alert(1)", "/a\\b", "/a b", "acceptances/1", "", "/x\r\nHost: y"} {
		e := sampleEnvelope()
		e.Item.Link = bad
		if _, err := composer.Email(e, "x"); !errors.Is(err, ErrUnsafe) {
			t.Errorf("link %q: %v", bad, err)
		}
		if _, err := composer.WebhookBody(e, "d"); !errors.Is(err, ErrUnsafe) {
			t.Errorf("webhook link %q: %v", bad, err)
		}
	}
	if l, err := composer.Link("/audit?target=user:1"); err != nil || l != "https://fair.example.com/audit?target=user:1" {
		t.Errorf("a link with a query: %q %v", l, err)
	}
	if _, err := (Composer{Base: "http://fair.example.com"}).Link("/x"); err == nil {
		t.Error("an http base URL")
	}
	// Non-ASCII subjects are Q-encoded.
	e = sampleEnvelope()
	e.BU.Name = "Réassurance"
	e.Title = "Fraude à la carte"
	m, _ = composer.Email(e, "Une décision")
	if !strings.HasPrefix(m.Subject, "=?utf-8?q?") {
		t.Errorf("subject not encoded: %q", m.Subject)
	}
}

// Every release kind renders, with a noun for its item type.
func TestEveryKindRenders(t *testing.T) {
	types := map[string]string{"estimate": "estimate_request", "acceptance": "acceptance", "posture": "posture", "iam": "breakglass",
		"finding": "finding", "register": "risk", "report": "report", "integration": "integration_run", "notify": "test"}
	for _, k := range Kinds {
		e := sampleEnvelope()
		e.Kind, e.Item.Type, e.Item.Link = k.Kind, types[k.Source], "/x"
		m, err := composer.Email(e, k.Label)
		if err != nil || !strings.Contains(m.Text, k.Label) || strings.Contains(m.Text, "the item") {
			t.Errorf("%s: %v\n%s", k.Kind, err, m.Text)
		}
	}
}

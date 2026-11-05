package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRejectsIncompleteEvents(t *testing.T) {
	for _, e := range []Event{
		{Severity: SeverityInfo, Actor: "a"},
		{Type: "x", Actor: "a"},
		{Type: "x", Severity: SeverityInfo},
		{Type: "x", Severity: "bogus", Actor: "a"},
	} {
		if _, err := Normalize(e, time.Now()); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("Normalize(%+v) err=%v, want ErrInvalidEvent", e, err)
		}
	}
}

func TestNormalizeFillsIDAndTime(t *testing.T) {
	e, err := Normalize(Event{Type: "x", Severity: SeverityHigh, Actor: "a"}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.ID) != 32 || e.Time.IsZero() {
		t.Fatalf("id=%q time=%v", e.ID, e.Time)
	}
}

func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	j := NewJSONLines(&buf)
	if err := j.Emit(context.Background(), Event{Type: "setting.changed", Severity: SeverityHigh, Actor: "u1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "audit" || got["type"] != "setting.changed" || got["severity"] != "high" {
		t.Fatalf("unexpected record: %v", got)
	}
}

type failing struct{}

func (failing) Emit(context.Context, Event) error { return errors.New("sink down") }

func TestMultiReportsFailures(t *testing.T) {
	m := NewMemory()
	err := Multi{m, failing{}}.Emit(context.Background(), Event{Type: "x", Severity: SeverityInfo, Actor: "a"})
	if err == nil {
		t.Fatal("Multi must surface sink failures, never drop silently")
	}
	if len(m.Events()) != 1 {
		t.Fatal("healthy sinks must still receive the event")
	}
}

func TestMsgIDSanitized(t *testing.T) {
	if got := sanitizeMsgID("a b\x01c" + strings.Repeat("x", 40)); strings.ContainsAny(got, " \x01") || len(got) > 32 {
		t.Fatalf("msgid not sanitized: %q", got)
	}
}

// F-001 T-42: a request's reason reaches the events that have none.
func TestContextReason(t *testing.T) {
	mem := NewMemory()
	e := ContextReason{Next: mem}
	ctx := WithReason(context.Background(), "ticket 7")
	_ = e.Emit(ctx, Event{Type: "a", Severity: SeverityInfo, Actor: "u"})
	_ = e.Emit(ctx, Event{Type: "b", Severity: SeverityInfo, Actor: "u", Reason: "its own"})
	_ = e.Emit(context.Background(), Event{Type: "c", Severity: SeverityInfo, Actor: "u"})
	_ = e.Emit(WithReason(context.Background(), ""), Event{Type: "d", Severity: SeverityInfo, Actor: "u"})
	got := mem.Events()
	if got[0].Reason != "ticket 7" || got[1].Reason != "its own" || got[2].Reason != "" || got[3].Reason != "" {
		t.Fatalf("%+v", got)
	}
}

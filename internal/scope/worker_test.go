package scope

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

func TestDailyAtNext(t *testing.T) {
	d := dailyAt(2 * time.Hour)
	for _, tc := range []struct{ now, want string }{
		{"2026-10-26T01:00:00Z", "2026-10-26T02:00:00Z"},
		{"2026-10-26T02:00:00Z", "2026-10-27T02:00:00Z"},
		{"2026-10-26T23:59:00Z", "2026-10-27T02:00:00Z"},
		{"2026-10-26T01:00:00-05:00", "2026-10-27T02:00:00Z"}, // 06:00 UTC: today's run has passed
	} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		want, _ := time.Parse(time.RFC3339, tc.want)
		if got := d.Next(now); !got.Equal(want) {
			t.Errorf("Next(%s) = %s, want %s", tc.now, got, want)
		}
	}
}

type failingEmitter struct{}

func (failingEmitter) Emit(context.Context, audit.Event) error { return errors.New("sink down") }

func TestSendMapsAuditEvents(t *testing.T) {
	mem := audit.NewMemory()
	w := New(Options{Audit: mem})
	err := w.send(context.Background(), event{id: 7, topic: "audit", payload: []byte(
		`{"type":"bu.moved","severity":"info","actor":"u1","attributes":{"bu_id":"b","old_parent":"p0","new_parent":null}}`)})
	if err != nil {
		t.Fatal(err)
	}
	evs := mem.OfType("bu.moved")
	if len(evs) != 1 || evs[0].Actor != "u1" || evs[0].Attributes["old_parent"] != "p0" || evs[0].Attributes["event_id"] != "7" {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := evs[0].Attributes["new_parent"]; ok {
		t.Fatal("null attributes must be omitted")
	}

	w = New(Options{Audit: failingEmitter{}})
	if err := w.send(context.Background(), event{id: 8, topic: "audit", payload: []byte(`{"type":"x","severity":"info","actor":"a"}`)}); err == nil {
		t.Fatal("audit sink failure must be returned so the event stays queued")
	}
}

// T-37: target and reason reach the sink; an event the catalog does not
// describe is recorded as audit.invalid_event (critical, with the
// original) instead of holding back the outbox.
func TestSendValidatesAgainstTheCatalog(t *testing.T) {
	c, err := audit.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	mem := audit.NewMemory()
	w := New(Options{Audit: audit.Validating{Next: mem, Catalog: c}})
	ok := event{id: 8, topic: "audit", payload: []byte(`{"type":"role.retired","severity":"high","actor":"u1","target":"role:r1","reason":"unused","attributes":{"name":"R"}}`)}
	if err := w.send(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	if e := mem.OfType("role.retired"); len(e) != 1 || e[0].Target != "role:r1" || e[0].Reason != "unused" {
		t.Fatalf("%+v", e)
	}
	bad := event{id: 9, topic: "audit", payload: []byte(`{"type":"role.dance","severity":"high","actor":"u1"}`)}
	if err := w.send(context.Background(), bad); err != nil {
		t.Fatalf("an uncatalogued event held back the outbox: %v", err)
	}
	inv := mem.OfType("audit.invalid_event")
	if len(inv) != 1 || inv[0].Severity != audit.SeverityCritical || inv[0].Target != "event:9" || !strings.Contains(inv[0].Attributes["payload"], "role.dance") {
		t.Fatalf("%+v", inv)
	}
	if len(mem.OfType("role.dance")) != 0 {
		t.Fatal("the uncatalogued event reached the sink")
	}
	// A failing sink still fails the delivery (audit fails closed).
	w = New(Options{Audit: audit.Validating{Next: failingEmitter{}, Catalog: c}})
	if err := w.send(context.Background(), ok); err == nil {
		t.Fatal("a sink failure was swallowed")
	}
}

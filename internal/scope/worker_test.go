package scope

import (
	"context"
	"errors"
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

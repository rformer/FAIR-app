package scope

import (
	"context"
	"strings"
	"testing"
	"time"
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

// F-002 T-06: audit events reach the trail in their producer's
// transaction (an iam.event_outbox trigger), never through the worker; a
// stray audit row is refused, not relayed.
func TestSendRefusesAuditRows(t *testing.T) {
	w := New(Options{})
	err := w.send(context.Background(), event{id: 7, topic: "audit", payload: []byte(`{"type":"bu.moved","severity":"info","actor":"u1"}`)})
	if err == nil || !strings.Contains(err.Error(), "trail") {
		t.Fatalf("an audit row was relayed: %v", err)
	}
}

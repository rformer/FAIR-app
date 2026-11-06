package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-20 (F-002-AC-30, AC-31; design §6.8): audit storage capacity.

func TestAuditCapacity(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	seq := auditsvc.Sequencer{DB: pool}
	emitter := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})
	submitN(t, e, "cap", 5)
	drainTrail(t, seq)

	// used measures the schema now (a huge quota: level ok).
	used := func() int64 {
		t.Helper()
		r, err := auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: 1 << 50}.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return r.Used
	}
	// at measures with a quota that puts usage at about pct percent.
	at := func(pct int64) auditsvc.CapacityResult {
		t.Helper()
		u := used()
		r, err := auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: u * 100 / pct}.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	events := func(typ string) []map[string]any {
		t.Helper()
		drainTrail(t, seq)
		return trailEventsOf(t, e, typ)
	}
	finding := func() string {
		return e.adminQuery("SELECT coalesce((SELECT status || '/' || severity FROM posture.drift_finding WHERE check_id = 'audit_capacity' AND status <> 'resolved'), 'none')")
	}

	if u := used(); u <= 0 || finding() != "none" {
		t.Fatalf("baseline: used %d, finding %s", u, finding())
	}

	// 75%: a warning, and the finding at high severity.
	if r := at(80); r.Level != "warning" || r.Finding != "opened" {
		t.Fatalf("at 80%%: %+v", r)
	}
	if got := finding(); got != "open/high" {
		t.Fatalf("finding at warning: %s", got)
	}
	warn := events("audit.capacity_warning")
	if len(warn) != 1 || warn[0]["severity"] != "high" || attrs(warn[0])["level"] != "warning" || attrs(warn[0])["used_bytes"] == nil {
		t.Fatalf("audit.capacity_warning %v", warn)
	}
	// Measuring with room resolves it; rising again records again; holding
	// a level records nothing more.
	quota := used() * 100 / 80
	if got := finding(); got != "none" {
		t.Fatalf("finding with room: %s", got)
	}
	m := auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: quota}
	if r, err := m.Step(ctx); err != nil || r.Level != "warning" || r.Previous != "ok" {
		t.Fatalf("warning again: %+v %v", r, err)
	}
	if r, err := m.Step(ctx); err != nil || r.Level != "warning" || r.Previous != "warning" || r.Finding != "refreshed" {
		t.Fatalf("still warning: %+v %v", r, err)
	}
	if n := len(events("audit.capacity_warning")); n != 2 {
		t.Fatalf("%d warnings, want one per rise", n)
	}

	// 90%: critical, and the finding becomes critical.
	if r, err := (auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: used() * 100 / 95}).Step(ctx); err != nil || r.Level != "critical" {
		t.Fatalf("at 95%%: %+v %v", r, err)
	}
	crit := events("audit.capacity_critical")
	if len(crit) != 1 || crit[0]["severity"] != "critical" || attrs(crit[0])["level"] != "critical" {
		t.Fatalf("audit.capacity_critical %v", crit)
	}
	if got := finding(); got != "open/critical" {
		t.Fatalf("finding at critical: %s", got)
	}

	// Full: other services' events are refused, so their operations fail;
	// nothing is dropped. The audit service still records its own.
	if r := at(120); r.Level != "full" {
		t.Fatalf("at 120%%: %+v", r)
	}
	intake := e.adminQuery("SELECT count(*) FROM audit.intake")
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		out, err := e.as(role, `SELECT audit.submit('{"type": "db.migrated", "severity": "info", "actor": "x"}')`)
		if err == nil || !strings.Contains(out, "the audit trail is full") {
			t.Fatalf("%s submitted while full: %s %v", role, out, err)
		}
	}
	if got := e.adminQuery("SELECT count(*) FROM audit.intake"); got != intake {
		t.Fatalf("intake %s -> %s while full", intake, got)
	}
	// A whole operation fails with its event: a Go producer's transaction.
	if err := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: e.appPool()}).Emit(ctx,
		audit.Event{Type: "db.migrated", Severity: audit.SeverityInfo, Actor: "x"}); err == nil {
		t.Fatal("a Go producer recorded an event while full")
	}
	// The audit service's own events are still recorded.
	if err := emitter.Emit(ctx, audit.Event{Type: "audit.searched", Severity: audit.SeverityLow, Actor: "system:audit",
		Attributes: map[string]string{"view": "status", "filter": "{}", "result_count": "1"}}); err != nil {
		t.Fatalf("the audit service's own event refused: %v", err)
	}
	var st struct {
		Storage map[string]any `json:"storage"`
	}
	_ = json.Unmarshal([]byte(e.adminQuery("SELECT audit.status()")), &st)
	if st.Storage["level"] != "full" || st.Storage["quota"] == nil || st.Storage["used"] == nil || st.Storage["percent"] == nil {
		t.Fatalf("status storage %v", st.Storage)
	}

	// Room again: events are accepted and the finding resolves.
	used()
	if _, err := e.as("app_rw", `SELECT audit.submit('{"type": "db.migrated", "severity": "info", "actor": "x"}')`); err != nil {
		t.Fatalf("submit after room was made: %v", err)
	}
	if got := finding(); got != "none" {
		t.Fatalf("finding with room: %s", got)
	}
	e.mustFail("app_audit", "SELECT * FROM audit.capacity_measure(0)", "positive quota")
	e.mustFail("app_rw", "SELECT * FROM audit.capacity_measure(1000)", "permission denied")
}

package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-18 (AC-27 - AC-29): automatic revert. Time travel moves an
// exception's timestamps; the rules use the database clock.

// timeTravel moves an exception's times (or retry schedule) as the posture
// functions would, as posture_definer, so its row MAC stays valid (T-36);
// a direct edit by any other role is tampering that drift reports.
func (e *env) timeTravel(sql string) {
	e.t.Helper()
	e.admin(e.db, "SET ROLE posture_definer; "+sql)
}

func expire(e *env, exceptionID string) {
	e.timeTravel("UPDATE posture.exception SET created_at = now() - interval '30 days', expires_at = now() - interval '1 second' WHERE id = '" + exceptionID + "'")
}

func exceptionState(e *env, id string) string {
	return e.adminQuery("SELECT state || ':' || revert_attempts FROM posture.exception WHERE id = '" + id + "'")
}

// AC-27 (ported from the T-00b TestExceptionAutoRevertAndNotices): an
// expired exception reverts to the active profile's value, audited (high)
// and notified, and can no longer be renewed.
func TestRevertOnExpiry(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pool := e.posturePool()
	x := approvedException(t, e, ev, 30*24*time.Hour)

	mem := audit.NewMemory()
	if out, err := posture.RevertDue(ctx, pool, mem, nil); err != nil || len(out) != 0 {
		t.Fatalf("reverted before expiry: %+v %v", out, err)
	}
	expire(e, x.ID)
	out, err := posture.RevertDue(ctx, pool, mem, nil)
	if err != nil || len(out) != 1 || out[0].Err != nil || out[0].ExceptionID != x.ID {
		t.Fatalf("revert: %+v %v", out, err)
	}
	if got := valueOf(e, settings.KeyAuthInactiveDisable); got != `"2160h0m0s":revert` {
		t.Fatalf("after revert: %s", got)
	}
	if got := exceptionState(e, x.ID); got != "reverted:0" {
		t.Fatalf("exception %s", got)
	}
	if a := mem.OfType("setting.exception_reverted"); len(a) != 1 || a[0].Severity != audit.SeverityHigh || a[0].Actor != posture.RevertActor {
		t.Fatalf("revert audit %+v", a)
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.notice_outbox WHERE kind = 'setting.exception_reverted'"); got != "1" {
		t.Fatalf("%s revert notices", got)
	}
	if out, _ := posture.RevertDue(ctx, pool, mem, nil); len(out) != 0 {
		t.Fatal("reverted twice")
	}
	if _, err := ev.RequestRenewal(ctx, e.principal("admin"), x.ID, "more time", 0); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("renewal after expiry must be refused (AC-26): %v", err)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
}

// Ported from the T-00b TestRenewalBeforeExpiry: a renewed exception does
// not revert at the original expiry.
func TestRevertSkipsRenewed(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	old := approvedException(t, e, ev, 10*24*time.Hour)
	r, err := ev.RequestRenewal(ctx, e.principal("admin"), old.ID, "integration not yet migrated", 10*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, e.principal("admin2"), r.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	renewed, err := ev.ApplyRenewal(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	expire(e, old.ID) // the original's expiry passes
	if out, _ := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); len(out) != 0 {
		t.Fatal("renewed exception must not revert at the original expiry")
	}
	if got := e.adminQuery("SELECT source || ':' || (exception_id = '" + renewed.ID + "') FROM posture.setting_value WHERE key = 'auth.inactive_disable_after' AND bu_id IS NULL"); got != "exception:true" {
		t.Fatalf("value after the original expired: %s", got)
	}
}

// Verification for T-18 (fault injection, AC-29): a revert that fails is
// retried with backoff, raises a critical revert_failed finding that stays
// open until a revert succeeds, and escalates hourly; the setting is never
// silently out of bounds.
func TestRevertFaultInjection(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pool := e.posturePool()
	x := approvedException(t, e, ev, 0)
	expire(e, x.ID)
	finding := func() string {
		return e.adminQuery("SELECT coalesce(string_agg(severity || ':' || status || ':' || (detail->>'attempts'), ','), '') FROM posture.drift_finding WHERE check_id = 'revert_failed'")
	}
	due := func() { e.timeTravel("UPDATE posture.exception SET revert_next_at = now() WHERE id = '" + x.ID + "'") }

	// Fault 1: the audit sink is down, so the revert cannot be recorded and rolls back.
	out, err := posture.RevertDue(ctx, pool, failingEmitter{}, nil)
	if err != nil || len(out) != 1 || out[0].Err == nil || !out[0].Escalated {
		t.Fatalf("first failure: %+v %v", out, err)
	}
	if got := exceptionState(e, x.ID); got != "revert_failed:1" {
		t.Fatalf("after failure: %s", got)
	}
	if got := finding(); got != "critical:open:1" {
		t.Fatalf("finding %s", got)
	}
	if got := valueOf(e, settings.KeyAuthInactiveDisable); got != `"8760h0m0s":exception` {
		t.Fatalf("value after a failed revert: %s", got)
	}
	// Backoff: not retried at once.
	if out, _ := posture.RevertDue(ctx, pool, failingEmitter{}, nil); len(out) != 0 {
		t.Fatal("retried before the backoff")
	}
	// Retried when due; within the hour, no second escalation.
	due()
	mem := audit.NewMemory()
	out, _ = posture.RevertDue(ctx, pool, failingEmitter{}, nil)
	if len(out) != 1 || out[0].Escalated {
		t.Fatalf("second failure: %+v", out)
	}
	if got := finding(); got != "critical:open:2" {
		t.Fatalf("finding after retry %s (one open finding, refreshed)", got)
	}
	if got := e.adminQuery("SELECT revert_next_at - now() BETWEEN interval '9 seconds' AND interval '10 seconds' FROM posture.exception WHERE id = '" + x.ID + "'"); got != "t" {
		t.Fatalf("second backoff: %s", got)
	}
	// An hour later the escalation repeats.
	e.admin(e.db, "UPDATE posture.drift_finding SET last_escalated_at = now() - interval '61 minutes'")
	due()
	out, _ = posture.RevertDue(ctx, pool, failingEmitter{}, nil)
	if len(out) != 1 || !out[0].Escalated {
		t.Fatalf("hourly escalation: %+v", out)
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.notice_outbox WHERE kind = 'setting.revert_failed'"); got != "2" {
		t.Fatalf("%s escalation notices, want 2", got)
	}

	// Fault 2: a dependency is unavailable (no usable MAC key), audit works.
	e.mustOwner("SELECT posture.retire_mac_key('k1')")
	due()
	out, _ = posture.RevertDue(ctx, pool, mem, nil)
	if len(out) != 1 || out[0].Err == nil {
		t.Fatalf("revert without a MAC key: %+v", out)
	}
	if a := mem.OfType("setting.revert_failed"); len(a) != 1 || a[0].Severity != audit.SeverityCritical {
		t.Fatalf("failure audit %+v", mem.Events())
	}

	// Restored: the next due attempt reverts and resolves the finding.
	addMACKey(e, "k2")
	due()
	out, _ = posture.RevertDue(ctx, pool, mem, nil)
	if len(out) != 1 || out[0].Err != nil {
		t.Fatalf("recovery: %+v", out)
	}
	if got := finding(); got != "critical:resolved:4" {
		t.Fatalf("finding after recovery %s", got)
	}
	if got := exceptionState(e, x.ID) + " " + valueOf(e, settings.KeyAuthInactiveDisable); got != `reverted:4 "2160h0m0s":revert` {
		t.Fatalf("after recovery: %s", got)
	}
	e.wantState("app_rw", "PERFORM posture.due_reverts()", "42501")
	e.wantState("app_rw", "PERFORM 1 FROM posture.drift_finding", "42501")
}

// AC-28: an expired exception's revert reaches services within 60 s with
// the service's loop (10 s) and the settings library's poll (30 s), even
// without change events.
func TestRevertWithin60Seconds(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	e, ev, _, _ := evaluatorFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := approvedException(t, e, ev, 0)
	c := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: e.appPool()}, Service: "iam"})
	if err := c.Register(settings.F001Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var loopErr error
	go c.Run(ctx, nil)
	go posture.RunReverts(ctx, e.posturePool(), audit.NewMemory(), nil, 10*time.Second, func(err error) { mu.Lock(); loopErr = err; mu.Unlock() })

	e.timeTravel("UPDATE posture.exception SET created_at = now() - interval '30 days', expires_at = now() + interval '1 second' WHERE id = '" + x.ID + "'")
	expired := time.Now().Add(time.Second)
	for {
		if d, err := c.Duration(settings.KeyAuthInactiveDisable, ""); err == nil && d == 90*24*time.Hour {
			break
		}
		if time.Since(expired) > 60*time.Second {
			t.Fatal("revert not in force at the service within 60 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if loopErr != nil {
		t.Fatal(loopErr)
	}
	t.Logf("revert in force at the service %v after expiry (requirement: 60 s)", time.Since(expired).Round(time.Second))
}

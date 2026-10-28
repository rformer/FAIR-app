package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-17 (AC-24 - AC-26): exception lifecycle. "Time travel" moves an
// exception's timestamps; every rule is evaluated against the database clock.

// approvedException creates an approved exception for an out-of-bounds
// Enterprise change (inactive-disable to a year) lasting d (0 = default).
func approvedException(t *testing.T, e *env, ev posture.Evaluator, d time.Duration) posture.Exception {
	t.Helper()
	ctx := context.Background()
	res, err := ev.Change(ctx, e.principal("admin"), posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable,
		Value: json.RawMessage(`"8760h0m0s"`), Explanation: "contractors", ExceptionDuration: d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, e.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := ev.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func within(t *testing.T, got time.Time, want time.Duration) {
	t.Helper()
	if d := time.Until(got); d < want-time.Minute || d > want+time.Minute {
		t.Fatalf("expires in %v, want %v", d, want)
	}
}

// AC-24: every exception expires: 90 days by default, a shorter duration on
// request, never longer than exception.max_duration in force.
func TestExceptionDuration(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	within(t, approvedException(t, e, ev, 0).ExpiresAt, 90*24*time.Hour)

	e2, ev2, _, _ := evaluatorFixture(t)
	within(t, approvedException(t, e2, ev2, 30*24*time.Hour).ExpiresAt, 30*24*time.Hour)

	e3, ev3, _, _ := evaluatorFixture(t)
	admin := e3.principal("admin")
	for _, d := range []time.Duration{200 * 24 * time.Hour, -time.Hour} {
		_, err := ev3.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable, Value: json.RawMessage(`"8760h0m0s"`),
			Explanation: "x", ExceptionDuration: d})
		if !errors.Is(err, posture.ErrExpiryOutOfRange) && !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("duration %v: %v", d, err)
		}
	}
	if n := e3.adminQuery("SELECT count(*) FROM posture.change"); n != "0" {
		t.Fatalf("refused durations recorded %s changes", n)
	}
	// Requested 60 days; the maximum is tightened to 30 days before approval: clamped.
	res, err := ev3.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable, Value: json.RawMessage(`"8760h0m0s"`),
		Explanation: "x", ExceptionDuration: 60 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev3.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyExceptionMaxDuration, Value: json.RawMessage(`"720h0m0s"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: e3.appPool()}).Decide(ctx, e3.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := ev3.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	within(t, x.ExpiresAt, 30*24*time.Hour)
}

// AC-26: renewal only before expiry, with a new justification and dual
// approval, as a new exception linked to the original.
func TestExceptionRenewal(t *testing.T) {
	e, ev, mem, _ := evaluatorFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	old := approvedException(t, e, ev, 0)

	if _, err := ev.RequestRenewal(ctx, admin, old.ID, " ", 0); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("renewal without justification: %v", err)
	}
	if _, err := ev.RequestRenewal(ctx, e.principal("auditor"), old.ID, "still needed", 0); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor renewal: %v", err)
	}
	r, err := ev.RequestRenewal(ctx, admin, old.ID, "contract extended to March", 14*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ev := mem.OfType("setting.exception_renewal_requested"); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh {
		t.Fatalf("renewal request audit %+v", ev)
	}
	if _, err := ev.ApplyRenewal(ctx, r.ID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("apply before approval: %v", err)
	}
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, r.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approved renewal: %v", err)
	}
	if _, err := appr.Decide(ctx, admin2, r.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := ev.ApplyRenewal(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	within(t, x.ExpiresAt, 14*24*time.Hour)
	if got := e.adminQuery(`SELECT o.state || ':' || (n.renewed_from = o.id) || ':' || n.state || ':' || n.justification || ':' ||
		(s.exception_id = n.id) FROM posture.exception o, posture.exception n, posture.setting_value s
		WHERE o.id = '` + old.ID + `' AND n.id = '` + x.ID + `' AND s.key = 'auth.inactive_disable_after' AND s.bu_id IS NULL`); got !=
		"renewed:true:active:contract extended to March:true" {
		t.Fatalf("after renewal: %s", got)
	}
	if a := mem.OfType("setting.exception_renewed"); len(a) != 1 || a[0].Severity != audit.SeverityHigh || a[0].Actor != admin2.UserID {
		t.Fatalf("renewal audit %+v", a)
	}
	if _, err := ev.ApplyRenewal(ctx, r.ID); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second apply: %v", err)
	}
	// The renewed (old) exception cannot be renewed again.
	if _, err := ev.RequestRenewal(ctx, admin, old.ID, "again", 0); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("renewing a renewed exception: %v", err)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}

	// Only before expiry: after the moment passes, neither request nor apply.
	r2, err := ev.RequestRenewal(ctx, admin, x.ID, "once more", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appr.Decide(ctx, admin2, r2.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	e.timeTravel("UPDATE posture.exception SET created_at = created_at - interval '20 days', expires_at = now() - interval '1 second' WHERE id = '" + x.ID + "'")
	if _, err := ev.ApplyRenewal(ctx, r2.ID); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("applying a renewal after expiry: %v", err)
	}
	if _, err := ev.RequestRenewal(ctx, admin, x.ID, "too late", 0); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("renewal after expiry: %v", err)
	}
}

// AC-25: the owner and admins are notified 14, 7 and 1 day(s) before expiry,
// once each.
func TestExceptionNotices(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pool := e.posturePool()
	x := approvedException(t, e, ev, 0)
	travel := func(left string) {
		e.timeTravel("UPDATE posture.exception SET created_at = least(created_at, now() - interval '1 day'), expires_at = now() + interval '" + left + "' WHERE id = '" + x.ID + "'")
	}
	run := func(want ...int) {
		t.Helper()
		mem := audit.NewMemory()
		got, err := posture.ExceptionNotices(ctx, pool, mem)
		if err != nil {
			t.Fatal(err)
		}
		var days []int
		for _, n := range got {
			days = append(days, n.DaysBefore)
			if n.OwnerID != e.principal("admin").UserID {
				t.Fatalf("notice owner %s", n.OwnerID)
			}
		}
		if len(days) != len(want) || (len(want) == 1 && days[0] != want[0]) {
			t.Fatalf("notices %v, want %v", days, want)
		}
		if len(mem.OfType("setting.exception_expiring")) != len(want) {
			t.Fatalf("audit events %+v", mem.Events())
		}
	}
	run() // 90 days left
	travel("13 days 23 hours")
	run(14)
	run() // once only
	travel("6 days 23 hours")
	run(7)
	travel("23 hours")
	run(1)
	run()
	if got := e.adminQuery(`SELECT string_agg((payload->>'days_before') || ':' || (recipients->'users'->>0 = '` + e.principal("admin").UserID + `') || ':' ||
		(recipients->>'permission_holders'), ',' ORDER BY id) FROM posture.notice_outbox`); got != "14:true:settings.approve,7:true:settings.approve,1:true:settings.approve" {
		t.Fatalf("notice outbox %s", got)
	}

	// A short exception crosses several thresholds at once: only the nearest is sent.
	e2, ev2, _, _ := evaluatorFixture(t)
	approvedException(t, e2, ev2, 5*24*time.Hour)
	got, err := posture.ExceptionNotices(ctx, e2.posturePool(), audit.NewMemory())
	if err != nil || len(got) != 1 || got[0].DaysBefore != 7 {
		t.Fatalf("5-day exception notices %+v %v", got, err)
	}
	if rec := e2.adminQuery("SELECT string_agg(days_before || ':' || sent, ',' ORDER BY days_before) FROM posture.exception_notice"); rec != "7:true,14:false" {
		t.Fatalf("recorded %s", rec)
	}

	// Audit failure records nothing; the next run retries.
	e3, ev3, _, _ := evaluatorFixture(t)
	approvedException(t, e3, ev3, 5*24*time.Hour)
	if _, err := posture.ExceptionNotices(ctx, e3.posturePool(), failingEmitter{}); err == nil {
		t.Fatal("notices recorded without audit")
	}
	if n := e3.adminQuery("SELECT count(*) FROM posture.exception_notice"); n != "0" {
		t.Fatalf("%s notices recorded without audit", n)
	}
	if got, err := posture.ExceptionNotices(ctx, e3.posturePool(), audit.NewMemory()); err != nil || len(got) != 1 {
		t.Fatalf("retry: %+v %v", got, err)
	}
}

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-14 (AC-20 - AC-22, AC-30, AC-31): the change evaluator, path by
// path, with its audit events.

type recordingPublisher struct {
	mu   sync.Mutex
	msgs []settings.ChangedEvent
}

func (p *recordingPublisher) Publish(_ context.Context, subject, _ string, data []byte) error {
	var e settings.ChangedEvent
	if err := json.Unmarshal(data, &e); err != nil || subject != settings.SubjectChanged {
		return errors.New("bad event")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.msgs = append(p.msgs, e)
	return nil
}

// evaluatorFixture: two Platform Admins and an Auditor, a MAC key, the
// Enterprise Baseline seeded (it has room for in-bounds loosening), and the
// F-001 settings registered.
func evaluatorFixture(t *testing.T) (*env, posture.Evaluator, *audit.Memory, *recordingPublisher) {
	e := setup(t)
	ctx := context.Background()
	postureAdmins(e)
	e.mustOwner("INSERT INTO iam.app_user (email) VALUES ('auditor@example.test')")
	e.mustOwner(grant("admin", "user:auditor", "Auditor", "ENTERPRISE"))
	e.drain()
	addMACKey(e, "k1")
	if _, err := posture.Seed(ctx, e.posturePool(), audit.NewMemory(), "system:installer", settings.ProfileEnterpriseBaseline, ""); err != nil {
		t.Fatal(err)
	}
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-001", "1", settings.F001Defs()); err != nil {
		t.Fatal(err)
	}
	mem, pub := audit.NewMemory(), &recordingPublisher{}
	return e, posture.Evaluator{DB: e.posturePool(), Audit: mem, Publish: pub}, mem, pub
}

func valueOf(e *env, key string) string {
	return e.adminQuery("SELECT value::text || ':' || source FROM posture.setting_value WHERE key = '" + key + "' AND bu_id IS NULL")
}

func onlyEvent(t *testing.T, mem *audit.Memory, typ string, sev audit.Severity) audit.Event {
	t.Helper()
	ev := mem.OfType(typ)
	if len(ev) != 1 || ev[0].Severity != sev {
		t.Fatalf("%s events: %+v (all: %d)", typ, ev, len(mem.Events()))
	}
	return ev[0]
}

func TestEvaluatorTightenAndInBounds(t *testing.T) {
	e, ev, mem, pub := evaluatorFixture(t)
	ctx := context.Background()
	admin := e.principal("admin")

	// AC-22: tightening applies at once, no approval.
	res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"10m0s"`)})
	if err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" || res.Warning != nil || res.PublishErr != nil {
		t.Fatalf("tighten: %+v %v", res, err)
	}
	if got := valueOf(e, settings.KeySessionIdleTimeout); got != `"10m0s":change` {
		t.Fatalf("after tighten: %s", got)
	}
	if a := onlyEvent(t, mem, "setting.changed", audit.SeverityInfo); a.Actor != admin.UserID || a.Attributes["previous"] != `"15m0s"` {
		t.Fatalf("tighten audit %+v", a)
	}

	// AC-20: loosening within the profile's bounds (Enterprise allows 30m) applies and is audited, flagged low.
	mem2 := audit.NewMemory()
	ev.Audit = mem2
	res, err = ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"30m0s"`)})
	if err != nil || res.Outcome != posture.Applied || res.Direction != "loosen" {
		t.Fatalf("in-bounds loosen: %+v %v", res, err)
	}
	onlyEvent(t, mem2, "setting.changed", audit.SeverityLow)
	if len(pub.msgs) != 2 || pub.msgs[1].Key != settings.KeySessionIdleTimeout || pub.msgs[1].Version <= pub.msgs[0].Version {
		t.Fatalf("published %+v", pub.msgs)
	}
	// FIPS may be switched off in Enterprise: its floor covers FedRAMP and CMMC only.
	if res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyFIPSEnabled, Value: json.RawMessage(`false`)}); err != nil || res.Outcome != posture.Applied {
		t.Fatalf("FIPS off in Enterprise: %+v %v", res, err)
	}
}

// AC-30, AC-31: weakening a hard-floor setting is refused and audited (high).
func TestEvaluatorHardFloor(t *testing.T) {
	e, ev, mem, _ := evaluatorFixture(t)
	ctx := context.Background()
	admin := e.principal("admin")
	before := e.adminQuery("SELECT count(*) FROM posture.change")
	for _, c := range []struct{ key, value string }{
		{settings.KeyTLSMinVersion, `"1.1"`}, {settings.KeyAuditEnabled, `false`}, {settings.KeyAuthMFAPrivileged, `false`}, {settings.KeyRLSEnforced, `false`},
	} {
		_, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: c.key, Value: json.RawMessage(c.value), Explanation: "please"})
		if !errors.Is(err, posture.ErrHardFloor) {
			t.Errorf("%s = %s: %v", c.key, c.value, err)
		}
	}
	if got := len(mem.OfType("setting.hard_floor_refused")); got != 4 {
		t.Fatalf("%d refusal events, want 4", got)
	}
	for _, a := range mem.OfType("setting.hard_floor_refused") {
		if a.Severity != audit.SeverityHigh || a.Actor != admin.UserID {
			t.Fatalf("refusal event %+v", a)
		}
	}
	if after := e.adminQuery("SELECT count(*) FROM posture.change"); after != before {
		t.Fatalf("a refused change was recorded (%s -> %s)", before, after)
	}
	// If the refusal cannot be audited, the caller is told.
	ev.Audit = failingEmitter{}
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyTLSMinVersion, Value: json.RawMessage(`"1.0"`)}); !errors.Is(err, posture.ErrHardFloor) || !strings.Contains(err.Error(), "could not be audited") {
		t.Fatalf("unaudited refusal: %v", err)
	}
}

// AC-21: out of bounds needs an explanation, shows the warning, needs a
// second approver, and then applies as an exception with a high-severity
// event.
func TestEvaluatorOutOfBounds(t *testing.T) {
	e, ev, mem, pub := evaluatorFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	req := posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable, Value: json.RawMessage(`"8760h0m0s"`)} // a year; Enterprise allows 180 days

	res, err := ev.Change(ctx, admin, req)
	if !errors.Is(err, posture.ErrExplanationRequired) || res.Warning == nil {
		t.Fatalf("without explanation: %+v %v", res, err)
	}
	w := res.Warning
	if string(w.Bound) != `"4320h0m0s"` || !slices.Equal(w.Controls, []string{"AC-2(3)"}) || !slices.Equal(w.Params, []string{"ac-02.03_odp.02"}) ||
		!strings.Contains(w.Message, "AC-2(3)") {
		t.Fatalf("warning %+v", w)
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.change"); n != "0" || len(mem.Events()) != 0 {
		t.Fatalf("a refused request wrote %s changes and %d events", n, len(mem.Events()))
	}

	req.Explanation = "Seasonal contractors return each autumn"
	res, err = ev.Change(ctx, admin, req)
	if err != nil || res.Outcome != posture.PendingApproval || res.ApprovalID == "" || res.Warning == nil {
		t.Fatalf("with explanation: %+v %v", res, err)
	}
	if a := onlyEvent(t, mem, "setting.change_requested", audit.SeverityHigh); a.Reason != req.Explanation || a.Attributes["controls"] != "AC-2(3)" {
		t.Fatalf("request audit %+v", a)
	}
	if got := valueOf(e, settings.KeyAuthInactiveDisable); got != `"2160h0m0s":profile` {
		t.Fatalf("pending change already applied: %s", got)
	}
	if _, err := ev.ApplyApproved(ctx, res.ChangeID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("apply before approval: %v", err)
	}

	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, res.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if st, err := appr.Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil || st != approvals.Approved {
		t.Fatalf("second admin approves: %v %v", st, err)
	}
	x, err := ev.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	if x.ApprovedBy != admin2.UserID || x.OwnerID != admin.UserID || string(x.Value) != `"8760h0m0s"` {
		t.Fatalf("exception %+v", x)
	}
	// AC-24: expiry from exception.max_duration in force (90 days).
	if d := time.Until(x.ExpiresAt); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("exception expires in %v, want about 90 days", d)
	}
	if got := valueOf(e, settings.KeyAuthInactiveDisable); got != `"8760h0m0s":exception` {
		t.Fatalf("after approval: %s", got)
	}
	if a := onlyEvent(t, mem, "setting.exception_created", audit.SeverityHigh); a.Actor != admin2.UserID || a.Attributes["exception_id"] != x.ID {
		t.Fatalf("exception audit %+v", a)
	}
	if len(pub.msgs) != 1 || pub.msgs[0].Key != settings.KeyAuthInactiveDisable {
		t.Fatalf("published %+v", pub.msgs)
	}
	if _, err := ev.ApplyApproved(ctx, res.ChangeID); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second apply: %v", err)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
}

func TestEvaluatorAuthorization(t *testing.T) {
	e, ev, mem, _ := evaluatorFixture(t)
	ctx := context.Background()
	req := posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"10m0s"`)}
	if _, err := ev.Change(ctx, e.principal("auditor"), req); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor: %v", err)
	}
	noCtx := e.principal("admin")
	noCtx.DBToken = ""
	if _, err := ev.Change(ctx, noCtx, req); !errors.Is(err, posture.ErrNoContext) {
		t.Fatalf("no context: %v", err)
	}
	for _, bad := range []posture.ChangeRequest{
		{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`15`)},
		{Key: "no.such_setting", Value: json.RawMessage(`1`)},
		{Key: settings.KeySessionIdleTimeout, BUID: e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL"), Value: json.RawMessage(`"5m0s"`)},
	} {
		if _, err := ev.Change(ctx, e.principal("admin"), bad); !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	// No audit, no change: a failing audit sink rolls the change back.
	ev.Audit = failingEmitter{}
	if _, err := ev.Change(ctx, e.principal("admin"), req); err == nil || !strings.Contains(err.Error(), "audit sink down") {
		t.Fatalf("change with a failing audit sink: %v", err)
	}
	if got := valueOf(e, settings.KeySessionIdleTimeout); got != `"15m0s":profile` || e.adminQuery("SELECT count(*) FROM posture.change") != "0" {
		t.Fatalf("an unaudited change was kept: %s", got)
	}
	if len(mem.Events()) != 0 {
		t.Fatalf("unexpected events %+v", mem.Events())
	}
}

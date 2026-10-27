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

// F-015 T-21 (AC-07, AC-16 - AC-19): the profile switch.

func activeProfile(e *env) string {
	return e.adminQuery("SELECT profile_id || '@' || version FROM posture.active_profile")
}

// Verification for T-21: activation is blocked while any conflict is
// unresolved, and is rollback-safe.
func TestSwitchConflictsAndActivation(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t) // Enterprise Baseline active
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	mem := audit.NewMemory()
	sw := posture.Switches{DB: e.appPool(), Audit: mem}
	// Explicit values Enterprise allows but FedRAMP does not.
	for _, c := range []struct{ key, value string }{{settings.KeySessionIdleTimeout, `"30m0s"`}, {settings.KeyFIPSEnabled, `false`}} {
		if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: c.key, Value: json.RawMessage(c.value)}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := sw.Request(ctx, e.principal("auditor"), settings.ProfileFedRAMPModerate, "1.0.0", ""); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor request: %v", err)
	}
	r, err := sw.Request(ctx, admin, settings.ProfileFedRAMPModerate, "1.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	// AC-16: only the explicit values; the Enterprise defaults (lockout 5) follow FedRAMP at activation.
	if r.Loosening || r.Conflicts != 2 {
		t.Fatalf("request %+v", r)
	}
	// AC-18: pending, and the current profile stays in force.
	ps, err := sw.Pending(ctx, admin)
	if err != nil || ps == nil || ps.Unresolved() != 2 || ps.Target != "fedramp-moderate@1.0.0" {
		t.Fatalf("pending %+v %v", ps, err)
	}
	if got := activeProfile(e); got != "enterprise-baseline@1.0.0" {
		t.Fatalf("active while pending: %s", got)
	}
	if _, err := sw.Request(ctx, admin, settings.ProfileCMMCL2R2, "1.0.0", ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second pending switch: %v", err)
	}

	// AC-17: no activation while anything is unresolved.
	if _, err := sw.Activate(ctx, admin, r.ID); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("activate with unresolved conflicts: %v", err)
	}
	// FIPS off is below FedRAMP's floor: conform only.
	if _, err := sw.Resolve(ctx, admin, r.ID, settings.KeyFIPSEnabled, "", posture.ExceptionAsIs, "lab", 0); !errors.Is(err, posture.ErrHardFloor) {
		t.Fatalf("exception below the floor: %v", err)
	}
	if _, err := sw.Resolve(ctx, admin, r.ID, settings.KeyFIPSEnabled, "", posture.Conform, "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Resolve(ctx, admin, r.ID, settings.KeySessionIdleTimeout, "", posture.ExceptionAsIs, "", 0); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("exception without reason: %v", err)
	}
	approval, err := sw.Resolve(ctx, admin, r.ID, settings.KeySessionIdleTimeout, "", posture.ExceptionAsIs, "call center rollout", 30*24*time.Hour)
	if err != nil || approval == "" {
		t.Fatalf("exception: %q %v", approval, err)
	}

	// Rollback-safe: an exception not yet approved stops activation, and nothing changes.
	before := e.adminQuery("SELECT string_agg(key || '=' || value::text || ':' || source, ',' ORDER BY key) FROM posture.setting_value")
	if _, err := sw.Activate(ctx, admin, r.ID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("activate before the exception's approval: %v", err)
	}
	if after := e.adminQuery("SELECT string_agg(key || '=' || value::text || ':' || source, ',' ORDER BY key) FROM posture.setting_value"); after != before || activeProfile(e) != "enterprise-baseline@1.0.0" {
		t.Fatal("a failed activation changed something")
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, approval, true, ""); err != nil {
		t.Fatal(err)
	}
	changed, err := sw.Activate(ctx, admin, r.ID)
	if err != nil || changed == 0 {
		t.Fatalf("activate: %d %v", changed, err)
	}
	if got := activeProfile(e); got != "fedramp-moderate@1.0.0" {
		t.Fatalf("active %s", got)
	}
	checks := map[string]string{
		settings.KeyFIPSEnabled:           `true:profile`, // conformed
		settings.KeyAuthLockoutThreshold:  `3:profile`,    // re-seeded from FedRAMP
		settings.KeySessionNetworkBinding: `"reauthenticate":profile`,
		settings.KeySessionIdleTimeout:    `"30m0s":exception`, // kept under the new exception
	}
	for k, want := range checks {
		if got := e.adminQuery("SELECT value::text || ':' || source FROM posture.setting_value WHERE key = '" + k + "' AND bu_id IS NULL"); got != want {
			t.Errorf("%s: %s, want %s", k, got, want)
		}
	}
	if got := e.adminQuery(`SELECT e.approved_by::text = '` + admin2.UserID + `' AND e.expires_at - now() BETWEEN interval '29 days' AND interval '30 days'
		FROM posture.exception e JOIN posture.switch_conflict c ON c.exception_id = e.id WHERE c.key = 'session.idle_timeout'`); got != "t" {
		t.Fatalf("switch exception: %s", got)
	}
	if got := e.adminQuery("SELECT string_agg(id || ':' || status, ',' ORDER BY id) FROM posture.profile WHERE status IN ('active', 'approved') AND kind = 'builtin'"); got != "cmmc-l2-r2:approved,enterprise-baseline:approved,fedramp-moderate:active" {
		t.Fatalf("profile statuses %s", got)
	}
	if ps, _ := sw.Pending(ctx, admin); ps != nil {
		t.Fatalf("still pending %+v", ps)
	}
	if ev := mem.OfType("profile.activated"); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh {
		t.Fatalf("activation audit %+v", ev)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
}

// AC-19: switching to weaker bounds needs a justification and dual
// approval, is audited high, and notifies SecOps in SaaS mode.
func TestSwitchLoosening(t *testing.T) {
	r := registryFixture(t, settings.ProfileFedRAMPModerate, "saas")
	e := r.e
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	mem := audit.NewMemory()
	sw := posture.Switches{DB: e.appPool(), Audit: mem}
	if _, err := sw.Request(ctx, admin, settings.ProfileEnterpriseBaseline, "1.0.0", ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("loosening without justification: %v", err)
	}
	req, err := sw.Request(ctx, admin, settings.ProfileEnterpriseBaseline, "1.0.0", "spin-off leaves federal scope")
	if err != nil || !req.Loosening || req.ApprovalID == "" || req.Conflicts != 0 {
		t.Fatalf("loosening request %+v %v", req, err)
	}
	if a := mem.OfType("profile.switch_requested"); len(a) != 1 || a[0].Severity != audit.SeverityHigh {
		t.Fatalf("request audit %+v", a)
	}
	if _, err := sw.Activate(ctx, admin, req.ID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("activate before approval: %v", err)
	}
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, req.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := appr.Decide(ctx, admin2, req.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Activate(ctx, admin, req.ID); err != nil {
		t.Fatal(err)
	}
	if got := activeProfile(e); got != "enterprise-baseline@1.0.0" {
		t.Fatalf("active %s", got)
	}
	if got := e.adminQuery("SELECT string_agg(event->>'type', ',') FROM posture.secops_outbox"); got != "profile.switched" {
		t.Fatalf("SecOps queue %s", got)
	}
	// The settings library sees the new profile.
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 15*time.Minute {
		t.Fatalf("idle after switch %v", d)
	}
	if err := r.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.client.Int(settings.KeyAuthLockoutThreshold, ""); n != 5 {
		t.Fatalf("lockout after switch %d, want the Enterprise default 5", n)
	}
}

// AC-07: a newer version of the active built-in profile goes through the
// same switch; its differences are shown first.
func TestSwitchToNewerBuiltin(t *testing.T) {
	r := registryFixture(t, settings.ProfileFedRAMPModerate, "self-hosted")
	e := r.e
	ctx := context.Background()
	admin := e.principal("admin")
	loadBase(t, e) // fedramp-moderate 1.1.0: idle relaxed, lockout and token tightened
	pr := posture.Profiles{DB: e.appPool(), Audit: audit.NewMemory()}
	diff, err := pr.Diff(ctx, admin, settings.ProfileFedRAMPModerate, "1.0.0", settings.ProfileFedRAMPModerate, "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]string{}
	for _, d := range diff {
		if d.Change != "unchanged" {
			changes[d.Key] = d.Change
		}
	}
	if len(changes) != 3 || changes[settings.KeySessionIdleTimeout] != "loosen" || changes[settings.KeyTokenMaxLifetime] != "tighten" {
		t.Fatalf("differences %v", changes)
	}
	sw := posture.Switches{DB: e.appPool(), Audit: audit.NewMemory()}
	req, err := sw.Request(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0", "FedRAMP baseline update")
	if err != nil || !req.Loosening {
		t.Fatalf("upgrade request %+v %v (relaxed idle timeout makes it a loosening)", req, err)
	}
	if err := sw.Cancel(ctx, admin, req.ID); err != nil {
		t.Fatal(err)
	}
	if ps, _ := sw.Pending(ctx, admin); ps != nil {
		t.Fatal("cancelled switch still pending")
	}
	// Cancelled: a new request is possible, and nothing changed.
	if _, err := sw.Request(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0", "again"); err != nil {
		t.Fatal(err)
	}
	if got := activeProfile(e); got != "fedramp-moderate@1.0.0" {
		t.Fatalf("active %s", got)
	}
}

// A value made weaker than the target after the request blocks activation.
func TestSwitchRefusesStaleConflicts(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	admin := e.principal("admin")
	sw := posture.Switches{DB: e.appPool(), Audit: audit.NewMemory()}
	req, err := sw.Request(ctx, admin, settings.ProfileFedRAMPModerate, "1.0.0", "")
	if err != nil || req.Conflicts != 0 {
		t.Fatalf("request %+v %v", req, err)
	}
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"25m0s"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Activate(ctx, admin, req.ID); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("activation over a new conflict: %v", err)
	}
	if got := activeProfile(e); got != "enterprise-baseline@1.0.0" {
		t.Fatalf("active %s", got)
	}
}

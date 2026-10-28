package tests

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-19 (AC-11 - AC-13): custom profiles.

func j(s string) json.RawMessage { return json.RawMessage(s) }

func profileRow(e *env, id string) string {
	return e.adminQuery("SELECT status || ':' || label_deviates || ':' || family || ':' || base_profile_id FROM posture.profile WHERE id = '" + id + "'")
}

func viewKey(t *testing.T, keys []posture.ProfileKey, key string) posture.ProfileKey {
	t.Helper()
	for _, k := range keys {
		if k.Key == key {
			return k
		}
	}
	t.Fatalf("%s not in the view", key)
	return posture.ProfileKey{}
}

func TestCustomProfileLifecycle(t *testing.T) {
	e, _, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	mem := audit.NewMemory()
	pr := posture.Profiles{DB: e.appPool(), Audit: mem}
	admin, admin2, auditor := e.principal("admin"), e.principal("admin2"), e.principal("auditor")

	// AC-11: profile.manage derives from any built-in profile (FedRAMP, not the active Enterprise).
	if _, err := pr.Create(ctx, auditor, settings.ProfileFedRAMPModerate, "1.1.0", "acme-fedramp", "ACME FedRAMP"); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor create: %v", err)
	}
	v, err := pr.Create(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0", "acme-fedramp", "ACME FedRAMP")
	if err != nil || v != "1" {
		t.Fatalf("create: %q %v", v, err)
	}
	if got := profileRow(e, "acme-fedramp"); got != "draft:false:fedramp:fedramp-moderate" {
		t.Fatalf("new profile %s", got)
	}
	if _, err := pr.Create(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0", "acme-fedramp", "again"); !errors.Is(err, posture.ErrInvalidValue) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, err := pr.Create(ctx, admin, "acme-fedramp", "1", "acme-2", "custom of custom"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("custom base: %v", err)
	}
	keys, err := pr.View(ctx, admin, "acme-fedramp", "1")
	if err != nil || len(keys) != 20 {
		t.Fatalf("view: %d keys, %v", len(keys), err)
	}
	if k := viewKey(t, keys, settings.KeySessionIdleTimeout); k.Direction != "unchanged" || !slices.Equal(k.Controls, []string{"AC-11"}) {
		t.Fatalf("idle timeout row %+v", k)
	}

	// Tightening needs no justification; loosening does (AC-12).
	if loose, err := pr.Edit(ctx, admin, "acme-fedramp", "1", settings.KeySessionIdleTimeout, j(`"10m0s"`), j(`"10m0s"`), ""); err != nil || loose {
		t.Fatalf("tighten: %v %v", loose, err)
	}
	if _, err := pr.Edit(ctx, admin, "acme-fedramp", "1", settings.KeyAuthLockoutThreshold, j(`5`), j(`8`), ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("loosen without justification: %v", err)
	}
	if loose, err := pr.Edit(ctx, admin, "acme-fedramp", "1", settings.KeyAuthLockoutThreshold, j(`5`), j(`8`), "shared kiosks"); err != nil || !loose {
		t.Fatalf("loosen: %v %v", loose, err)
	}
	if got := profileRow(e, "acme-fedramp"); got != "draft:true:fedramp:fedramp-moderate" {
		t.Fatalf("after loosening %s (Deviates from base)", got)
	}
	// AC-11: nothing on the hard floor, including family floors inherited from the base.
	for _, c := range []struct{ key, def, bound string }{
		{settings.KeyTLSMinVersion, `"1.2"`, `"1.1"`}, {settings.KeyAuditEnabled, `true`, `false`}, {settings.KeyFIPSEnabled, `true`, `false`},
	} {
		if _, err := pr.Edit(ctx, admin, "acme-fedramp", "1", c.key, j(c.def), j(c.bound), "x"); !errors.Is(err, posture.ErrHardFloor) {
			t.Errorf("%s bound %s: %v", c.key, c.bound, err)
		}
	}
	for _, bad := range [][3]string{
		{settings.KeySessionIdleTimeout, `"30m0s"`, `"20m0s"`}, // default weaker than bound
		{settings.KeySessionIdleTimeout, `15`, `15`},
		{"no.such_setting", `1`, `1`},
	} {
		if _, err := pr.Edit(ctx, admin, "acme-fedramp", "1", bad[0], j(bad[1]), j(bad[2]), "x"); !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	// AC-13: the view shows the deviations against the base.
	keys, _ = pr.View(ctx, admin2, "acme-fedramp", "1") // approvers may see it too
	if k := viewKey(t, keys, settings.KeyAuthLockoutThreshold); k.Direction != "loosen" || !k.Loosened || k.Justification != "shared kiosks" ||
		string(k.BaseBound) != "3" || string(k.Bound) != "8" || !slices.Equal(k.Controls, []string{"AC-7"}) {
		t.Fatalf("lockout row %+v", k)
	}
	if k := viewKey(t, keys, settings.KeySessionIdleTimeout); k.Direction != "tighten" || k.Loosened {
		t.Fatalf("idle row %+v", k)
	}
	// posture.view holders (the Auditor) may read profiles (AC-43; T-31), not edit them.
	if _, err := pr.View(ctx, auditor, "acme-fedramp", "1"); err != nil {
		t.Fatalf("auditor view: %v", err)
	}
	if _, err := pr.Edit(ctx, auditor, "acme-fedramp", "1", settings.KeySessionIdleTimeout, json.RawMessage(`"5m0s"`), json.RawMessage(`"5m0s"`), ""); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor edit: %v", err)
	}

	// Submit; drafts only are editable.
	approvalID, err := pr.Submit(ctx, admin, "acme-fedramp", "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Edit(ctx, admin, "acme-fedramp", "1", settings.KeySessionIdleTimeout, j(`"5m0s"`), j(`"5m0s"`), ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("edit after submit: %v", err)
	}
	// Self-approval is impossible (AC-12), and nothing is approved before the decision.
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, approvalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if out, err := e.asUser("app_rw", "admin", "SELECT iam.decide_approval('"+approvalID+"', true)"); err == nil {
		t.Fatalf("self-approval in the database: %s", out)
	}
	if _, err := pr.Approve(ctx, "acme-fedramp", "1"); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("approve before the decision: %v", err)
	}
	if _, err := appr.Decide(ctx, auditor, approvalID, true, ""); err == nil {
		t.Fatal("an auditor decided a profile approval")
	}
	if _, err := appr.Decide(ctx, admin2, approvalID, true, ""); err != nil {
		t.Fatal(err)
	}
	approver, err := pr.Approve(ctx, "acme-fedramp", "1")
	if err != nil || approver != admin2.UserID {
		t.Fatalf("approve: %s %v", approver, err)
	}
	if got := profileRow(e, "acme-fedramp"); got != "approved:true:fedramp:fedramp-moderate" {
		t.Fatalf("approved profile %s", got)
	}
	if _, err := pr.Approve(ctx, "acme-fedramp", "1"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second approval: %v", err)
	}
	for typ, sev := range map[string]audit.Severity{"profile.created": audit.SeverityInfo, "profile.submitted": audit.SeverityHigh, "profile.approved": audit.SeverityHigh} {
		if ev := mem.OfType(typ); len(ev) != 1 || ev[0].Severity != sev {
			t.Errorf("%s events %+v", typ, ev)
		}
	}
	if ev := mem.OfType("profile.value_changed"); len(ev) != 2 || ev[1].Severity != audit.SeverityLow {
		t.Errorf("value events %+v", ev)
	}
	if posture.DeviationLabel("FedRAMP Moderate") != "Deviates from FedRAMP Moderate" {
		t.Fatal("label")
	}
}

// A rejected submission goes back to draft; the old approval is void.
func TestCustomProfileReopen(t *testing.T) {
	e, _, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pr := posture.Profiles{DB: e.appPool(), Audit: audit.NewMemory()}
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	if _, err := pr.Create(ctx, admin, settings.ProfileEnterpriseBaseline, "1.1.0", "acme-ent", "ACME Enterprise"); err != nil {
		t.Fatal(err)
	}
	// FIPS has no floor in the Enterprise family. Its base default is on
	// (bound off), so a default of off is a loosening: it needs a justification.
	if _, err := pr.Edit(ctx, admin, "acme-ent", "1", settings.KeyFIPSEnabled, j(`false`), j(`false`), ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("FIPS default off without justification: %v", err)
	}
	if loose, err := pr.Edit(ctx, admin, "acme-ent", "1", settings.KeyFIPSEnabled, j(`false`), j(`false`), "lab only"); err != nil || !loose {
		t.Fatalf("FIPS default off in Enterprise: %v %v", loose, err)
	}
	first, err := pr.Submit(ctx, admin, "acme-ent", "1")
	if err != nil {
		t.Fatal(err)
	}
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin2, first, false, "FIPS off needs a risk acceptance first"); err != nil {
		t.Fatal(err)
	}
	if err := pr.Reopen(ctx, e.principal("auditor"), "acme-ent", "1"); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor reopen: %v", err)
	}
	if err := pr.Reopen(ctx, admin, "acme-ent", "1"); err != nil {
		t.Fatal(err)
	}
	// Back to the base value: no deviation left.
	if loose, err := pr.Edit(ctx, admin, "acme-ent", "1", settings.KeyFIPSEnabled, j(`true`), j(`false`), ""); err != nil || loose {
		t.Fatalf("back to base: %v %v", loose, err)
	}
	if got := profileRow(e, "acme-ent"); got != "draft:false:enterprise:enterprise-baseline" {
		t.Fatalf("after reopen %s", got)
	}
	second, err := pr.Submit(ctx, admin, "acme-ent", "1")
	if err != nil || second == first {
		t.Fatalf("resubmit: %s %v", second, err)
	}
	if _, err := appr.Decide(ctx, admin2, second, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Approve(ctx, "acme-ent", "1"); err != nil {
		t.Fatal(err)
	}
	if got := profileRow(e, "acme-ent"); got != "approved:false:enterprise:enterprise-baseline" {
		t.Fatalf("approved %s", got)
	}
}

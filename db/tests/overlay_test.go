package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-23 (AC-33, AC-34; design §6.6): the Restricted BU overlay is
// present on every BU in a restricted subtree, its edits are audited, and
// weakening it below the AC-33 default needs dual approval and expires.

// inRestrictedSubtree reports whether n or an ancestor is restricted.
func inRestrictedSubtree(m *model, n string) bool {
	for a := n; a != ""; a = m.parent[a] {
		if m.restricted[a] {
			return true
		}
	}
	return false
}

// TestOverlayOnEveryRestrictedBU builds random trees with random overrides,
// then toggles restrictions and moves subtrees, and checks after each step
// that every BU in a restricted subtree gets the overlay (strictest of it and
// the T-22 value) and no other BU does.
func TestOverlayOnEveryRestrictedBU(t *testing.T) {
	for seed := uint64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			ctx := context.Background()
			rg := registryFixture(t, settings.ProfileEnterpriseBaseline, "self-hosted") // instance network_binding: off
			e := rg.e
			r := rand.New(rand.NewPCG(seed, 0x23)) // #nosec G404 -- seeded for reproducible property tests
			key := settings.KeySessionNetworkBinding

			m := &model{parent: map[string]string{"ENTERPRISE": ""}, restricted: map[string]bool{}, archived: map[string]bool{}, maxDepth: 4}
			for i := range 16 {
				var p string
				for p = ""; p == "" || m.depth(p) >= m.maxDepth; {
					ns := m.nodes()
					p = ns[r.IntN(len(ns))]
				}
				c := fmt.Sprintf("N%d", i)
				e.addBU(c, p)
				m.parent[c] = p
			}
			e.drain()
			ids := map[string]string{}
			for _, n := range m.nodes() {
				ids[n] = e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + n + "'")
			}
			overrides := map[string]string{}
			for range 6 { // weaker than the overlay, so it shows wherever it applies
				ns := m.nodes()
				bu, v := ns[r.IntN(len(ns))], bindingOrder[r.IntN(2)]
				res, err := rg.set.Set(ctx, e.principal("admin"), settings.Request{Key: key, BUID: ids[bu], Value: json.RawMessage(`"` + v + `"`)})
				if err != nil || res.Outcome != settings.Applied {
					t.Fatalf("override %s=%s: %+v %v", bu, v, res, err)
				}
				overrides[bu] = v
			}

			check := func(step string) {
				t.Helper()
				if err := rg.client.Refresh(ctx); err != nil {
					t.Fatal(err)
				}
				for _, n := range m.nodes() {
					want := wantEffective(m, "off", overrides, n)
					if inRestrictedSubtree(m, n) {
						want = "reauthenticate" // the overlay, the strictest value
					}
					if v, err := rg.client.Enum(key, ids[n]); err != nil || v != want {
						t.Fatalf("%s: %s = %s %v, want %s (restricted %v, parents %v, overrides %v)", step, n, v, err, want, m.restricted, m.parent, overrides)
					}
				}
			}
			check("unrestricted")
			for i := range 10 {
				ns := m.nodes()[1:]
				if i%3 != 2 {
					n := ns[r.IntN(len(ns))]
					m.restricted[n] = !m.restricted[n]
					e.mustOwner(fmt.Sprintf("UPDATE iam.bu SET restricted = %t WHERE code = '%s'", m.restricted[n], n))
				} else {
					var n, p string
					for {
						n, p = ns[r.IntN(len(ns))], m.nodes()[r.IntN(len(ns)+1)]
						if p != m.parent[n] && !m.isAncestor(n, p) && m.depth(p)+1+m.height(n) <= m.maxDepth {
							break
						}
					}
					m.parent[n] = p
					e.mustOwner(fmt.Sprintf("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = '%s') WHERE code = '%s'", p, n))
				}
				check(fmt.Sprintf("step %d", i))
			}
		})
	}
}

// weakenOverlay sets the overlay's network binding to v through an approved
// overlay exception, so tests of the T-22 rule see it without the overlay.
func weakenOverlay(t *testing.T, rg registryEnv, v string) {
	t.Helper()
	ctx := context.Background()
	ov := posture.Overlay{DB: rg.e.posturePool(), Audit: audit.NewMemory()}
	res, err := ov.Change(ctx, rg.e.principal("admin"), settings.KeySessionNetworkBinding, json.RawMessage(`"`+v+`"`), "inheritance tests without the overlay", 0)
	if err != nil || res.Outcome != posture.PendingApproval {
		t.Fatalf("weaken overlay: %+v %v", res, err)
	}
	if _, err := (approvals.Service{DB: rg.e.appPool()}).Decide(ctx, rg.e.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.ApplyApproved(ctx, res.ChangeID); err != nil {
		t.Fatal(err)
	}
}

type overlayEnv struct {
	registryEnv
	ov    posture.Overlay
	mem   *audit.Memory
	r, r1 string // a restricted BU and its child
	free  string // an unrestricted BU
}

func overlayFixture(t *testing.T, mode string) overlayEnv {
	rg := registryFixture(t, settings.ProfileEnterpriseBaseline, mode)
	e := rg.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.addBU("R1", "R")
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	e.drain()
	id := func(c string) string { return e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + c + "'") }
	mem := audit.NewMemory()
	return overlayEnv{registryEnv: rg, ov: posture.Overlay{DB: e.posturePool(), Audit: mem}, mem: mem, r: id("R"), r1: id("R1"), free: id("A")}
}

func (o overlayEnv) binding(t *testing.T, bu string) string {
	t.Helper()
	if err := o.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := o.client.Enum(settings.KeySessionNetworkBinding, bu)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (o overlayEnv) entry(t *testing.T, key string) posture.OverlayEntry {
	t.Helper()
	all, err := o.ov.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(all, func(x posture.OverlayEntry) bool { return x.Key == key })
	if i < 0 {
		t.Fatalf("overlay has no %s: %+v", key, all)
	}
	return all[i]
}

// AC-33: the overlay's defaults, present on the restricted BU and below it
// and nowhere else; a key not yet registered (export.reason_required, F-010)
// waits for its feature.
func TestOverlayDefaults(t *testing.T) {
	o := overlayFixture(t, "self-hosted")
	all, err := o.ov.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range all {
		got = append(got, fmt.Sprintf("%s=%s:%s:%t", x.Key, x.Value, x.Source, x.Applies))
	}
	want := []string{`bu.reauth_max_age="15m0s":default:true`, `export.reason_required=true:default:false`,
		`session.network_binding="reauthenticate":default:true`}
	if !slices.Equal(got, want) {
		t.Fatalf("overlay %v, want %v", got, want)
	}
	for bu, want := range map[string]string{o.r: "reauthenticate", o.r1: "reauthenticate", o.free: "off", "": "off"} {
		if got := o.binding(t, bu); got != want {
			t.Fatalf("network binding at %q = %s, want %s", bu, got, want)
		}
	}
	// Unrestricting removes it.
	o.e.mustOwner("UPDATE iam.bu SET restricted = false WHERE code = 'R'")
	if got := o.binding(t, o.r1); got != "off" {
		t.Fatalf("after unrestrict: %s", got)
	}
	if _, err := o.ov.Change(context.Background(), o.e.principal("admin"), "export.reason_required", json.RawMessage(`false`), "x", 0); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("editing an unregistered overlay key: %v", err)
	}
}

// AC-34: weakening the overlay below its default needs an explanation and
// dual approval and applies as an expiring exception; tightening and
// returning to the default apply at once; the revert restores the default.
func TestOverlayWeakeningNeedsApproval(t *testing.T) {
	ctx := context.Background()
	o := overlayFixture(t, "saas")
	e := o.e
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	key := settings.KeySessionNetworkBinding

	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('nobody@example.test', 'Nobody')")
	e.mustOwner(grant("admin", "user:nobody", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	if _, err := o.ov.Change(ctx, e.principal("nobody"), key, json.RawMessage(`"flag"`), "x", 0); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("without settings.change: %v", err)
	}
	res, err := o.ov.Change(ctx, admin, key, json.RawMessage(`"flag"`), "", 0)
	if !errors.Is(err, posture.ErrExplanationRequired) || res.Warning == nil || string(res.Warning.Bound) != `"reauthenticate"` {
		t.Fatalf("weakening without explanation: %+v %v", res, err)
	}
	res, err = o.ov.Change(ctx, admin, key, json.RawMessage(`"flag"`), "branch office VPN", 7*24*time.Hour)
	if err != nil || res.Outcome != posture.PendingApproval || res.Direction != "loosen" {
		t.Fatalf("weakening with explanation: %+v %v", res, err)
	}
	if a := o.mem.OfType("overlay.change_requested"); len(a) != 1 || a[0].Severity != audit.SeverityHigh {
		t.Fatalf("request audit %+v", a)
	}
	if got := o.binding(t, o.r); got != "reauthenticate" {
		t.Fatalf("before approval: %s", got)
	}
	if _, err := o.ov.ApplyApproved(ctx, res.ChangeID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("apply before approval: %v", err)
	}
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, res.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := appr.Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := o.ov.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(x.ExpiresAt); d < 6*24*time.Hour || d > 7*24*time.Hour {
		t.Fatalf("exception expires in %v, want 7 days", d)
	}
	if got := o.binding(t, o.r1); got != "flag" {
		t.Fatalf("after approval: %s", got)
	}
	if ent := o.entry(t, key); ent.Source != "exception" || ent.ExceptionID != x.ID || ent.ExpiresAt == nil {
		t.Fatalf("overlay view %+v", ent)
	}
	if got := e.adminQuery("SELECT overlay FROM posture.exception WHERE id = '" + x.ID + "'"); got != "t" {
		t.Fatal("not an overlay exception")
	}
	if got := e.adminQuery("SELECT string_agg(event ->> 'type', ',') FROM posture.secops_outbox"); got != "overlay.exception_created" {
		t.Fatalf("SecOps queue %q", got)
	}
	if got := valueOf(e, key); got != "" && got != `"off":profile` {
		t.Fatalf("instance value touched: %s", got)
	}

	// Renewal before expiry, then revert at expiry restores the default.
	ev := posture.Evaluator{DB: e.posturePool(), Audit: audit.NewMemory()}
	rn, err := ev.RequestRenewal(ctx, admin, x.ID, "still needed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appr.Decide(ctx, admin2, rn.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	y, err := ev.ApplyRenewal(ctx, rn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ent := o.entry(t, key); ent.ExceptionID != y.ID || string(ent.Value) != `"flag"` {
		t.Fatalf("after renewal %+v", ent)
	}
	expire(e, y.ID)
	if out, err := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 || out[0].Err != nil {
		t.Fatalf("revert: %+v %v", out, err)
	}
	if ent := o.entry(t, key); ent.Source != "default" || string(ent.Value) != `"reauthenticate"` {
		t.Fatalf("after revert %+v", ent)
	}
	if got := o.binding(t, o.r); got != "reauthenticate" {
		t.Fatalf("after revert: %s", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
}

// Tightening under an overlay exception and returning to the default apply
// at once; the default replaces the exception. Overlay rows carry MACs.
func TestOverlayTighteningAndMAC(t *testing.T) {
	ctx := context.Background()
	o := overlayFixture(t, "self-hosted")
	e := o.e
	admin := e.principal("admin")
	key := settings.KeySessionNetworkBinding

	res, err := o.ov.Change(ctx, admin, key, json.RawMessage(`"off"`), "lab network", 0)
	if err != nil || res.Outcome != posture.PendingApproval {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, e.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := o.ov.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	// Tightening under the exception: no approval, still the exception.
	res, err = o.ov.Change(ctx, admin, key, json.RawMessage(`"flag"`), "", 0)
	if err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("tighten under exception: %+v %v", res, err)
	}
	if ent := o.entry(t, key); ent.Source != "exception" || ent.ExceptionID != x.ID || string(ent.Value) != `"flag"` {
		t.Fatalf("after tightening %+v", ent)
	}
	// Back to the default: the exception is superseded.
	res, err = o.ov.Change(ctx, admin, key, json.RawMessage(`"reauthenticate"`), "", 0)
	if err != nil || res.Outcome != posture.Applied {
		t.Fatalf("back to default: %+v %v", res, err)
	}
	if got := e.adminQuery("SELECT state FROM posture.exception WHERE id = '" + x.ID + "'"); got != "superseded" {
		t.Fatalf("exception %s", got)
	}
	if a := o.mem.OfType("overlay.changed"); len(a) != 2 {
		t.Fatalf("%d overlay.changed audits", len(a))
	}
	if got := o.binding(t, o.r); got != "reauthenticate" {
		t.Fatal(got)
	}
	// An out-of-band edit is caught by the drift check.
	if got := e.adminQuery("SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
	e.admin(e.db, `UPDATE posture.overlay_value SET value = '"off"'`)
	if got := e.adminQuery("SELECT string_agg(key, ',') FROM posture.mac_mismatches()"); got != "overlay:"+key {
		t.Fatalf("MAC mismatches %q", got)
	}
	// Application roles cannot touch the overlay tables or its write functions.
	e.mustFail("app_rw", "SELECT * FROM posture.overlay_value", "permission denied")
	e.wantState("app_rw", "PERFORM posture.request_overlay_change('"+key+"', '\"off\"', 'x')", "42501")
	e.wantState("app_posture", "PERFORM posture.write_overlay('"+key+"', '\"off\"', 'change', NULL, NULL)", "42501")
}

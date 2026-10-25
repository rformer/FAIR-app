package settings

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newReg(t *testing.T, profile string, saas bool) (*Registry, *audit.Memory, *clock, *[]audit.Event) {
	t.Helper()
	mem := audit.NewMemory()
	clk := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	var secops []audit.Event
	r, err := New(context.Background(), Options{
		Defs: F001Defs(), Profiles: BuiltinProfiles(), ActiveProfile: profile,
		Emitter: mem, Clock: clk.now, SaaS: saas,
		SecOps: func(_ context.Context, e audit.Event) { secops = append(secops, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, mem, clk, &secops
}

func TestBuiltinProfilesValid(t *testing.T) {
	for _, p := range BuiltinProfiles() {
		if err := ValidateProfile(p, F001Defs()); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
	}
}

func TestProfileMissingBindingFailsStartup(t *testing.T) {
	p := BuiltinProfiles()[0]
	delete(p.Settings, KeySessionIdleTimeout)
	_, err := New(context.Background(), Options{Defs: F001Defs(), Profiles: []Profile{p}, ActiveProfile: p.ID, Emitter: audit.NewMemory()})
	if err == nil {
		t.Fatal("a registered key with no profile binding must fail startup (F-015 AC-01)")
	}
}

func TestProfileBoundBelowFloorRejected(t *testing.T) {
	p := BuiltinProfiles()[0]
	p.Settings[KeyTLSMinVersion] = Bound{Default: "1.2", Weakest: "1.1"}
	if err := ValidateProfile(p, F001Defs()); err == nil {
		t.Fatal("a profile bound weaker than the hard floor must fail validation (AC-31)")
	}
}

func TestSeedIsAudited(t *testing.T) {
	r, mem, _, _ := newReg(t, ProfileFedRAMPModerate, false)
	if len(mem.OfType("setting.seeded")) != 1 {
		t.Fatal("seeding must be audited (AC-10)")
	}
	v, _ := r.Duration(KeySessionIdleTimeout)
	if v != 15*time.Minute {
		t.Fatalf("idle timeout seeded to %v", v)
	}
}

func TestTighteningIsImmediate(t *testing.T) {
	r, _, _, secops := newReg(t, ProfileFedRAMPModerate, true)
	res, err := r.Set(context.Background(), Request{Key: KeySessionIdleTimeout, Value: 10 * time.Minute, Actor: "alice"})
	if err != nil || res.Outcome != Applied {
		t.Fatalf("tighten: %v %v", res.Outcome, err)
	}
	if len(*secops) != 0 {
		t.Fatal("tightening must not notify SecOps")
	}
}

func TestLooseningWithinBoundsApplies(t *testing.T) {
	r, mem, _, secops := newReg(t, ProfileEnterpriseBaseline, true)
	res, err := r.Set(context.Background(), Request{Key: KeySessionIdleTimeout, Value: 25 * time.Minute, Actor: "alice"})
	if err != nil || res.Outcome != Applied {
		t.Fatalf("in-bounds loosen: %v %v", res.Outcome, err)
	}
	if ev := mem.OfType("setting.changed"); len(ev) != 1 || ev[0].Severity != audit.SeverityLow {
		t.Fatal("in-bounds loosening must be audited")
	}
	if len(*secops) != 1 {
		t.Fatal("any weakening in SaaS must notify SecOps (AC-23)")
	}
}

func TestOutOfBoundsNeedsExplanationAndDualApproval(t *testing.T) {
	ctx := context.Background()
	r, mem, _, secops := newReg(t, ProfileFedRAMPModerate, true)

	res, err := r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 30 * time.Minute, Actor: "alice"})
	if !errors.Is(err, ErrExplanationRequired) || res.Warning == nil || len(res.Warning.Controls) == 0 {
		t.Fatalf("missing explanation must be refused with a control warning: %v %+v", err, res)
	}

	res, err = r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 30 * time.Minute, Actor: "alice", Explanation: "call-center pilot"})
	if err != nil || res.Outcome != PendingApproval {
		t.Fatalf("expected pending approval: %v %v", res.Outcome, err)
	}
	if v, _ := r.Duration(KeySessionIdleTimeout); v != 15*time.Minute {
		t.Fatal("value must not change before approval")
	}
	if _, err := r.Approve(ctx, res.ApprovalID, "alice", 0); !errors.Is(err, ErrSelfApproval) {
		t.Fatal("requester must not approve their own change")
	}
	if _, err := r.Approve(ctx, res.ApprovalID, "bob", 120*day); !errors.Is(err, ErrExpiryTooLong) {
		t.Fatal("exception longer than the maximum must be refused (AC-24)")
	}
	ex, err := r.Approve(ctx, res.ApprovalID, "bob", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ex.ExpiresAt.Sub(ex.CreatedAt) != 90*day {
		t.Fatalf("default exception expiry = %v, want 90d", ex.ExpiresAt.Sub(ex.CreatedAt))
	}
	v, _ := r.Get(KeySessionIdleTimeout)
	if v.Value != 30*time.Minute || v.Source != SourceException {
		t.Fatalf("value after approval: %+v", v)
	}
	if len(mem.OfType("setting.exception_created")) != 1 || len(*secops) != 1 {
		t.Fatal("exception must be audited (high) and SecOps notified")
	}
}

func TestHardFloorRefused(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{ProfileFedRAMPModerate, ProfileCMMCL2R2, ProfileEnterpriseBaseline} {
		r, mem, _, _ := newReg(t, p, false)
		for _, req := range []Request{
			{Key: KeyTLSMinVersion, Value: "1.1"},
			{Key: KeyAuditEnabled, Value: false},
			{Key: KeyAuthMFAPrivileged, Value: false},
			{Key: KeyRLSEnforced, Value: false},
		} {
			req.Actor, req.Explanation = "alice", "please"
			if res, err := r.Set(ctx, req); !errors.Is(err, ErrHardFloor) || res.Outcome != Refused {
				t.Errorf("%s %s=%v must be refused, got %v %v", p, req.Key, req.Value, res.Outcome, err)
			}
		}
		if len(mem.OfType("setting.hard_floor_refused")) != 4 {
			t.Errorf("%s: hard-floor refusals must be audited", p)
		}
	}
}

func TestFIPSFloorIsConditionalOnFamily(t *testing.T) {
	ctx := context.Background()
	fed, _, _, _ := newReg(t, ProfileFedRAMPModerate, false)
	if _, err := fed.Set(ctx, Request{Key: KeyFIPSEnabled, Value: false, Actor: "a", Explanation: "x"}); !errors.Is(err, ErrHardFloor) {
		t.Fatal("FIPS is a hard floor under FedRAMP")
	}
	ent, _, _, _ := newReg(t, ProfileEnterpriseBaseline, false)
	if res, err := ent.Set(ctx, Request{Key: KeyFIPSEnabled, Value: false, Actor: "a"}); err != nil || res.Outcome != Applied {
		t.Fatalf("FIPS may be disabled within Enterprise Baseline bounds: %v %v", res.Outcome, err)
	}
}

func TestBreakGlassEnableAlwaysNeedsApproval(t *testing.T) {
	for _, p := range []string{ProfileFedRAMPModerate, ProfileCMMCL2R2, ProfileEnterpriseBaseline} {
		r, _, _, _ := newReg(t, p, false)
		res, err := r.Set(context.Background(), Request{Key: KeyBreakGlassEnabled, Value: true, Actor: "a", Explanation: "IdP migration window"})
		if err != nil || res.Outcome != PendingApproval {
			t.Errorf("%s: enabling break-glass must require dual approval (F-001 AC-41), got %v %v", p, res.Outcome, err)
		}
	}
}

func TestExceptionAutoRevertAndNotices(t *testing.T) {
	ctx := context.Background()
	r, mem, clk, _ := newReg(t, ProfileFedRAMPModerate, false)
	res, _ := r.Set(ctx, Request{Key: KeyAuthLockoutThreshold, Value: 6, Actor: "alice", Explanation: "kiosk testing"})
	ex, err := r.Approve(ctx, res.ApprovalID, "bob", 30*day)
	if err != nil {
		t.Fatal(err)
	}

	clk.advance(16 * day)
	if got := r.ExpiringWithin(14 * day); len(got) != 1 {
		t.Fatalf("14-day notice window should include the exception, got %d", len(got))
	}
	if out, _ := r.ExpireExceptions(ctx); len(out) != 0 {
		t.Fatal("must not revert before expiry")
	}

	clk.advance(14 * day)
	out, err := r.ExpireExceptions(ctx)
	if err != nil || len(out) != 1 || out[0].ID != ex.ID {
		t.Fatalf("expected one revert, got %v %v", out, err)
	}
	v, _ := r.Get(KeyAuthLockoutThreshold)
	if v.Value != 3 || v.Source != SourceRevert {
		t.Fatalf("after revert: %+v", v)
	}
	if len(mem.OfType("setting.exception_reverted")) != 1 {
		t.Fatal("revert must be audited")
	}
	if _, err := r.RequestRenewal(ctx, ex.ID, "alice", "more time"); err == nil {
		t.Fatal("renewal after expiry must be refused (AC-26)")
	}
}

func TestRenewalBeforeExpiry(t *testing.T) {
	ctx := context.Background()
	r, _, clk, _ := newReg(t, ProfileFedRAMPModerate, false)
	res, _ := r.Set(ctx, Request{Key: KeyTokenMaxLifetime, Value: 180 * day, Actor: "alice", Explanation: "legacy integration"})
	ex, _ := r.Approve(ctx, res.ApprovalID, "bob", 10*day)
	clk.advance(9 * day)

	id, err := r.RequestRenewal(ctx, ex.ID, "alice", "integration not yet migrated")
	if err != nil {
		t.Fatal(err)
	}
	nex, err := r.Approve(ctx, id, "carol", 10*day)
	if err != nil {
		t.Fatal(err)
	}
	if nex.RenewedFrom != ex.ID {
		t.Fatal("renewal must link to the original exception")
	}
	old, _ := r.Exception(ex.ID)
	if old.State != ExceptionRenewed {
		t.Fatalf("original state = %s", old.State)
	}
	clk.advance(2 * day) // original would have expired; renewal still active
	if out, _ := r.ExpireExceptions(ctx); len(out) != 0 {
		t.Fatal("renewed exception must not revert at the original expiry")
	}
}

func TestTighteningInsideExceptionKeepsCoverage(t *testing.T) {
	ctx := context.Background()
	r, _, _, _ := newReg(t, ProfileFedRAMPModerate, false)
	res, _ := r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 60 * time.Minute, Actor: "alice", Explanation: "x"})
	ex, _ := r.Approve(ctx, res.ApprovalID, "bob", 0)
	if _, err := r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 45 * time.Minute, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	v, _ := r.Get(KeySessionIdleTimeout)
	if v.Source != SourceException || v.ExceptionID != ex.ID {
		t.Fatalf("out-of-bounds value must stay covered by its exception: %+v", v)
	}
	if _, err := r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 15 * time.Minute, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.Exception(ex.ID); e.State != ExceptionSuperseded {
		t.Fatalf("returning inside the bound supersedes the exception, state=%s", e.State)
	}
}

type failEmitter struct{ fail bool }

func (f *failEmitter) Emit(context.Context, audit.Event) error {
	if f.fail {
		return errors.New("audit down")
	}
	return nil
}

func TestFailsClosedWhenAuditUnavailable(t *testing.T) {
	ctx := context.Background()
	em := &failEmitter{}
	r, err := New(ctx, Options{Defs: F001Defs(), Profiles: BuiltinProfiles(), ActiveProfile: ProfileEnterpriseBaseline, Emitter: em})
	if err != nil {
		t.Fatal(err)
	}
	em.fail = true
	if _, err := r.Set(ctx, Request{Key: KeySessionIdleTimeout, Value: 20 * time.Minute, Actor: "a"}); err == nil {
		t.Fatal("change must fail when the audit record cannot be written")
	}
	if v, _ := r.Duration(KeySessionIdleTimeout); v != 15*time.Minute {
		t.Fatal("value must be rolled back when audit fails")
	}
}

// Property test: Compare is a total order consistent with Strictest.
func TestCompareIsTotalOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	defs := map[string]Def{}
	for _, d := range F001Defs() {
		defs[d.Key] = d
	}
	gen := func(d Def) any {
		switch d.Kind {
		case KindDuration:
			return time.Duration(rng.IntN(1000)) * time.Minute
		case KindInt:
			return rng.IntN(20)
		case KindBool:
			return rng.IntN(2) == 1
		default:
			return d.Order[rng.IntN(len(d.Order))]
		}
	}
	for _, d := range defs {
		for i := 0; i < 200; i++ {
			a, b, c := gen(d), gen(d), gen(d)
			ab, _ := d.Compare(a, b)
			ba, _ := d.Compare(b, a)
			if ab != -ba {
				t.Fatalf("%s: antisymmetry broken for %v,%v", d.Key, a, b)
			}
			bc, _ := d.Compare(b, c)
			ac, _ := d.Compare(a, c)
			if ab >= 0 && bc >= 0 && ac < 0 {
				t.Fatalf("%s: transitivity broken for %v,%v,%v", d.Key, a, b, c)
			}
			s, _ := d.Strictest(a, b, c)
			for _, x := range []any{a, b, c} {
				if cmp, _ := d.Compare(s, x); cmp < 0 {
					t.Fatalf("%s: Strictest(%v,%v,%v)=%v is weaker than %v", d.Key, a, b, c, s, x)
				}
			}
		}
	}
}

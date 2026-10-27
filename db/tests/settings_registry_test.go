package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-16: the F-001 T-00b settings tests (pkg/settings/settings_test.go),
// run against the real registry. Writes go through settings.Setter
// (posture.Setter embedded as a service would, connected as app_rw); reads
// through settings.Client. Behaviors the stand-in tests cover that already
// have real-registry tests elsewhere:
//   - BuiltinProfilesValid, ProfileBoundBelowFloorRejected: packages (T-06, T-10)
//   - ProfileMissingBindingFailsStartup: TestPostureStartupRegistration (T-12)
//   - SeedIsAudited: TestPostureSeed (T-10)
//   - CompareIsTotalOrder: strictness property and parity tests (T-13)
// ExceptionAutoRevertAndNotices and RenewalBeforeExpiry move with T-17/T-18.

type registryEnv struct {
	e      *env
	set    posture.Setter
	audit  *audit.Memory
	client *settings.Client
}

func registryFixture(t *testing.T, profile, mode string) registryEnv {
	e := setup(t)
	ctx := context.Background()
	postureAdmins(e)
	addMACKey(e, "k1")
	e.mustOwner("SELECT posture.set_deployment_mode('" + mode + "')")
	if _, err := posture.Seed(ctx, e.posturePool(), audit.NewMemory(), "system:installer", profile, ""); err != nil {
		t.Fatal(err)
	}
	app := e.appPool() // the calling service's own pool: app_rw
	c := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: app}, Service: "iam"})
	if err := c.Register(settings.F001Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, settings.DBRegistrar{DB: app}, "F-001", "1"); err != nil {
		t.Fatal(err)
	}
	mem := audit.NewMemory()
	return registryEnv{e: e, set: posture.Setter{Evaluator: posture.Evaluator{DB: app, Audit: mem}}, audit: mem, client: c}
}

// duration reads a setting as the service would, after a refresh.
func (r registryEnv) duration(t *testing.T, key string) time.Duration {
	t.Helper()
	if err := r.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	d, err := r.client.Duration(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (r registryEnv) secops() string { return outboxCount(r.e) }

func TestRegistryTighteningIsImmediate(t *testing.T) {
	r := registryFixture(t, settings.ProfileFedRAMPModerate, "saas")
	res, err := r.set.Set(context.Background(), r.e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: 10 * time.Minute})
	if err != nil || res.Outcome != settings.Applied {
		t.Fatalf("tighten: %v %v", res.Outcome, err)
	}
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 10*time.Minute {
		t.Fatalf("services see %v", d)
	}
	if n := r.secops(); n != "0" {
		t.Fatal("tightening must not notify SecOps")
	}
}

func TestRegistryLooseningWithinBoundsApplies(t *testing.T) {
	r := registryFixture(t, settings.ProfileEnterpriseBaseline, "saas")
	res, err := r.set.Set(context.Background(), r.e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: 25 * time.Minute})
	if err != nil || res.Outcome != settings.Applied {
		t.Fatalf("in-bounds loosen: %v %v", res.Outcome, err)
	}
	if ev := r.audit.OfType("setting.changed"); len(ev) != 1 || ev[0].Severity != audit.SeverityLow {
		t.Fatal("in-bounds loosening must be audited")
	}
	if n := r.secops(); n != "1" {
		t.Fatal("any weakening in SaaS must notify SecOps (AC-23)")
	}
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 25*time.Minute {
		t.Fatalf("services see %v", d)
	}
}

func TestRegistryOutOfBoundsNeedsExplanationAndDualApproval(t *testing.T) {
	ctx := context.Background()
	r := registryFixture(t, settings.ProfileFedRAMPModerate, "saas")
	admin, admin2 := r.e.principal("admin"), r.e.principal("admin2")

	res, err := r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 30 * time.Minute})
	if !errors.Is(err, settings.ErrExplanationRequired) || res.Warning == nil || len(res.Warning.Controls) == 0 {
		t.Fatalf("missing explanation must be refused with a control warning: %v %+v", err, res)
	}
	res, err = r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 30 * time.Minute, Explanation: "call-center pilot"})
	if err != nil || res.Outcome != settings.PendingApproval || res.ChangeID == "" {
		t.Fatalf("expected pending approval: %+v %v", res, err)
	}
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 15*time.Minute {
		t.Fatal("value must not change before approval")
	}
	appr := approvals.Service{DB: r.e.appPool()}
	if _, err := appr.Decide(ctx, admin, res.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatal("requester must not approve their own change")
	}
	if _, err := appr.Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	ex, err := r.set.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(ex.ExpiresAt); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Fatalf("default exception expiry in %v, want 90d", d)
	}
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 30*time.Minute {
		t.Fatalf("value after approval: %v", d)
	}
	if got := valueOf(r.e, settings.KeySessionIdleTimeout); got != `"30m0s":exception` {
		t.Fatalf("source after approval: %s", got)
	}
	if len(r.audit.OfType("setting.exception_created")) != 1 || r.secops() != "1" {
		t.Fatal("exception must be audited (high) and SecOps notified")
	}
}

func TestRegistryHardFloorRefused(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{settings.ProfileFedRAMPModerate, settings.ProfileCMMCL2R2, settings.ProfileEnterpriseBaseline} {
		r := registryFixture(t, p, "self-hosted")
		for _, req := range []settings.Request{
			{Key: settings.KeyTLSMinVersion, Value: "1.1"},
			{Key: settings.KeyAuditEnabled, Value: false},
			{Key: settings.KeyAuthMFAPrivileged, Value: false},
			{Key: settings.KeyRLSEnforced, Value: false},
		} {
			req.Explanation = "please"
			if res, err := r.set.Set(ctx, r.e.principal("admin"), req); !errors.Is(err, settings.ErrHardFloor) || res.Outcome != settings.Refused {
				t.Errorf("%s %s=%v must be refused, got %v %v", p, req.Key, req.Value, res.Outcome, err)
			}
		}
		if len(r.audit.OfType("setting.hard_floor_refused")) != 4 {
			t.Errorf("%s: hard-floor refusals must be audited", p)
		}
	}
}

func TestRegistryFIPSFloorIsConditionalOnFamily(t *testing.T) {
	ctx := context.Background()
	fed := registryFixture(t, settings.ProfileFedRAMPModerate, "self-hosted")
	if _, err := fed.set.Set(ctx, fed.e.principal("admin"), settings.Request{Key: settings.KeyFIPSEnabled, Value: false, Explanation: "x"}); !errors.Is(err, settings.ErrHardFloor) {
		t.Fatal("FIPS is a hard floor under FedRAMP")
	}
	ent := registryFixture(t, settings.ProfileEnterpriseBaseline, "self-hosted")
	if res, err := ent.set.Set(ctx, ent.e.principal("admin"), settings.Request{Key: settings.KeyFIPSEnabled, Value: false}); err != nil || res.Outcome != settings.Applied {
		t.Fatalf("FIPS may be disabled within Enterprise Baseline bounds: %v %v", res.Outcome, err)
	}
}

func TestRegistryBreakGlassEnableAlwaysNeedsApproval(t *testing.T) {
	for _, p := range []string{settings.ProfileFedRAMPModerate, settings.ProfileCMMCL2R2, settings.ProfileEnterpriseBaseline} {
		r := registryFixture(t, p, "self-hosted")
		res, err := r.set.Set(context.Background(), r.e.principal("admin"), settings.Request{Key: settings.KeyBreakGlassEnabled, Value: true, Explanation: "IdP migration window"})
		if err != nil || res.Outcome != settings.PendingApproval {
			t.Errorf("%s: enabling break-glass must require dual approval (F-001 AC-41), got %v %v", p, res.Outcome, err)
		}
	}
}

// AC-22 inside an exception (the gap T-16's port found in T-14).
func TestRegistryTighteningInsideExceptionKeepsCoverage(t *testing.T) {
	ctx := context.Background()
	r := registryFixture(t, settings.ProfileFedRAMPModerate, "saas")
	admin := r.e.principal("admin")
	res, err := r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 60 * time.Minute, Explanation: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: r.e.appPool()}).Decide(ctx, r.e.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	ex, err := r.set.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	// Still out of bounds, but stricter: applies at once, still covered.
	if res, err := r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 45 * time.Minute}); err != nil || res.Outcome != settings.Applied {
		t.Fatalf("tightening inside the exception: %+v %v", res, err)
	}
	if got := r.e.adminQuery("SELECT s.value::text || ':' || s.source || ':' || (s.exception_id = '" + ex.ID + "') || ':' || e.value::text || ':' || e.state FROM posture.setting_value s JOIN posture.exception e ON e.id = '" + ex.ID + "' WHERE s.key = 'session.idle_timeout' AND s.bu_id IS NULL"); got != `"45m0s":exception:true:"45m0s":active` {
		t.Fatalf("out-of-bounds value must stay covered by its exception: %s", got)
	}
	// Weakening again inside the exception is not a tightening: it needs approval.
	if _, err := r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 50 * time.Minute}); !errors.Is(err, settings.ErrExplanationRequired) {
		t.Fatalf("loosening inside the exception: %v", err)
	}
	// Back within the bound: the exception is superseded.
	if _, err := r.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: 15 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if got := r.e.adminQuery("SELECT state FROM posture.exception WHERE id = '" + ex.ID + "'"); got != "superseded" {
		t.Fatalf("returning inside the bound supersedes the exception, state=%s", got)
	}
	if got := valueOf(r.e, settings.KeySessionIdleTimeout); got != `"15m0s":change` {
		t.Fatalf("value %s", got)
	}
	if n := r.secops(); n != "1" {
		t.Fatalf("SecOps notified %s times; only the exception weakened", n)
	}
	if got := mustAs(r.e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches", got)
	}
}

func TestRegistryFailsClosedWhenAuditUnavailable(t *testing.T) {
	r := registryFixture(t, settings.ProfileEnterpriseBaseline, "self-hosted")
	r.set.Evaluator.Audit = failingEmitter{}
	if _, err := r.set.Set(context.Background(), r.e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: 20 * time.Minute}); err == nil {
		t.Fatal("change must fail when the audit record cannot be written")
	}
	if d := r.duration(t, settings.KeySessionIdleTimeout); d != 15*time.Minute {
		t.Fatal("value must be rolled back when audit fails")
	}
}

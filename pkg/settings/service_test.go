package settings_test

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

var (
	alice = audit.Actor{Kind: audit.ActorUser, ID: "alice"}
	bob   = audit.Actor{Kind: audit.ActorUser, ID: "bob"}
)

type fixture struct {
	svc   *settings.Service
	audit *audit.Memory
	now   time.Time
}

func newFixture(t *testing.T, profileID string) *fixture {
	t.Helper()
	p, err := settings.LookupProfile(profileID)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{audit: audit.NewMemory(), now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	f.svc, err = settings.New(context.Background(), settings.Config{
		Profile: p, Defs: settings.AllDefs(), Audit: f.audit, Clock: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) set(t *testing.T, key, val, reason string) (settings.Result, error) {
	t.Helper()
	return f.svc.Set(context.Background(), settings.SetRequest{Key: key, Value: val, Reason: reason, Actor: alice})
}

func TestAllBuiltinProfilesSeedCleanly(t *testing.T) {
	for id := range settings.BuiltinProfiles() {
		f := newFixture(t, id)
		if got := f.audit.OfType("setting.seeded"); len(got) != 1 {
			t.Fatalf("%s: want one seed event, got %d", id, len(got))
		}
		if flags := f.svc.PostureFlags(); len(flags) != 0 {
			t.Fatalf("%s: fresh install has posture flags: %+v", id, flags)
		}
	}
}

func TestSecureDefaults(t *testing.T) {
	// F-001 "Secure defaults" table, checked in every profile.
	want := map[string]string{
		"auth.mfa_required": "true", "auth.mfa_required_privileged": "true",
		"auth.jit_provisioning": "false", "auth.totp_enabled": "false",
		"bu.new_restricted": "true", "bu.restricted_rollup_default": "excluded",
		"session.idle_timeout": "15m0s", "session.absolute_timeout": "12h0m0s",
		"token.max_lifetime": "2160h0m0s", "auth.banner_enabled": "true",
		"breakglass.enabled": "false", "audit.enabled": "true", "tls.min_version": "1.2",
		"auth.lockout_threshold": "3", "auth.lockout_window": "15m0s",
	}
	for id := range settings.BuiltinProfiles() {
		f := newFixture(t, id)
		for k, v := range want {
			if got, _ := f.svc.Get(k); got != v {
				t.Errorf("%s: %s = %s, want %s", id, k, got, v)
			}
		}
	}
	// Network binding default differs by profile (F-001 design §5.8).
	for id, want := range map[string]string{
		settings.ProfileEnterpriseBaseline: "off",
		settings.ProfileFedRAMPModerate:    "reauthenticate",
		settings.ProfileCMMCL2:             "reauthenticate",
	} {
		if got, _ := newFixture(t, id).svc.Get("session.network_binding"); got != want {
			t.Errorf("%s network_binding = %s, want %s", id, got, want)
		}
	}
	if settings.DefaultProfile != settings.ProfileFedRAMPModerate {
		t.Fatal("install default must be FedRAMP Moderate")
	}
}

func TestApplyPathTightenIsImmediate(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	res, err := f.set(t, "session.idle_timeout", "10m", "") // no reason needed to tighten
	if err != nil || res.Outcome != settings.Applied {
		t.Fatalf("got %+v, %v", res, err)
	}
	if v, _ := f.svc.Get("session.idle_timeout"); v != "10m0s" {
		t.Fatalf("value = %s", v)
	}
	ev := f.audit.OfType("setting.changed")
	if len(ev) != 1 || ev[0].Severity != audit.SeverityInfo || ev[0].Attributes["direction"] != "tighten" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestWarnPathLoosenWithinBounds(t *testing.T) {
	f := newFixture(t, settings.ProfileEnterpriseBaseline)
	if _, err := f.set(t, "session.idle_timeout", "20m", ""); !errors.Is(err, settings.ErrReasonRequired) {
		t.Fatalf("loosening without reason: %v", err)
	}
	res, err := f.set(t, "session.idle_timeout", "20m", "call-center workflow")
	if err != nil || res.Outcome != settings.AppliedWithWarning || res.Warning == nil {
		t.Fatalf("got %+v, %v", res, err)
	}
	if !strings.Contains(strings.Join(res.Warning.Controls, ","), "AC-11") {
		t.Fatalf("warning should name controls: %+v", res.Warning)
	}
	ev := f.audit.OfType("setting.loosened")
	if len(ev) != 1 || ev[0].Severity != audit.SeverityHigh || ev[0].Reason != "call-center workflow" {
		t.Fatalf("audit = %+v", ev)
	}
	flags := f.svc.PostureFlags()
	if len(flags) != 1 || flags[0].Key != "session.idle_timeout" || flags[0].Exception {
		t.Fatalf("posture flags = %+v", flags)
	}
}

func TestDualApprovalPathOutOfBounds(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	res, err := f.set(t, "session.idle_timeout", "30m", "pilot")
	if err != nil || res.Outcome != settings.PendingApproval || res.ApprovalID == "" || res.Warning == nil {
		t.Fatalf("got %+v, %v", res, err)
	}
	if v, _ := f.svc.Get("session.idle_timeout"); v != "15m0s" {
		t.Fatal("value must not change before approval")
	}
	if ev := f.audit.OfType("setting.loosen_requested"); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh {
		t.Fatalf("audit = %+v", ev)
	}

	// Self-approval is impossible.
	if _, err := f.svc.Approve(context.Background(), res.ApprovalID, alice, ""); !errors.Is(err, settings.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if v, _ := f.svc.Get("session.idle_timeout"); v != "15m0s" {
		t.Fatal("self-approval must not apply")
	}

	got, err := f.svc.Approve(context.Background(), res.ApprovalID, bob, "")
	if err != nil {
		t.Fatal(err)
	}
	wantExp := f.now.Add(90 * 24 * time.Hour)
	if !got.ExceptionExpires.Equal(wantExp) {
		t.Fatalf("exception expires %v, want %v", got.ExceptionExpires, wantExp)
	}
	if v, _ := f.svc.Get("session.idle_timeout"); v != "30m0s" {
		t.Fatalf("value = %s", v)
	}
	ev := f.audit.OfType("setting.exception_created")
	if len(ev) != 1 || ev[0].Actor.ID != "bob" || ev[0].Attributes["requested_by"] != "alice" {
		t.Fatalf("audit should record both identities: %+v", ev)
	}
	// A second approval of the same request fails.
	if _, err := f.svc.Approve(context.Background(), res.ApprovalID, audit.Actor{Kind: audit.ActorUser, ID: "carol"}, ""); err == nil {
		t.Fatal("double approval should fail")
	}
}

func TestExceptionAutoRevertsAtExpiry(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	res, _ := f.set(t, "session.idle_timeout", "30m", "pilot")
	if _, err := f.svc.Approve(context.Background(), res.ApprovalID, bob, ""); err != nil {
		t.Fatal(err)
	}
	var notified []string
	f.svc.OnChange(func(k, v string) { notified = append(notified, k+"="+v) })

	f.now = f.now.Add(89 * 24 * time.Hour)
	if keys, _ := f.svc.RevertExpired(context.Background()); len(keys) != 0 {
		t.Fatalf("reverted early: %v", keys)
	}
	f.now = f.now.Add(24 * time.Hour)
	keys, err := f.svc.RevertExpired(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if v, _ := f.svc.Get("session.idle_timeout"); v != "15m0s" {
		t.Fatalf("value after revert = %s", v)
	}
	if len(f.audit.OfType("setting.exception_reverted")) != 1 || len(notified) != 1 {
		t.Fatal("revert must be audited and propagated")
	}
}

func TestApprovalExpiresAfter72h(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	res, _ := f.set(t, "auth.lockout_threshold", "10", "testing")
	f.now = f.now.Add(73 * time.Hour)
	if _, err := f.svc.Approve(context.Background(), res.ApprovalID, bob, ""); !errors.Is(err, settings.ErrApprovalExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestStaleApprovalRejected(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	res, _ := f.set(t, "session.idle_timeout", "30m", "pilot")
	if _, err := f.set(t, "session.idle_timeout", "5m", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Approve(context.Background(), res.ApprovalID, bob, ""); !errors.Is(err, settings.ErrStaleApproval) {
		t.Fatalf("got %v", err)
	}
}

func TestAlwaysDualApproveKeys(t *testing.T) {
	// Post-install break-glass enablement needs dual approval even though it
	// is within bounds (F-001 AC-41); restricting/disabling does not (AC-45).
	f := newFixture(t, settings.ProfileEnterpriseBaseline)
	res, err := f.set(t, "breakglass.enabled", "true", "IdP migration weekend")
	if err != nil || res.Outcome != settings.PendingApproval {
		t.Fatalf("got %+v, %v", res, err)
	}
	got, err := f.svc.Approve(context.Background(), res.ApprovalID, bob, "")
	if err != nil || !got.ExceptionExpires.IsZero() {
		t.Fatalf("in-bounds approval should not create an exception: %+v, %v", got, err)
	}
	res, err = f.set(t, "breakglass.enabled", "false", "")
	if err != nil || res.Outcome != settings.Applied {
		t.Fatalf("disabling break-glass must be immediate: %+v, %v", res, err)
	}
}

func TestHardFloorRefused(t *testing.T) {
	cases := []struct{ profile, key, val string }{
		{settings.ProfileEnterpriseBaseline, "auth.mfa_required_privileged", "false"},
		{settings.ProfileEnterpriseBaseline, "audit.enabled", "false"},
		{settings.ProfileFedRAMPModerate, "crypto.fips_required", "false"},
		{settings.ProfileCMMCL2, "crypto.fips_required", "false"},
	}
	for _, c := range cases {
		f := newFixture(t, c.profile)
		res, err := f.set(t, c.key, c.val, "please")
		if !errors.Is(err, settings.ErrHardFloor) || res.Outcome != settings.Refused {
			t.Errorf("%s %s=%s: got %+v, %v", c.profile, c.key, c.val, res, err)
		}
		if ev := f.audit.OfType("setting.hard_floor_refused"); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh {
			t.Errorf("%s: missing high-severity refusal event", c.key)
		}
	}
	// FIPS can be loosened (with warning) under Enterprise Baseline only.
	f := newFixture(t, settings.ProfileEnterpriseBaseline)
	if res, err := f.set(t, "crypto.fips_required", "false", "dev cluster"); err != nil || res.Outcome != settings.AppliedWithWarning {
		t.Fatalf("enterprise fips loosen: %+v, %v", res, err)
	}
}

func TestAuditFailureBlocksChange(t *testing.T) {
	p, _ := settings.LookupProfile(settings.ProfileFedRAMPModerate)
	em := &flakyEmitter{}
	svc, err := settings.New(context.Background(), settings.Config{Profile: p, Defs: settings.AllDefs(), Audit: em})
	if err != nil {
		t.Fatal(err)
	}
	em.fail = true
	if _, err := svc.Set(context.Background(), settings.SetRequest{Key: "session.idle_timeout", Value: "5m", Actor: alice}); err == nil {
		t.Fatal("expected error")
	}
	if v, _ := svc.Get("session.idle_timeout"); v != "15m0s" {
		t.Fatal("change applied without an audit record")
	}
}

type flakyEmitter struct{ fail bool }

func (f *flakyEmitter) Emit(context.Context, audit.Event) error {
	if f.fail {
		return errors.New("sink down")
	}
	return nil
}
func (f *flakyEmitter) Close(context.Context) error { return nil }

func TestStartupFailsOnUnboundKey(t *testing.T) {
	p, _ := settings.LookupProfile(settings.ProfileFedRAMPModerate)
	defs := append(settings.AllDefs(), settings.Def{Key: "new.feature_key", Type: settings.TypeBool, StrictBool: true})
	_, err := settings.New(context.Background(), settings.Config{Profile: p, Defs: defs, Audit: audit.NewMemory()})
	if err == nil || !strings.Contains(err.Error(), "new.feature_key") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsNonUserActorsAndBadValues(t *testing.T) {
	f := newFixture(t, settings.ProfileFedRAMPModerate)
	_, err := f.svc.Set(context.Background(), settings.SetRequest{Key: "session.idle_timeout", Value: "5m",
		Actor: audit.Actor{Kind: audit.ActorService, ID: "svc"}})
	if !errors.Is(err, settings.ErrNotAUser) {
		t.Fatalf("got %v", err)
	}
	for k, v := range map[string]string{"session.idle_timeout": "soon", "session.network_binding": "maybe", "auth.lockout_threshold": "3.5"} {
		if _, err := f.set(t, k, v, "x"); !errors.Is(err, settings.ErrInvalidValue) {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
	if _, err := f.set(t, "no.such", "1", "x"); !errors.Is(err, settings.ErrUnknownKey) {
		t.Fatalf("got %v", err)
	}
}

// Property: Compare is a total order consistent with Strictest, and the
// hard floor is never violated by any sequence of Set/Approve calls.
func TestComparatorAndFloorProperties(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	durs := []string{"1m", "5m", "15m", "30m", "1h", "12h", "24h"}
	d := settings.Def{Key: "x", Type: settings.TypeDuration, Direction: settings.LowerIsStricter}
	for i := 0; i < 500; i++ {
		a, _ := d.Normalize(durs[r.Intn(len(durs))])
		b, _ := d.Normalize(durs[r.Intn(len(durs))])
		c, _ := d.Normalize(durs[r.Intn(len(durs))])
		if d.Compare(a, b) != -d.Compare(b, a) {
			t.Fatal("antisymmetry")
		}
		if d.Compare(a, b) >= 0 && d.Compare(b, c) >= 0 && d.Compare(a, c) < 0 {
			t.Fatal("transitivity")
		}
		s := d.Strictest(a, b, c)
		for _, v := range []string{a, b, c} {
			if d.Compare(s, v) < 0 {
				t.Fatal("strictest is not strictest")
			}
		}
	}

	f := newFixture(t, settings.ProfileEnterpriseBaseline)
	vals := map[string][]string{
		"auth.mfa_required_privileged": {"true", "false"},
		"audit.enabled":                {"true", "false"},
		"tls.min_version":              {"1.2", "1.3"},
	}
	keys := []string{"auth.mfa_required_privileged", "audit.enabled", "tls.min_version"}
	for i := 0; i < 300; i++ {
		k := keys[r.Intn(len(keys))]
		v := vals[k][r.Intn(2)]
		res, _ := f.set(t, k, v, "fuzz")
		if res.ApprovalID != "" {
			_, _ = f.svc.Approve(context.Background(), res.ApprovalID, bob, "")
		}
		for _, st := range f.svc.States() {
			if st.Floor != "" && st.Value != st.Floor && (st.Key == "auth.mfa_required_privileged" || st.Key == "audit.enabled") {
				t.Fatalf("floor violated: %+v", st)
			}
		}
	}
}

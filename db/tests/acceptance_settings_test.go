package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-008 T-01 (F-008-AC-04, AC-12; design §4): the acceptance settings,
// registered by the risk service and bound by every built-in profile; no
// profile lets a tier need no approval.
func TestAcceptanceSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-008", "1", settings.F008Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyAcceptanceTier1Max:       `100000:profile`,
		settings.KeyAcceptanceTier2Max:       `1000000:profile`,
		settings.KeyAcceptanceTier1LevelsUp:  `0:profile`,
		settings.KeyAcceptanceTier2LevelsUp:  `1:profile`,
		settings.KeyAcceptanceTier1Approvals: `1:profile`,
		settings.KeyAcceptanceTier2Approvals: `1:profile`,
		settings.KeyAcceptanceTier3Approvals: `2:profile`,
		settings.KeyAcceptanceMaxDuration:    `365:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || direction, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-008'`); got !=
		"acceptance.max_duration_days:lower_is_stricter,acceptance.tier1_approvals:higher_is_stricter,acceptance.tier1_levels_up:higher_is_stricter,"+
			"acceptance.tier1_max:lower_is_stricter,acceptance.tier2_approvals:higher_is_stricter,acceptance.tier2_levels_up:higher_is_stricter,"+
			"acceptance.tier2_max:lower_is_stricter,acceptance.tier3_approvals:higher_is_stricter" {
		t.Fatalf("definitions: %s", got)
	}

	admin := e.principal("admin")
	change := func(key, value string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value)})
	}
	// Within the bounds, either way: applied.
	for _, c := range []struct{ key, value string }{
		{settings.KeyAcceptanceTier1Max, `10000000`}, // the weakest allowed
		{settings.KeyAcceptanceTier2Max, `100000000`},
		{settings.KeyAcceptanceMaxDuration, `730`},
		{settings.KeyAcceptanceTier2LevelsUp, `0`},
		{settings.KeyAcceptanceTier3Approvals, `1`},
		{settings.KeyAcceptanceTier1Max, `50000`}, // stricter
		{settings.KeyAcceptanceMaxDuration, `90`},
		{settings.KeyAcceptanceTier1Approvals, `2`},
		{settings.KeyAcceptanceTier2LevelsUp, `3`},
	} {
		if res, err := change(c.key, c.value); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", c.key, c.value, res, err)
		}
	}
	// Beyond the loosening bound: an explanation and dual approval; a tier
	// with no approval among them.
	for _, c := range []struct{ key, value string }{
		{settings.KeyAcceptanceTier1Max, `10000001`},
		{settings.KeyAcceptanceTier2Max, `100000001`},
		{settings.KeyAcceptanceMaxDuration, `731`},
		{settings.KeyAcceptanceTier1Approvals, `0`},
		{settings.KeyAcceptanceTier3Approvals, `0`},
	} {
		if _, err := change(c.key, c.value); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Errorf("%s = %s beyond the bound: %v", c.key, c.value, err)
		}
	}
	// A negative level is no value at all.
	if _, err := change(settings.KeyAcceptanceTier1LevelsUp, `-1`); err == nil {
		t.Error("a negative level accepted")
	}
}

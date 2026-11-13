package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-007 T-01 (F-007-AC-06, AC-08; design §4): the register settings,
// registered by the risk service and bound by every built-in profile.
func TestRegisterSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-007", "1", settings.F007Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyRegisterIterations:     `100000:profile`,
		settings.KeyRegisterAnalysisMaxAge: `365:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || direction, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-007'`); got !=
		"register.analysis_max_age_days:lower_is_stricter,register.iterations:higher_is_stricter" {
		t.Fatalf("definitions: %s", got)
	}

	admin := e.principal("admin")
	change := func(key, value string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value)})
	}
	// Within the bounds, either way: applied.
	for key, value := range map[string]string{
		settings.KeyRegisterIterations:     `10000`, // the weakest allowed
		settings.KeyRegisterAnalysisMaxAge: `730`,
	} {
		if res, err := change(key, value); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", key, value, res, err)
		}
	}
	for key, value := range map[string]string{
		settings.KeyRegisterIterations:     `200000`, // stricter
		settings.KeyRegisterAnalysisMaxAge: `90`,
	} {
		if res, err := change(key, value); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", key, value, res, err)
		}
	}
	// Beyond the loosening bound: an explanation and dual approval.
	for key, value := range map[string]string{
		settings.KeyRegisterIterations:     `9999`,
		settings.KeyRegisterAnalysisMaxAge: `731`,
	} {
		if _, err := change(key, value); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Errorf("%s = %s beyond the bound: %v", key, value, err)
		}
	}
}

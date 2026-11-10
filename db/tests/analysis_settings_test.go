package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-005 T-01 (F-005-AC-01, AC-05, AC-13; design §7): the simulation
// settings, registered by the risk service and bound by every built-in
// profile.
func TestAnalysisSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-005", "1", settings.F005Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeySimulationIterationsDefault: `100000:profile`,
		settings.KeySimulationIterationsMin:     `10000:profile`,
		settings.KeySimulationIterationsMax:     `1000000:profile`,
		settings.KeySimulationMaxActiveRuns:     `5:profile`,
		settings.KeySimulationConvergenceBP:     `100:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || direction, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-005'`); got !=
		"simulation.convergence_threshold_bp:lower_is_stricter,simulation.iterations_default:higher_is_stricter,simulation.iterations_max:lower_is_stricter,"+
			"simulation.iterations_min:higher_is_stricter,simulation.max_active_runs:lower_is_stricter" {
		t.Fatalf("definitions: %s", got)
	}

	admin := e.principal("admin")
	change := func(key, value string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value)})
	}
	// Within the bounds, either way: applied.
	for key, value := range map[string]string{
		settings.KeySimulationIterationsDefault: `200000`, // stricter
		settings.KeySimulationIterationsMin:     `1000`,   // the weakest allowed
		settings.KeySimulationIterationsMax:     `2000000`,
		settings.KeySimulationMaxActiveRuns:     `2`,
		settings.KeySimulationConvergenceBP:     `500`,
	} {
		if res, err := change(key, value); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", key, value, res, err)
		}
	}
	// Beyond the loosening bound: an explanation and dual approval.
	for key, value := range map[string]string{
		settings.KeySimulationIterationsDefault: `9999`,
		settings.KeySimulationIterationsMin:     `999`,
		settings.KeySimulationIterationsMax:     `2000001`,
		settings.KeySimulationMaxActiveRuns:     `51`,
		settings.KeySimulationConvergenceBP:     `501`,
	} {
		if _, err := change(key, value); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Errorf("%s = %s beyond the bound: %v", key, value, err)
		}
	}
}

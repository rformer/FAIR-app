package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-004 T-02 (F-004-AC-05, AC-20, AC-21, AC-23, AC-30; design §7): the
// estimate and calibration settings, registered by the risk service and
// bound by every built-in profile.
func TestEstimateSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-004", "1", settings.F004Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyEstimateReminderLead:    `"48h0m0s":profile`,
		settings.KeyCalibrationExerciseSize: `20:profile`,
		settings.KeyCalibrationReusePeriod:  `"4320h0m0s":profile`,
		settings.KeyCalibrationWindow:       `"8760h0m0s":profile`,
		settings.KeyCalibrationMinAnswers:   `20:profile`,
		settings.KeyCalibrationRetention:    `"26280h0m0s":profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || direction || ':' || owner_feature, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-004'`); got !=
		"calibration.exercise_size:higher_is_stricter:F-004,calibration.min_answers:higher_is_stricter:F-004,calibration.retention:lower_is_stricter:F-004,"+
			"calibration.reuse_period:higher_is_stricter:F-004,calibration.window:higher_is_stricter:F-004,estimate.reminder_lead:higher_is_stricter:F-004" {
		t.Fatalf("definitions: %s", got)
	}

	admin := e.principal("admin")
	change := func(key, value string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value)})
	}
	// Within the bounds, either way: applied.
	for key, value := range map[string]string{
		settings.KeyCalibrationRetention:    `"17520h0m0s"`, // two years: stricter
		settings.KeyCalibrationExerciseSize: `10`,           // the weakest allowed
		settings.KeyEstimateReminderLead:    `"1h0m0s"`,
	} {
		if res, err := change(key, value); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", key, value, res, err)
		}
	}
	// Beyond the loosening bound: an explanation and dual approval.
	for key, value := range map[string]string{
		settings.KeyCalibrationRetention:    `"61392h0m0s"`, // seven years and a day
		settings.KeyCalibrationExerciseSize: `9`,
		settings.KeyCalibrationMinAnswers:   `5`,
		settings.KeyCalibrationReusePeriod:  `"24h0m0s"`,
	} {
		if _, err := change(key, value); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Errorf("%s = %s beyond the bound: %v", key, value, err)
		}
	}
}

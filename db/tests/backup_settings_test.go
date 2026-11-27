package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-014 T-02 (F-014-AC-41; design §4, D-OQ10): backup.max_age_hours, bound
// by every built-in profile at 24 hours, at most 168: a shorter age applies
// at once; a longer one within the bound needs an explanation; beyond it,
// an exception.
func TestBackupSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.posturePool()}).Register(ctx, "F-014", "1", settings.F014Defs()); err != nil {
		t.Fatal(err)
	}
	if got := valueOf(e, settings.KeyBackupMaxAge); got != "24:profile" {
		t.Fatalf("%s = %s", settings.KeyBackupMaxAge, got)
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || type || ':' || direction || ':' || bu_scopable || ':' || loosening_needs_approval, ',' ORDER BY key)
		FROM posture.setting_def WHERE owner_feature = 'F-014'`); got != "backup.max_age_hours:int:lower_is_stricter:false:false" {
		t.Fatalf("definitions: %s", got)
	}
	admin := e.principal("admin")
	change := func(value, why string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyBackupMaxAge, Value: json.RawMessage(value), Explanation: why})
	}
	if res, err := change(`6`, ""); err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("6 hours: %+v %v", res, err)
	}
	if _, err := change(`168`, "weekly backups at a small site"); err != nil {
		t.Errorf("168 hours: %v", err)
	}
	if _, err := change(`169`, ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Errorf("169 hours without an explanation: %v", err)
	}
	if got := valueOf(e, settings.KeyBackupMaxAge); got != "168:change" {
		t.Fatalf("after the changes: %s", got)
	}
}

package tests

import (
	"context"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

// F-010 T-02 (F-010-AC-06, AC-10, AC-15, AC-16; design §4, OQ7): the report
// settings, bound by every built-in profile, and export.reason_required,
// BU-scoped, on in restricted subtrees through the F-015 overlay.
func TestReportSettings(t *testing.T) {
	o := overlayFixture(t, "self-hosted")
	e := o.e
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-010", "1", settings.F010Defs()); err != nil {
		t.Fatal(err)
	}
	if err := o.client.Register(settings.F010Defs()...); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyReportMarking:           `"Confidential":profile`,
		settings.KeyReportRetention:         `30:profile`,
		settings.KeyReportSnapshotInterval:  `7:profile`,
		settings.KeyReportSnapshotRetention: `1095:profile`,
		settings.KeyExportReasonRequired:    `false:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || type || ':' || direction || ':' || bu_scopable, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-010'`); got !=
		"export.reason_required:bool:true_is_stricter:true,report.marking:string:nonempty_is_stricter:false,report.retention_days:int:lower_is_stricter:false,"+
			"report.snapshot_interval_days:int:lower_is_stricter:false,report.snapshot_retention_days:int:higher_is_stricter:false" {
		t.Fatalf("definitions: %s", got)
	}

	// The overlay's default now applies: reasons inside R's subtree only.
	if err := o.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for bu, want := range map[string]bool{o.r: true, o.r1: true, o.free: false, "": false} {
		got, err := o.client.Bool(settings.KeyExportReasonRequired, bu)
		if err != nil || got != want {
			t.Errorf("export.reason_required at %q = %v (%v), want %v", bu, got, err, want)
		}
	}
	if e := o.entry(t, settings.KeyExportReasonRequired); !e.Applies || e.Source != "default" {
		t.Errorf("overlay entry %+v", e)
	}
	// Unrestricting R removes it.
	e.mustOwner("UPDATE iam.bu SET restricted = false WHERE code = 'R'")
	if err := o.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := o.client.Bool(settings.KeyExportReasonRequired, o.r1); got {
		t.Error("still required after unrestricting R")
	}
}

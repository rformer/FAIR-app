package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-011 T-02 (F-011-AC-04; design §4): the integration settings, bound by
// every built-in profile. integration.allowed_hosts is a set, empty on
// install: every host added is a loosening needing an explanation and a
// second approver; removing hosts tightens. records_retention_days keeps
// received records 30 days, at most 365.
func TestIntegrationSettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-011", "1", settings.F011Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyIntegrationAllowedHosts:    `[]:profile`,
		settings.KeyIntegrationRecordRetention: `30:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || type || ':' || direction || ':' || bu_scopable || ':' || loosening_needs_approval, ',' ORDER BY key)
		FROM posture.setting_def WHERE owner_feature = 'F-011'`); got !=
		"integration.allowed_hosts:set:subset_is_stricter:false:true,integration.records_retention_days:int:lower_is_stricter:false:false" {
		t.Fatalf("definitions: %s", got)
	}

	admin, admin2 := e.principal("admin"), e.principal("admin2")
	change := func(key, value, why string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value), Explanation: why})
	}
	// Retention: shorter applies at once; a loosening within the bound is
	// accepted with its explanation; beyond the bound needs one too.
	if res, err := change(settings.KeyIntegrationRecordRetention, `7`, ""); err != nil || res.Outcome != posture.Applied {
		t.Errorf("7 days: %+v %v", res, err)
	}
	if _, err := change(settings.KeyIntegrationRecordRetention, `365`, "keep a year for diagnosis"); err != nil {
		t.Errorf("365 days: %v", err)
	}
	if _, err := change(settings.KeyIntegrationRecordRetention, `366`, ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Errorf("366 days without an explanation: %v", err)
	}

	key := settings.KeyIntegrationAllowedHosts
	approve := func(value string) {
		t.Helper()
		if _, err := change(key, value, ""); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Fatalf("%s without an explanation: %v", value, err)
		}
		res, err := change(key, value, "the CMDB's API")
		if err != nil || res.Outcome != posture.PendingApproval || res.Direction != "loosen" {
			t.Fatalf("%s: %+v %v", value, res, err)
		}
		if got := e.adminQuery("SELECT kind FROM iam.approval_request WHERE id = '" + res.ApprovalID + "'"); got != approvals.KindSettingsLoosen {
			t.Fatalf("approval kind %s", got)
		}
		if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin, res.ApprovalID, true, ""); err == nil {
			t.Fatal("the requester approved their own loosening")
		}
		if st, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil || st != approvals.Approved {
			t.Fatalf("approve: %v %v", st, err)
		}
		if _, err := ev.ApplyApproved(ctx, res.ChangeID); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	approve(`["cmdb.example"]`)
	approve(`["*.corp.example","cmdb.example"]`)
	if got := valueOf(e, key); got != `["*.corp.example", "cmdb.example"]:change` {
		t.Fatalf("after the approvals: %s", got)
	}
	if res, err := change(key, `["cmdb.example"]`, ""); err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("remove: %+v %v", res, err)
	}
	// notification.allowed_hosts is a separate setting: hosts allowed for
	// connectors are not allowed for notices.
	if got := valueOf(e, settings.KeyNotificationAllowedHosts); got != `[]:profile` && got != "" {
		t.Errorf("notification.allowed_hosts = %s", got)
	}
}

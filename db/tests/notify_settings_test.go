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

// F-009 T-01b (F-009-AC-06, AC-10, AC-14, AC-17; design §4, amended
// 2026-11-16): the notification settings, bound by every built-in profile.
// notification.allowed_hosts is a set: every host added is a loosening
// needing an explanation and a second approver; removing hosts tightens.
func TestNotifySettings(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(ctx, "F-009", "1", settings.F009Defs()); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		settings.KeyNotificationDetail:       `"minimal":profile`,
		settings.KeyNotificationAllowedHosts: `[]:profile`,
		settings.KeyNotificationRetryHours:   `24:profile`,
		settings.KeyNotificationLogRetention: `90:profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if got := e.adminQuery(`SELECT string_agg(key || ':' || type || ':' || direction || ':' || loosening_needs_approval, ',' ORDER BY key) FROM posture.setting_def WHERE owner_feature = 'F-009'`); got !=
		"notification.allowed_hosts:set:subset_is_stricter:true,notification.detail:enum:ordered:false,"+
			"notification.log_retention_days:int:higher_is_stricter:false,notification.retry_hours:int:higher_is_stricter:false" {
		t.Fatalf("definitions: %s", got)
	}
	// Sets are never BU-scopable.
	if got := e.adminState(`INSERT INTO posture.setting_def (key, type, direction, bu_scopable, owner_feature, registered_version)
		VALUES ('p.bu_set', 'set', 'subset_is_stricter', true, 'F-009', '1')`); got != "23514" {
		t.Errorf("a BU-scopable set: %s", got)
	}

	admin, admin2 := e.principal("admin"), e.principal("admin2")
	change := func(key, value, why string) (posture.ChangeResult, error) {
		return ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(value), Explanation: why})
	}
	for _, c := range []struct{ key, value string }{
		{settings.KeyNotificationDetail, `"titles"`},
		{settings.KeyNotificationRetryHours, `1`},
		{settings.KeyNotificationRetryHours, `72`},
		{settings.KeyNotificationLogRetention, `365`},
	} {
		if res, err := change(c.key, c.value, ""); err != nil || res.Outcome != posture.Applied {
			t.Errorf("%s = %s: %+v %v", c.key, c.value, res, err)
		}
	}
	for _, c := range []struct{ key, value string }{
		{settings.KeyNotificationRetryHours, `0`},
		{settings.KeyNotificationLogRetention, `29`},
	} {
		if _, err := change(c.key, c.value, ""); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Errorf("%s = %s beyond the bound: %v", c.key, c.value, err)
		}
	}

	key := settings.KeyNotificationAllowedHosts
	// Values the set kind refuses.
	for _, bad := range []string{`"hooks.example"`, `["b.example","a.example"]`, `["a.example","a.example"]`, `["*","a.example"]`, `[""]`, `null`} {
		if _, err := change(key, bad, ""); !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// Adding a host loosens within the bound: an explanation and a second
	// approver; applied as a change, not an exception.
	approve := func(value string) {
		t.Helper()
		if _, err := change(key, value, ""); !errors.Is(err, posture.ErrExplanationRequired) {
			t.Fatalf("%s without an explanation: %v", value, err)
		}
		res, err := change(key, value, "the ticketing system's webhook")
		if err != nil || res.Outcome != posture.PendingApproval || res.Direction != "loosen" {
			t.Fatalf("%s: %+v %v", value, res, err)
		}
		if got := e.adminQuery("SELECT kind FROM iam.approval_request WHERE id = '" + res.ApprovalID + "'"); got != approvals.KindSettingsLoosen {
			t.Fatalf("approval kind %s", got)
		}
		if st, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil || st != approvals.Approved {
			t.Fatalf("approve: %v %v", st, err)
		}
		if _, err := ev.ApplyApproved(ctx, res.ChangeID); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	approve(`["hooks.example"]`)
	approve(`["*.corp.example","hooks.example"]`) // a second host: a loosening again
	approve(`["*.corp.example","mail.example"]`)  // replacing one: it adds one
	if got := valueOf(e, key); got != `["*.corp.example", "mail.example"]:change` {
		t.Fatalf("after the approvals: %s", got)
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.exception WHERE key = '" + key + "'"); n != "0" {
		t.Fatalf("%s exceptions", n)
	}
	// Removing a host tightens and applies at once.
	if res, err := change(key, `["mail.example"]`, ""); err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("remove: %+v %v", res, err)
	}
	// Any host ({"*"}) is within the bound, and needs approval too.
	approve(`["*"]`)
	if got := valueOf(e, key); got != `["*"]:change` {
		t.Fatalf("any host: %s", got)
	}
}

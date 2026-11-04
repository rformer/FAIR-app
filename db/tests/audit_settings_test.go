package tests

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-002 T-04 (F-002-AC-24, AC-25, AC-28; design §4.4): the audit trail's
// settings, the string kind, and approval for every loosening of a setting
// whose definition asks for it.

// auditSettingsFixture is evaluatorFixture with the F-002 settings
// registered as well (the audit service registers them, T-05).
func auditSettingsFixture(t *testing.T) (*env, posture.Evaluator, *audit.Memory) {
	e, ev, mem, _ := evaluatorFixture(t)
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(context.Background(), "F-002", "1", settings.F002Defs()); err != nil {
		t.Fatal(err)
	}
	return e, ev, mem
}

func TestAuditSettingsRegisteredAndSeeded(t *testing.T) {
	e, _, _ := auditSettingsFixture(t)
	// The Enterprise Baseline package's defaults are in force (design §4.4).
	for key, want := range map[string]string{
		settings.KeyAuditRetentionOnline:   `"8760h0m0s":profile`,
		settings.KeyAuditRetentionTotal:    `"61368h0m0s":profile`,
		settings.KeyAuditMaxClockSkew:      `"5m0s":profile`,
		settings.KeyAuditBacklogRecords:    `10000:profile`,
		settings.KeyAuditBacklogAge:        `"15m0s":profile`,
		settings.KeyAuditSyslogDestination: `"":profile`,
		settings.KeyAuditOTLPDestination:   `"":profile`,
	} {
		if got := valueOf(e, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	row := e.adminQuery(`SELECT type || ':' || direction || ':' || loosening_needs_approval || ':' || owner_feature FROM posture.setting_def WHERE key = 'audit.syslog_destination'`)
	if row != "string:nonempty_is_stricter:true:F-002" {
		t.Fatalf("syslog destination definition: %s", row)
	}
	if got := e.adminQuery(`SELECT hard_floor::text FROM posture.setting_def WHERE key = 'audit.retention_online'`); got != `"2160h0m0s"` {
		t.Fatalf("online retention floor: %s", got)
	}
	// A release may set loosening_needs_approval but never drop it.
	defs := settings.F002Defs()
	for i := range defs {
		defs[i].LooseningNeedsApproval = false
	}
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(context.Background(), "F-002", "2", defs); err == nil ||
		!strings.Contains(err.Error(), "would drop the approval") {
		t.Fatalf("dropping the approval flag: %v", err)
	}
}

func TestAuditRetentionFloorAndBounds(t *testing.T) {
	e, ev, _ := auditSettingsFixture(t)
	ctx := context.Background()
	admin := e.principal("admin")
	// AC-28: never below 90 days online, exception or not.
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuditRetentionOnline, Value: json.RawMessage(`"2159h0m0s"`),
		Explanation: "storage"}); !errors.Is(err, posture.ErrHardFloor) {
		t.Fatalf("below the floor: %v", err)
	}
	// Enterprise allows 90 days within its bound; longer is a tightening.
	if res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuditRetentionOnline, Value: json.RawMessage(`"2160h0m0s"`)}); err != nil ||
		res.Outcome != posture.Applied || res.Direction != "loosen" {
		t.Fatalf("90 days: %+v %v", res, err)
	}
	if res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuditRetentionTotal, Value: json.RawMessage(`"87600h0m0s"`)}); err != nil ||
		res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("ten years: %+v %v", res, err)
	}
	// Below the Enterprise bound (one year in all) needs an exception.
	if res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuditRetentionTotal, Value: json.RawMessage(`"4380h0m0s"`)}); !errors.Is(err, posture.ErrExplanationRequired) ||
		res.Warning == nil || !strings.Contains(res.Warning.Message, "AU-11") {
		t.Fatalf("total below the bound: %+v %v", res, err)
	}
}

func TestAuditDestinationLooseningNeedsApproval(t *testing.T) {
	e, ev, _ := auditSettingsFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	key := settings.KeyAuditSyslogDestination

	// Naming a destination tightens and applies at once.
	res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(`"siem.example:6514"`)})
	if err != nil || res.Outcome != posture.Applied || res.Direction != "tighten" {
		t.Fatalf("set: %+v %v", res, err)
	}
	// Changing it to another destination is neither tighter nor weaker.
	res, err = ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(`"siem2.example:6514"`)})
	if err != nil || res.Outcome != posture.Applied || res.Direction != "neutral" {
		t.Fatalf("change: %+v %v", res, err)
	}
	// Values the string kind refuses.
	for _, bad := range []string{`7`, `"a` + `\n` + `b"`, `"` + strings.Repeat("x", 256) + `"`} {
		if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(bad)}); !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("%.40s: %v", bad, err)
		}
	}

	// Clearing it loosens within the bound, and still needs an explanation
	// and a second approver (AC-24).
	mem2 := audit.NewMemory()
	ev.Audit = mem2
	clearReq := posture.ChangeRequest{Key: key, Value: json.RawMessage(`""`)}
	res, err = ev.Change(ctx, admin, clearReq)
	if !errors.Is(err, posture.ErrExplanationRequired) || res.Warning == nil || !strings.Contains(res.Warning.Message, "second approver") {
		t.Fatalf("clear without explanation: %+v %v", res, err)
	}
	clearReq.Explanation = "moving to a new SIEM next week"
	res, err = ev.Change(ctx, admin, clearReq)
	if err != nil || res.Outcome != posture.PendingApproval || res.ApprovalID == "" {
		t.Fatalf("clear: %+v %v", res, err)
	}
	if got := e.adminQuery("SELECT kind FROM iam.approval_request WHERE id = '" + res.ApprovalID + "'"); got != approvals.KindSettingsLoosen {
		t.Fatalf("approval kind %s", got)
	}
	onlyEvent(t, mem2, "setting.change_requested", audit.SeverityHigh)
	if got := valueOf(e, key); got != `"siem2.example:6514":change` {
		t.Fatalf("cleared before approval: %s", got)
	}
	if _, err := ev.ApplyApproved(ctx, res.ChangeID); !errors.Is(err, posture.ErrNotApproved) {
		t.Fatalf("apply before approval: %v", err)
	}
	appr := approvals.Service{DB: e.appPool()}
	if _, err := appr.Decide(ctx, admin, res.ApprovalID, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if st, err := appr.Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil || st != approvals.Approved {
		t.Fatalf("approve: %v %v", st, err)
	}
	x, err := ev.ApplyApproved(ctx, res.ChangeID)
	if err != nil || x.ID != "" || x.Key != key || string(x.Value) != `""` {
		t.Fatalf("apply: %+v %v", x, err)
	}
	// Applied as a change, not an exception: nothing expires or reverts.
	if got := valueOf(e, key); got != `"":change` {
		t.Fatalf("after apply: %s", got)
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.exception WHERE key = '" + key + "'"); n != "0" {
		t.Fatalf("%s exceptions", n)
	}
	if a := onlyEvent(t, mem2, "setting.changed", audit.SeverityHigh); a.Actor != admin.UserID || a.Attributes["direction"] != "loosen" {
		t.Fatalf("applied event %+v", a)
	}
	if _, err := ev.ApplyApproved(ctx, res.ChangeID); err == nil {
		t.Fatal("applied twice")
	}

	// A change recorded as requested cannot loosen such a setting without approval.
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(`"siem.example:6514"`)}); err != nil {
		t.Fatal(err)
	}
	id := e.mustAsUser("app_posture", "admin", `SELECT change_id FROM posture.request_change('audit.syslog_destination', NULL, '"other:1"', NULL)`)
	e.admin(e.db, "UPDATE posture.change SET new_value = '\"\"', direction = 'loosen' WHERE id = '"+id+"'")
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "PF002")
}

// Paths the Go evaluator hides (found by mutation testing).
func TestAuditLooseningApprovalEdges(t *testing.T) {
	e, ev, _ := auditSettingsFixture(t)
	ctx := context.Background()
	admin := e.principal("admin")
	key := settings.KeyAuditOTLPDestination
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: key, Value: json.RawMessage(`"collector:4317"`)}); err != nil {
		t.Fatal(err)
	}
	// The database itself wants the explanation, not only the evaluator.
	e.wantStateAs("app_posture", "admin", `PERFORM posture.request_change('audit.otlp_destination', NULL, '""', NULL)`, "PF002")

	// ApplyApproved is only for changes waiting for an approval: a change
	// that needed none is neither applied nor reported as approved.
	id := e.mustAsUser("app_posture", "admin", `SELECT change_id FROM posture.request_change('audit.max_clock_skew', NULL, '"10m0s"', NULL)`)
	mem := audit.NewMemory()
	ev.Audit = mem
	if _, err := ev.ApplyApproved(ctx, id); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("ApplyApproved on a requested change: %v", err)
	}
	if got := valueOf(e, settings.KeyAuditMaxClockSkew); got != `"5m0s":profile` || len(mem.Events()) != 0 {
		t.Fatalf("after refusal: %s, %d events", got, len(mem.Events()))
	}
	if _, err := ev.ApplyApproved(ctx, "00000000-0000-4000-8000-000000000009"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("ApplyApproved on no change: %v", err)
	}

	// A release may add the flag to a registered setting; the definition
	// follows (here: the flag cleared behind the registry's back, then
	// registered again).
	reg := settings.DBRegistrar{DB: e.appPool()}
	e.admin(e.db, `UPDATE posture.setting_def SET loosening_needs_approval = false WHERE key = 'audit.otlp_destination'`)
	if err := reg.Register(ctx, "F-002", "4", settings.F002Defs()); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery(`SELECT loosening_needs_approval FROM posture.setting_def WHERE key = 'audit.otlp_destination'`); got != "t" {
		t.Fatalf("flag not set on re-registration: %s", got)
	}
}

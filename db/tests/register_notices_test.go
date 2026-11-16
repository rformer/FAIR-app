package tests

import (
	"context"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/register"
)

// F-009 T-12 (F-009-AC-20; design §3.7): a risk's owner hears once when its
// exposure goes stale and once when an action goes overdue; again only
// after the condition cleared and returned.
func TestRegisterNotices(t *testing.T) {
	f := strideF007Fixture(t) // owen's risk at A1, pinned to a run of scenario s1
	ra, rg := f.ra, f.rg
	ctx := context.Background()
	job := register.NoticeJob{DB: ra.appPool()}
	sweep := func() (int, int) {
		t.Helper()
		o, c, err := job.Sweep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return o, c
	}
	outbox := func() string {
		return ra.adminQuery("SELECT coalesce(string_agg(kind, ',' ORDER BY id), '') FROM register.notice_outbox WHERE risk_id = '" + f.risk + "'")
	}
	if o, _ := sweep(); o != 0 || outbox() != "" {
		t.Fatalf("a current risk: %d %s", o, outbox())
	}
	// Stale: a newer scenario version.
	doc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+f.s1, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+f.s1, map[string]any{"document": doc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario v2: %d %s", got.code, got.raw)
	}
	if o, _ := sweep(); o != 1 || outbox() != "risk.stale" {
		t.Fatalf("stale: %d %s", o, outbox())
	}
	if o, _ := sweep(); o != 0 || outbox() != "risk.stale" {
		t.Errorf("stale again: %d %s", o, outbox())
	}
	if got := ra.adminQuery("SELECT user_id FROM register.notice_outbox WHERE risk_id = '" + f.risk + "'"); got != f.owen {
		t.Errorf("to %s, not the owner", got)
	}
	// Cleared (closed), then returned (reopened, still stale): again.
	if got := rg.call(t, "POST", "owen", "/api/v1/register/risks/"+f.risk+"/close", map[string]any{"reason": "mitigated"}); got.code != 200 {
		t.Fatalf("close: %d %s", got.code, got.raw)
	}
	if _, c := sweep(); c != 1 {
		t.Errorf("cleared %d", c)
	}
	if got := rg.call(t, "POST", "owen", "/api/v1/register/risks/"+f.risk+"/reopen", map[string]any{"reason": "back"}); got.code != 200 {
		t.Fatalf("reopen: %d %s", got.code, got.raw)
	}
	if o, _ := sweep(); o != 1 || outbox() != "risk.stale,risk.stale" {
		t.Errorf("returned: %d %s", o, outbox())
	}

	// Overdue: an action past its due date; done clears it.
	action := map[string]any{"id": "0f6b7a1e-3c2d-4b5a-9e8f-7a6b5c4d3e2f", "title": "Segment the claims network", "owner": f.owen,
		"due": time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02"), "state": "planned"}
	plan := func(version int, state string) {
		t.Helper()
		action["state"] = state
		got := rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+f.risk+"/treatment", map[string]any{"expected_version": version, "change_note": "plan",
			"document": map[string]any{"schema_version": 1, "decision": "transfer", "rationale": "Insure it.", "actions": []any{action}}})
		if got.code != 200 {
			t.Fatalf("treatment: %d %s", got.code, got.raw)
		}
	}
	plan(0, "planned")
	if o, _ := sweep(); o != 1 || outbox() != "risk.stale,risk.stale,risk.action_overdue" {
		t.Errorf("overdue: %d %s", o, outbox())
	}
	plan(1, "done")
	if _, c := sweep(); c != 1 {
		t.Errorf("an action done clears it: %d", c)
	}

	// The notify service takes them to the owner, linked to the risk.
	pool := notifyPool(t, ra.env)
	// One leader cycle drains more than a batch (F-009 T-14: notify.Cycle).
	if n, err := (notify.Cycle{Collector: notify.Collector{DB: pool, Batch: 1}, FanOut: notify.FanOut{DB: pool, Batch: 1}}).Run(ctx); err != nil || n != 3 {
		t.Fatalf("one cycle collected %d: %v", n, err)
	}
	if got := ra.adminQuery(`SELECT string_agg(n.kind || '|' || (n.envelope #>> '{item,link}') || '|' || i.user_id, ',' ORDER BY n.seq)
		FROM notify.notice n JOIN notify.inbox i ON i.notice_id = n.id WHERE n.source = 'register'`); got !=
		"risk.stale|/register/risks/"+f.risk+"|"+f.owen+",risk.stale|/register/risks/"+f.risk+"|"+f.owen+",risk.action_overdue|/register/risks/"+f.risk+"|"+f.owen {
		t.Errorf("notices: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM register.notice_outbox WHERE delivered_at IS NULL"); got != "0" {
		t.Errorf("%s left in the outbox", got)
	}
	if got := ra.adminState("SET ROLE app_rw; PERFORM register.notice_sweep(0)"); got != "PF026" {
		t.Errorf("a zero batch: %s", got)
	}
}

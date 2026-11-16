package tests

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/acceptance"
)

// F-008 T-06 (F-008-AC-09, AC-10, AC-13; design §3.2, §3.6): the job, with
// time moved by setting expiry dates as acceptance_definer.
func TestAcceptanceSweep(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	job := acceptance.Job{DB: ra.appPool()}
	sweep := func() acceptance.Swept {
		t.Helper()
		s, err := job.Sweep(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	active := func(name string) (risk, id string) {
		t.Helper()
		risk = a.accepted(t, name, "owen")
		id, code := a.request(t, "owen", risk, "Within appetite", days(200), "")
		if code != "" {
			t.Fatalf("request %s: %s", name, code)
		}
		if _, code := a.decide(t, "appA1", id, "approve"); code != "" {
			t.Fatalf("approve %s: %s", name, code)
		}
		return risk, id
	}
	expiresIn := func(id string, n int) {
		t.Helper()
		ra.admin(ra.db, "SET ROLE acceptance_definer; UPDATE acceptance.acceptance SET expires_on = current_date + "+strconv.Itoa(n)+" WHERE id = '"+id+"'")
	}
	state := func(id string) string {
		return ra.adminQuery("SELECT state || coalesce('/' || end_reason, '') || '|' || tier || '|' || (SELECT code FROM iam.bu WHERE id = tier_bu_id) FROM acceptance.acceptance WHERE id = '" + id + "'")
	}
	notices := func(id string) string {
		return ra.adminQuery("SELECT coalesce(string_agg(kind || ':' || coalesce(lead_days::text, '-') || ':' || coalesce(tier::text, '-') || ':' || coalesce((SELECT split_part(email, '@', 1) FROM iam.app_user u WHERE u.id = user_id), '*'), ',' ORDER BY id), '') FROM acceptance.notice_outbox WHERE acceptance_id = '" + id + "' AND kind IN ('expiring', 'expired', 'suspended') OR (acceptance_id = '" + id + "' AND kind = 'decision_needed' AND tier IS NOT NULL)")
	}
	_, x := active("Claims ransomware 2")
	if s := sweep(); s != (acceptance.Swept{}) {
		t.Errorf("nothing due: %+v", s)
	}

	// Notices (AC-10): 30, 14, 7 days before, each once, to the owner (who requested).
	expiresIn(x, 30)
	sweep()
	sweep()
	expiresIn(x, 14)
	sweep()
	expiresIn(x, 8)
	sweep()
	expiresIn(x, 7)
	sweep()
	if got := notices(x); got != "expiring:30:-:owen,expiring:14:-:owen,expiring:7:-:owen" {
		t.Errorf("notices: %s", got)
	}
	// Expiry (AC-09): ended, notified, audited, by the system.
	expiresIn(x, 0)
	if s := sweep(); s.Expired != 1 || s.Notices != 1 {
		t.Errorf("expiry: %+v", s)
	}
	if got := state(x); got != "expired|1|A1" {
		t.Errorf("expired: %s", got)
	}
	if got := notices(x); !strings.HasSuffix(got, ",expired:-:-:owen") {
		t.Errorf("expiry notice: %s", got)
	}
	if got := ra.adminQuery("SELECT kind || '|' || (actor IS NULL) FROM acceptance.step WHERE acceptance_id = '" + x + "' ORDER BY n DESC LIMIT 1"); got != "expired|true" {
		t.Errorf("the last step: %s", got)
	}
	if s := sweep(); s.Expired != 0 || s.Notices != 0 {
		t.Errorf("again: %+v", s)
	}

	// After an outage (the job catches up): a 30-day lead missed, only the 7-day
	// notice; a passed expiry ends it with only the expiry notice.
	_, y := active("Claims vendor")
	_, z := active("Claims insider")
	expiresIn(y, 5)
	expiresIn(z, -3)
	if s := sweep(); s.Expired != 1 {
		t.Errorf("catching up: %+v", s)
	}
	if got := notices(y); got != "expiring:7:-:owen" {
		t.Errorf("after an outage: %s", got)
	}
	if got := notices(z); got != "expired:-:-:owen" {
		t.Errorf("expired in an outage: %s", got)
	}
	// A suspended acceptance past its expiry ends too.

	// A higher tier (AC-13): suspended, a review at the new tier (A, one
	// level up), its approvers reactivate it; A1's approver no longer can.
	_, h := active("Claims fraud")
	setInstance(ra.env, "acceptance.tier1_max", "1")
	defer setInstance(ra.env, "acceptance.tier1_max", "100000")
	s := sweep()
	if s.Suspended != 2 { // and y, still active
		t.Errorf("suspensions: %+v", s)
	}
	if got := state(h); got != "suspended|2|A" {
		t.Errorf("suspended: %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(kind, ',' ORDER BY n) FROM acceptance.step WHERE acceptance_id = '" + h + "' AND n > 3"); got != "suspended,review_requested" {
		t.Errorf("steps: %s", got)
	}
	if got := ra.adminQuery("SELECT (data #>> '{tier,n}') || '|' || (data #>> '{tier,bu_id}') FROM acceptance.step WHERE acceptance_id = '" + h + "' AND kind = 'review_requested'"); got != "2|"+ra.bu["A"] {
		t.Errorf("the review: %s", got)
	}
	if got := notices(h); got != "suspended:-:2:owen,decision_needed:-:2:*" {
		t.Errorf("suspension notices: %s", got)
	}
	if s := sweep(); s.Suspended != 0 {
		t.Errorf("suspended twice: %+v", s)
	}
	if _, code := a.decide(t, "appA1", h, "approve"); code != "42501 not_your_tier" {
		t.Errorf("A1's approver: %s", code)
	}
	if _, code := a.decide(t, "appA", h, "approve"); code != "" {
		t.Errorf("A's approver: %s", code)
	}
	if got := state(h); got != "active|2|A" {
		t.Errorf("reactivated: %s", got)
	}
	// A lower tier changes nothing.
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	if s := sweep(); s.Suspended != 0 {
		t.Errorf("a lower tier: %+v", s)
	}
	if got := state(h); got != "active|2|A" {
		t.Errorf("after a lower tier: %s", got)
	}
	// Into tier 3 later: suspended again, its notices queued again (tier 3).
	setInstance(ra.env, "acceptance.tier1_max", "1")
	setInstance(ra.env, "acceptance.tier2_max", "2")
	defer setInstance(ra.env, "acceptance.tier2_max", "1000000")
	sweep()
	if got := state(h); got != "suspended|3|ENTERPRISE" {
		t.Errorf("tier 3: %s", got)
	}
	if got := notices(h); !strings.HasSuffix(got, "suspended:-:3:owen,decision_needed:-:3:*") {
		t.Errorf("tier 3 notices: %s", got)
	}
	// A suspended acceptance past its expiry ends as expired.
	expiresIn(h, 0)
	sweep()
	if got := state(h); got != "expired|3|ENTERPRISE" {
		t.Errorf("suspended, then expired: %s", got)
	}
	setInstance(ra.env, "acceptance.tier2_max", "1000000")
	setInstance(ra.env, "acceptance.tier1_max", "100000")

	// A stale exposure does not suspend (design §3.3).
	st, sid := active("Claims stale")
	scenario := ra.adminQuery("SELECT scenario_id FROM register.risk_scenario WHERE risk_id = '" + st + "'")
	sdoc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+scenario, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+scenario, map[string]any{"document": sdoc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario v2: %d %s", got.code, got.raw)
	}
	setInstance(ra.env, "acceptance.tier1_max", "1")
	sweep()
	if got := state(sid); got != "active|1|A1" {
		t.Errorf("stale: %s", got)
	}
	setInstance(ra.env, "acceptance.tier1_max", "100000")

	// Audited, by the system (AC-18).
	got := ra.adminQuery(`SELECT string_agg(DISTINCT (body ->> 'type') || ':' || (body ->> 'actor'), ',') FROM audit.intake
		WHERE body ->> 'type' IN ('acceptance.expired', 'acceptance.suspended', 'acceptance.review_requested')`)
	if got != "acceptance.expired:system:risk,acceptance.review_requested:system:risk,acceptance.suspended:system:risk" {
		t.Errorf("events: %s", got)
	}
}

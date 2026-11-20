package tests

import (
	"strconv"
	"strings"
	"testing"
)

// F-008 T-09: the STRIDE suite for design §7, over acceptanceFixture (owen
// a Risk Owner at A, chief at the root, analyst a Risk Analyst at A,
// mallory at B; approvers appA1 at A1, appA at A, root1 and root2 at the
// root). The rows map to these tests and others in TestSTRIDECatalog.

func (a *acceptanceEnv) userID(name string) string {
	return a.ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + name + "@example.test'")
}

func (a *acceptanceEnv) pending(t *testing.T, name string) (risk, id string) {
	t.Helper()
	risk = a.accepted(t, name, "owen")
	id, code := a.request(t, "owen", risk, "Within appetite", days(120), "")
	if code != "" {
		t.Fatalf("request %s: %s", name, code)
	}
	return risk, id
}

// E: someone accepts a risk beyond their authority.
func TestSTRIDEF008Authority(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	_, id := a.pending(t, "Authority tier 1")
	// Only acceptance.approve at the tier's BU (A1, inherited from A and the
	// root): refused (42501), or not found by those who cannot see it.
	for user, want := range map[string]string{"analyst": "42501", "chief": "42501", "mallory": "P0002", "est": "P0002"} {
		if _, code := a.decide(t, user, id, "approve"); !strings.HasPrefix(code, want) {
			t.Errorf("%s decides: %q, want %s", user, code, want)
		}
	}
	// Tier 2 is A's: A1's approver may not decide it, nor revoke it once active.
	setInstance(ra.env, "acceptance.tier1_max", "1")
	_, t2 := a.pending(t, "Authority tier 2")
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	if _, code := a.decide(t, "appA1", t2, "approve"); code != "42501 not_your_tier" {
		t.Errorf("tier 2 by A1's approver: %q", code)
	}
	// The tier's approvals are fixed at request: later settings do not move it.
	setInstance(ra.env, "acceptance.tier1_approvals", "2")
	if _, code := a.decide(t, "appA1", id, "approve"); code != "" {
		t.Fatalf("approve: %q", code)
	}
	setInstance(ra.env, "acceptance.tier1_approvals", "1")
	if got := ra.adminQuery("SELECT state || '|' || approvals_needed FROM acceptance.acceptance WHERE id = '" + id + "'"); got != "active|1" {
		t.Errorf("with the snapshot's approvals: %s", got)
	}
	if _, code := a.sql(t, "appA1", "SELECT acceptance.revoke($1, 'x')::text", t2); code != "42501 not_your_tier" {
		t.Errorf("revoking at another tier: %q", code)
	}
	// Without a signed context, as another role, or directly: refused.
	for _, c := range []struct{ name, sql, want string }{
		{"no context", "SET ROLE app_rw; SELECT acceptance.decide('" + t2 + "', 'approve', 'x', NULL)", "PF027"},
		{"another definer", "SET ROLE register_definer; SELECT acceptance.decide('" + t2 + "', 'approve', 'x', NULL)", "42501"},
		{"the job's function", "SET ROLE register_definer; SELECT acceptance.sweep()", "42501"},
		{"a direct head update", "SET ROLE app_rw; UPDATE acceptance.acceptance SET state = 'active' WHERE id = '" + t2 + "'", "42501"},
		{"a direct insert", "SET ROLE app_rw; INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind) SELECT id, 9, bu_id, 'approved' FROM acceptance.acceptance LIMIT 1", "42501"},
	} {
		if got := ra.adminState(c.sql); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := ra.adminQuery("SELECT state FROM acceptance.acceptance WHERE id = '" + t2 + "'"); got != "pending" {
		t.Errorf("tier 2 after the attempts: %s", got)
	}
}

// E: one person requests and approves, or approves twice.
func TestSTRIDEF008SeparationOfDuties(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	// The owner and a requester who also hold acceptance.approve at the tier.
	ra.mustOwner(grant("platform", "user:owen", "Approver", "A1"))
	ra.mustOwner(grant("platform", "user:chief", "Approver", "ENTERPRISE"))
	ra.drain()
	risk, id := a.pending(t, "Duties owned")
	if _, code := a.decide(t, "owen", id, "approve"); code != "42501 separation_of_duties" {
		t.Errorf("the owner and requester approves: %q", code)
	}
	if _, code := a.request(t, "chief", risk, "x", days(30), ""); code != "PF027 pending_exists" {
		t.Errorf("a second request: %q", code)
	}
	if _, code := a.sql(t, "owen", "SELECT acceptance.withdraw($1, 'by chief')::text", id); code != "" {
		t.Fatalf("withdraw: %q", code)
	}
	cid, code := a.request(t, "chief", risk, "Requested by the chief", days(30), "")
	if code != "" {
		t.Fatalf("chief requests: %q", code)
	}
	for _, user := range []string{"chief", "owen"} { // the requester; the owner
		if _, code := a.decide(t, user, cid, "approve"); code != "42501 separation_of_duties" {
			t.Errorf("%s approves chief's request: %q", user, code)
		}
	}
	// Two approvals: two different approvers, each once.
	setInstance(ra.env, "acceptance.tier1_approvals", "2")
	_, two := a.pending(t, "Duties twice")
	setInstance(ra.env, "acceptance.tier1_approvals", "1")
	if _, code := a.decide(t, "appA1", two, "approve"); code != "" {
		t.Fatalf("first approval: %q", code)
	}
	if _, code := a.decide(t, "appA1", two, "approve"); code != "PF027 already_decided" {
		t.Errorf("approving twice: %q", code)
	}
	if got := ra.adminQuery("SELECT state FROM acceptance.acceptance WHERE id = '" + two + "'"); got != "pending" {
		t.Errorf("after one approver twice: %s", got)
	}
	if _, code := a.decide(t, "appA", two, "approve"); code != "" {
		t.Fatalf("second approval: %q", code)
	}
	if got := ra.adminQuery("SELECT state || '|' || (SELECT count(DISTINCT actor) FROM acceptance.step WHERE acceptance_id = '" + two + "' AND kind = 'approved') FROM acceptance.acceptance WHERE id = '" + two + "'"); got != "active|2" {
		t.Errorf("two approvers: %s", got)
	}
}

// T: an acceptance's history or evidence is altered.
func TestSTRIDEF008HistoryTamper(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	_, id := a.pending(t, "Tamper")
	if _, code := a.decide(t, "appA1", id, "approve"); code != "" {
		t.Fatal(code)
	}
	evidence := ra.adminQuery("SELECT data::text FROM acceptance.step WHERE acceptance_id = '" + id + "' AND n = 1")
	for _, role := range []string{"app_rw", "acceptance_definer", "register_definer", "fair_owner", ""} {
		set := ""
		if role != "" {
			set = "SET ROLE " + role + "; "
		}
		for _, sql := range []string{
			"UPDATE acceptance.step SET reason = 'forged' WHERE acceptance_id = '" + id + "'",
			"DELETE FROM acceptance.step WHERE acceptance_id = '" + id + "'",
			"TRUNCATE acceptance.step CASCADE",
		} {
			if got := ra.adminState(set + sql); got == "" {
				t.Errorf("as %q: %s succeeded", role, sql)
			}
		}
		if role != "acceptance_definer" && role != "" {
			if got := ra.adminState(set + "UPDATE acceptance.acceptance SET expires_on = expires_on + 365 WHERE id = '" + id + "'"); got == "" {
				t.Errorf("as %q: the head updated", role)
			}
		}
	}
	// The evidence is a copy: a newer scenario version and treatment change
	// the risk, not what the acceptance was granted on.
	scenario := ra.adminQuery("SELECT l.scenario_id FROM register.risk_scenario l JOIN acceptance.acceptance x ON x.risk_id = l.risk_id WHERE x.id = '" + id + "'")
	doc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+scenario, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+scenario, map[string]any{"document": doc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario v2: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT data::text FROM acceptance.step WHERE acceptance_id = '" + id + "' AND n = 1"); got != evidence {
		t.Errorf("the evidence changed:\n%s\n%s", evidence, got)
	}
	if got := ra.adminQuery("SELECT data #>> '{exposure,status}' FROM acceptance.step WHERE acceptance_id = '" + id + "' AND n = 1"); got != "current" {
		t.Errorf("the evidence's status: %s", got)
	}
}

// I: acceptances cross business units.
func TestSTRIDEF008Visibility(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	ac := acceptanceAPI(t, ra)
	_, id := a.pending(t, "Visibility")
	setInstance(ra.env, "acceptance.tier1_max", "1")
	_, t2 := a.pending(t, "Visibility tier 2")
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	// mallory (B) holds acceptance.view at B only: nothing of A's.
	if got := ac.call(t, "GET", "mallory", "/api/v1/acceptances", nil); got.code != 200 || len(got.body["acceptances"].([]any)) != 0 {
		t.Errorf("mallory lists: %d %s", got.code, got.raw)
	}
	for _, path := range []string{"/api/v1/acceptances/" + id, "/api/v1/acceptances?risk=" + ra.adminQuery("SELECT risk_id FROM acceptance.acceptance WHERE id = '"+id+"'")} {
		got := ac.call(t, "GET", "mallory", path, nil)
		if (got.code != 404 && got.code != 200) || (got.code == 200 && len(got.body["acceptances"].([]any)) != 0) {
			t.Errorf("mallory reads %s: %d %s", path, got.code, got.raw)
		}
	}
	if got := ac.call(t, "GET", "mallory", "/api/v1/acceptances/permissions?bu="+ra.bu["A1"], nil).body; got["acceptance.view"] != false {
		t.Errorf("mallory's permissions at A1: %v", got)
	}
	if n, code := a.sql(t, "mallory", "SELECT count(*)::text FROM acceptance.people(ARRAY[$1::uuid])", a.userID("owen")); n != "0" || code != "" {
		t.Errorf("mallory reads owen's name: %s %s", n, code)
	}
	if n, _ := a.sql(t, "mallory", "SELECT (SELECT count(*) FROM acceptance.acceptance)::text || '|' || (SELECT count(*) FROM acceptance.step)::text"); n != "0|0" {
		t.Errorf("mallory's rows: %s", n)
	}
	// The inbox: only what the caller sees and may decide.
	ids := func(user string) string {
		var out []string
		for _, x := range ac.call(t, "GET", user, "/api/v1/acceptances/inbox", nil).body["acceptances"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return strings.Join(out, ",")
	}
	if got := ids("appA1"); got != id {
		t.Errorf("appA1's inbox: %s (tier 2 is A's)", got)
	}
	if got := ids("appA"); !strings.Contains(got, id) || !strings.Contains(got, t2) {
		t.Errorf("appA's inbox: %s", got)
	}
	if got := ids("mallory"); got != "" {
		t.Errorf("mallory's inbox: %s", got)
	}
}

// R: a decision cannot be attributed.
func TestSTRIDEF008Attribution(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	_, id := a.pending(t, "Attribution")
	events := func() string {
		return ra.adminQuery(`SELECT string_agg((body ->> 'type') || '|' || (body ->> 'actor') || '|' || (body ->> 'bu_id') || '|' || coalesce(body #>> '{attributes,reason}', '-'), ',' ORDER BY id)
			FROM audit.intake WHERE body ->> 'target' = 'acceptance:` + id + `'`)
	}
	steps := func() string {
		return ra.adminQuery("SELECT count(*) FROM acceptance.step WHERE acceptance_id = '" + id + "'")
	}
	before, n := events(), steps()
	// A refused decision leaves neither a step nor an event.
	if _, code := a.decide(t, "owen", id, "approve"); code == "" {
		t.Fatal("owen approved")
	}
	if events() != before || steps() != n {
		t.Errorf("a refused decision left a trace: %s / %s", events(), steps())
	}
	if _, code := a.decide(t, "appA1", id, "approve"); code != "" {
		t.Fatal(code)
	}
	owen, app, bu := a.userID("owen"), a.userID("appA1"), ra.bu["A1"]
	want := "acceptance.requested|" + owen + "|" + bu + "|-," +
		"acceptance.approved|" + app + "|" + bu + "|Reviewed with the committee," +
		"acceptance.activated|" + app + "|" + bu + "|-"
	if got := events(); got != want {
		t.Errorf("events:\n%s\nwant\n%s", got, want)
	}
	// Every step has its actor and a decision its reason.
	if got := ra.adminQuery("SELECT string_agg(kind || '|' || coalesce(actor::text, 'system') || '|' || coalesce(reason, '-'), ',' ORDER BY n) FROM acceptance.step WHERE acceptance_id = '" + id + "'"); got != "requested|"+owen+"|Within appetite,approved|"+app+"|Reviewed with the committee,activated|"+app+"|-" {
		t.Errorf("steps: %s", got)
	}
}

// D: request floods.
func TestSTRIDEF008Limits(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	ac := acceptanceAPI(t, ra)
	risk, _ := a.pending(t, "Limits")
	if _, code := a.request(t, "owen", risk, "again", days(30), ""); code != "PF027 pending_exists" {
		t.Errorf("a second open request: %q", code)
	}
	other := a.accepted(t, "Limits long", "owen")
	if _, code := a.request(t, "owen", other, strings.Repeat("x", 5001), days(30), ""); code != "PF027 invalid_request" {
		t.Errorf("a 5,001-character justification: %q", code)
	}
	if _, code := a.request(t, "owen", other, "ok", days(366), ""); code != "PF027 invalid_expiry" {
		t.Errorf("past the longest duration: %q", code)
	}
	big := map[string]any{"risk_id": other, "justification": strings.Repeat("x", 70_000), "expires_on": days(30).Format("2006-01-02")}
	if got := ac.call(t, "POST", "owen", "/api/v1/acceptances", big); got.code != 400 {
		t.Errorf("a 70 KB body: %d", got.code)
	}
	if got := ac.call(t, "GET", "owen", "/api/v1/acceptances?limit="+strconv.Itoa(201), nil); got.code != 400 {
		t.Errorf("a page of 201: %d", got.code)
	}
	if got := ra.adminQuery("SELECT acceptance.sweep_batch()"); got != "500" {
		t.Errorf("the sweep's batch: %s", got)
	}
}

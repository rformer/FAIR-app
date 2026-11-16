package tests

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/rformer/fair-app/internal/acceptance"
	"github.com/rformer/fair-app/internal/acceptanceapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-008 T-05 (F-008-AC-01 to AC-08, AC-14, AC-16, AC-19; design §3.3, §6):
// the acceptance API, and the register's acceptance summary and filter.

type fixedAcceptanceLimits acceptance.Limits

func (l fixedAcceptanceLimits) Limits() (acceptance.Limits, error) { return acceptance.Limits(l), nil }

var defaultAcceptanceLimits = fixedAcceptanceLimits{Tier1Max: 100_000, Tier2Max: 1_000_000, Tier2LevelsUp: 1, Tier1Approvals: 1, Tier2Approvals: 1,
	Tier3Approvals: 2, MaxDurationDays: 365}

var acceptanceEnvs int

// acceptanceAPI serves the acceptance API on the risk env's keys.
func acceptanceAPI(t *testing.T, ra *riskAPIEnv) *riskAPIEnv {
	t.Helper()
	pool := ra.appPool()
	api := &acceptanceapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Settings: defaultAcceptanceLimits}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	ac := *ra
	ac.url = srv.URL
	acceptanceEnvs++
	ac.n += 700000 + 100000*acceptanceEnvs
	return &ac
}

func TestAcceptanceAPI(t *testing.T) {
	a := acceptanceFixture(t)
	ra, rg := a.ra, a.rg
	ac := acceptanceAPI(t, ra)
	a.accept(t, a.risk)
	ids := func(user, query string) []string {
		t.Helper()
		got := ac.call(t, "GET", user, "/api/v1/acceptances"+query, nil)
		if got.code != 200 {
			t.Fatalf("list %s as %s: %d %s", query, user, got.code, got.raw)
		}
		var out []string
		for _, x := range got.body["acceptances"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return out
	}
	inbox := func(user string) []string {
		t.Helper()
		got := ac.call(t, "GET", user, "/api/v1/acceptances/inbox", nil)
		if got.code != 200 {
			t.Fatalf("inbox as %s: %d %s", user, got.code, got.raw)
		}
		var out []string
		for _, x := range got.body["acceptances"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return out
	}
	request := func(user, risk string, body map[string]any) apiResp {
		t.Helper()
		b := map[string]any{"risk_id": risk, "justification": "Within appetite", "conditions": "Review quarterly", "expires_on": days(200).Format("2006-01-02")}
		for k, v := range body {
			b[k] = v
		}
		return ac.call(t, "POST", user, "/api/v1/acceptances", b)
	}

	// Who may, and every refusal (AC-01, AC-02, AC-17).
	if got := ac.call(t, "GET", "est", "/api/v1/acceptances", nil); got.code != 404 {
		t.Errorf("no acceptance permission: %d", got.code)
	}
	unquantified := a.create(t, "owen", ra.bu["A1"], "Claims compliance", "", "")
	a.accept(t, unquantified)
	for name, c := range map[string]struct {
		user, risk string
		body       map[string]any
		code       int
		err        string
	}{
		"a viewer":           {"analyst", a.risk, nil, 403, "forbidden"},
		"not a date":         {"owen", a.risk, map[string]any{"expires_on": "soon"}, 422, "invalid_expiry"},
		"too far":            {"owen", a.risk, map[string]any{"expires_on": days(400).Format("2006-01-02")}, 422, "invalid_expiry"},
		"no justification":   {"owen", a.risk, map[string]any{"justification": ""}, 422, "invalid_request"},
		"an unknown field":   {"owen", a.risk, map[string]any{"colour": "red"}, 400, "invalid_request"},
		"not current":        {"owen", unquantified, nil, 409, "exposure_not_current"},
		"another BU's risk":  {"mallory", a.risk, nil, 404, "not_found"},
	} {
		if got := request(c.user, c.risk, c.body); got.code != c.code || got.body["error"] != c.err {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	got := request("owen", a.risk, nil)
	if got.code != 201 || got.body["state"] != "pending" || got.body["tier"] != 1.0 || got.body["tier_bu_id"] != ra.bu["A1"] || got.body["approvals_needed"] != 1.0 {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if got := request("owen", a.risk, nil); got.code != 409 || got.body["error"] != "pending_exists" {
		t.Errorf("a second request: %d %s", got.code, got.raw)
	}

	// Reading it (AC-16): the evidence and what each may do.
	read := func(user string) map[string]any {
		t.Helper()
		got := ac.call(t, "GET", user, "/api/v1/acceptances/"+id, nil)
		if got.code != 200 {
			t.Fatalf("read as %s: %d %s", user, got.code, got.raw)
		}
		return got.body
	}
	v := read("analyst")
	if v["evidence"].(map[string]any)["justification"] != "Within appetite" || len(v["steps"].([]any)) != 1 || v["may_decide"] != false || v["risk_title"] != "Claims ransomware" {
		t.Errorf("the analyst reads: %v", v)
	}
	if v := read("owen"); v["may_withdraw"] != true || v["may_decide"] != false {
		t.Errorf("owen reads: may_withdraw %v may_decide %v", v["may_withdraw"], v["may_decide"])
	}
	if v := read("appA1"); v["may_decide"] != true {
		t.Errorf("appA1 may not decide")
	}
	if got := ac.call(t, "GET", "mallory", "/api/v1/acceptances/"+id, nil); got.code != 404 {
		t.Errorf("mallory reads it: %d", got.code)
	}

	// The inbox (AC-08): approvers at the tier's BU or above; not the requester or owner.
	for user, want := range map[string]bool{"appA1": true, "appA": true, "root1": true, "owen": false, "analyst": false} {
		if got := slices.Contains(inbox(user), id); got != want {
			t.Errorf("%s's inbox has it: %v, want %v", user, got, want)
		}
	}

	// Decisions (AC-05 to AC-07).
	decide := func(user, decision string) apiResp {
		t.Helper()
		return ac.call(t, "POST", user, "/api/v1/acceptances/"+id+"/decisions", map[string]any{"decision": decision, "rationale": "Reviewed with the committee"})
	}
	if got := decide("owen", "approve"); got.code != 403 || got.body["error"] != "not_your_tier" {
		t.Errorf("owen decides: %d %s", got.code, got.raw)
	}
	if got := ac.call(t, "POST", "appA1", "/api/v1/acceptances/"+id+"/decisions", map[string]any{"decision": "maybe", "rationale": "x"}); got.code != 422 {
		t.Errorf("an unknown decision: %d %s", got.code, got.raw)
	}
	if got := decide("appA1", "approve"); got.code != 200 || got.body["state"] != "active" {
		t.Fatalf("approve: %d %s", got.code, got.raw)
	}
	if got := decide("appA", "approve"); got.code != 409 || got.body["error"] != "not_pending" {
		t.Errorf("approving an active acceptance: %d %s", got.code, got.raw)
	}
	if slices.Contains(inbox("appA"), id) {
		t.Error("an active acceptance in the inbox")
	}
	if v := read("appA1"); v["may_revoke"] != true || v["may_decide"] != false {
		t.Errorf("appA1 after: %v %v", v["may_revoke"], v["may_decide"])
	}
	if v := read("owen"); v["may_renew"] != true {
		t.Errorf("owen may not renew")
	}

	// The register shows it (F-007-AC-18), and filters by it.
	summary := func() map[string]any {
		t.Helper()
		s, _ := rg.call(t, "GET", "owen", "/api/v1/register/risks/"+a.risk, nil).body["risk"].(map[string]any)["acceptance"].(map[string]any)
		return s
	}
	if s := summary(); s == nil || s["id"] != id || s["state"] != "active" || len(s["needs_review"].([]any)) != 0 {
		t.Errorf("the register's summary: %v", s)
	}
	riskIDs := func(q string) []string {
		var out []string
		for _, x := range rg.call(t, "GET", "owen", "/api/v1/register/risks?"+q, nil).body["risks"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return out
	}
	if got := riskIDs("acceptance=active"); !slices.Equal(got, []string{a.risk}) {
		t.Errorf("accepted risks: %v", got)
	}
	if got := riskIDs("acceptance=none"); slices.Contains(got, a.risk) || !slices.Contains(got, unquantified) {
		t.Errorf("risks without acceptance: %v", got)
	}

	// Needs review (AC-14): treatment no longer accept, a stale exposure, a move.
	review := func() []any {
		t.Helper()
		return read("owen")["needs_review"].([]any)
	}
	if got := rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+a.risk+"/treatment", map[string]any{"expected_version": 1, "change_note": "rethink",
		"document": map[string]any{"schema_version": 1, "decision": "transfer", "rationale": "Insure it."}}); got.code != 200 {
		t.Fatalf("treatment: %d %s", got.code, got.raw)
	}
	if got := review(); len(got) != 1 || got[0] != "treatment" {
		t.Errorf("treatment changed: %v", got)
	}
	if !slices.Contains(ids("owen", "?state=needs_review"), id) || !slices.Contains(riskIDs("acceptance=needs_review"), a.risk) {
		t.Error("not listed as needing review")
	}
	sdoc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+a.s1, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+a.s1, map[string]any{"document": sdoc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario v2: %d %s", got.code, got.raw)
	}
	if got := review(); len(got) != 2 || got[0] != "stale" {
		t.Errorf("stale too: %v", got)
	}
	if got := rg.call(t, "POST", "chief", "/api/v1/register/risks/"+a.risk+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "head office"}); got.code != 200 {
		t.Fatalf("move: %d %s", got.code, got.raw)
	}
	if got := review(); len(got) != 3 || got[2] != "moved" {
		t.Errorf("moved too: %v", got)
	}
	if v := read("owen"); v["state"] != "active" {
		t.Errorf("a review leaves it in force: %v", v["state"])
	}

	// Past its expiry it reads as expired, before the job ends it (AC-09).
	ra.admin(ra.db, "SET ROLE acceptance_definer; UPDATE acceptance.acceptance SET expires_on = current_date WHERE id = '"+id+"'")
	if v := read("owen"); v["state"] != "expired" || v["stored_state"] != "active" {
		t.Errorf("past expiry: %v / %v", v["state"], v["stored_state"])
	}
	if !slices.Contains(ids("owen", "?state=expired"), id) || slices.Contains(ids("owen", "?state=active"), id) {
		t.Error("the list by state")
	}
	if s := summary(); s["state"] != "expired" {
		t.Errorf("the register shows: %v", s)
	}
	// Revoke (AC-15) and withdraw (AC-03).
	if got := ac.call(t, "POST", "owen", "/api/v1/acceptances/"+id+"/revoke", map[string]any{"reason": "x"}); got.code != 403 {
		t.Errorf("owen revokes: %d", got.code)
	}
	// Moved to A, its approvers are A's now (tier 1: the risk's own BU).
	if got := ac.call(t, "POST", "appA1", "/api/v1/acceptances/"+id+"/revoke", map[string]any{"reason": "x"}); got.code != 404 {
		t.Errorf("the old BU's approver revokes: %d %s", got.code, got.raw)
	}
	if got := ac.call(t, "POST", "appA", "/api/v1/acceptances/"+id+"/revoke", map[string]any{"reason": "conditions not met"}); got.code != 200 || got.body["state"] != "ended" || got.body["end_reason"] != "revoked" {
		t.Errorf("revoke: %d %s", got.code, got.raw)
	}
	w := a.accepted(t, "Claims vendor", "owen")
	wid := request("owen", w, nil).body["id"].(string)
	if got := ac.call(t, "POST", "owen", "/api/v1/acceptances/"+wid+"/withdraw", map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("without a reason: %d", got.code)
	}
	if got := ac.call(t, "POST", "owen", "/api/v1/acceptances/"+wid+"/withdraw", map[string]any{"reason": "reassessed"}); got.code != 200 || got.body["end_reason"] != "withdrawn" {
		t.Errorf("withdraw: %d %s", got.code, got.raw)
	}

	// The list's filters (AC-19).
	if got := ids("owen", "?bu="+ra.bu["A1"]); !slices.Contains(got, wid) || slices.Contains(got, id) {
		t.Errorf("A1's subtree: %v (the revoked one moved to A)", got)
	}
	if got := ids("owen", "?bu="+ra.bu["A"]); !slices.Contains(got, wid) || !slices.Contains(got, id) {
		t.Errorf("A's subtree: %v", got)
	}
	if got := ids("owen", "?state=ended"); len(got) != 2 {
		t.Errorf("ended: %v", got)
	}
	if got := ids("owen", "?risk="+w); !slices.Equal(got, []string{wid}) {
		t.Errorf("by risk: %v", got)
	}
	if got := ac.call(t, "GET", "owen", "/api/v1/acceptances?state=maybe", nil); got.code != 400 {
		t.Errorf("an unknown state: %d", got.code)
	}
	// Names (T-07): the requester and the steps' actors, to those who see it.
	if v := read("owen"); v["names"].(map[string]any)[v["requested_by"].(string)] == nil || len(v["names"].(map[string]any)) < 2 {
		t.Errorf("names: %v", v["names"])
	}
	if got := ac.call(t, "GET", "owen", "/api/v1/acceptances", nil).body["acceptances"].([]any)[0].(map[string]any)["requested_by_name"]; got == nil {
		t.Error("no requester's name in the list")
	}
	// What the caller may do at a BU (T-07).
	perms := func(user, bu string) map[string]any {
		t.Helper()
		got := ac.call(t, "GET", user, "/api/v1/acceptances/permissions?bu="+bu, nil)
		if got.code != 200 {
			t.Fatalf("permissions: %d %s", got.code, got.raw)
		}
		return got.body
	}
	if p := perms("owen", ra.bu["A1"]); p["acceptance.request"] != true || p["acceptance.approve"] != false {
		t.Errorf("owen at A1: %v", p)
	}
	if p := perms("appA", ra.bu["A1"]); p["acceptance.request"] != false || p["acceptance.approve"] != true {
		t.Errorf("appA at A1: %v", p)
	}
	if p := perms("owen", ra.bu["B"]); p["acceptance.request"] != false || p["acceptance.view"] != false {
		t.Errorf("owen at B: %v", p)
	}
	tiers := ac.call(t, "GET", "owen", "/api/v1/acceptances/tiers", nil)
	if tiers.code != 200 || len(tiers.body["tiers"].([]any)) != 3 || tiers.body["max_duration_days"] != 365.0 {
		t.Errorf("tiers: %d %s", tiers.code, tiers.raw)
	}
}

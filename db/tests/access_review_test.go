package tests

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// F-001 T-39 (AC-49): access review campaigns. Reviewers certify or revoke
// each item, every decision is audited, and a revocation removes the access
// at once (the scope worker's drain).

func TestAccessReviews(t *testing.T) {
	be := bgFixture(t)
	e := be.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	for _, u := range []string{"ann", "carol", "dave", "erin", "rev", "rev2", "rev3", "zed", "rootrev"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Reviewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['access_review.decide', 'bu.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:ann", "Risk Analyst", "A1"))
	e.mustOwner(grant("admin", "user:rev", "Reviewer", "A"))
	e.mustOwner(grant("admin", "user:rev2", "Reviewer", "A"))
	e.mustOwner(grant("admin", "user:rev3", "Reviewer", "A"))
	e.mustOwner(grant("admin", "user:rev3", "BU Admin", "A"))
	e.mustOwner(grant("admin", "user:rootrev", "Reviewer", "ENTERPRISE"))
	e.mustOwner(grant("rev3", "user:zed", "Executive Viewer", "A1")) // rev3 granted zed's access
	e.mustOwner(grant("admin", "user:bob", "Executive Viewer", "B"))
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Ops'), ('Eng')")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT " + grpID("Ops") + ", id FROM iam.app_user WHERE email IN ('carol@example.test', 'dave@example.test')")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT " + grpID("Eng") + ", id FROM iam.app_user WHERE email = 'erin@example.test'")
	e.mustOwner(grant("admin", "group:Ops", "Executive Viewer", "A"))
	e.mustOwner(`SELECT iam.breakglass_install_enable('[{"email": "bg1@example.test", "name": "Break Glass"}]', ARRAY['\x` + strings.Repeat("ef", 32) + `'::bytea], 'DR policy')`)
	e.drain()

	admin := be.login(t, "admin")
	buA := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	if r := be.do(t, "POST", "/api/v1/group-mappings", admin, map[string]any{"group_id": e.adminQuery("SELECT id FROM iam.grp WHERE display_name = 'Eng'"),
		"role_id": e.adminQuery("SELECT id FROM iam.role WHERE name = 'Executive Viewer'"), "bu_id": buA, "reason": "eng"}, be.hdrs(admin)); r.code != http.StatusCreated {
		t.Fatalf("mapping: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/service-accounts", admin, map[string]any{"name": "Reporter", "bu_id": buA, "scopes": []string{"bu.view"},
		"auth_method": "client_credentials", "reason": "reporting"}, be.hdrs(admin)); r.code != http.StatusCreated {
		t.Fatalf("service account: %d %s", r.code, r.raw)
	}
	e.drain()

	type item = map[string]any
	open := func(cookie string, body map[string]any) (string, []item) {
		t.Helper()
		r := be.do(t, "POST", "/api/v1/access-reviews", cookie, body, be.hdrs(cookie))
		if r.code != http.StatusCreated {
			t.Fatalf("open: %d %s", r.code, r.raw)
		}
		var items []item
		for _, x := range r.body["items"].([]any) {
			items = append(items, x.(item))
		}
		return r.body["campaign"].(map[string]any)["id"].(string), items
	}
	due := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	id, items := open(admin, map[string]any{"name": "Q4 review of A", "bu_id": buA, "due_at": due, "reason": "quarterly"})
	byWho := map[string]item{}
	var kinds []string
	for _, x := range items {
		s := x["snapshot"].(map[string]any)
		key := strings.TrimSuffix(s["principal"].(string), "@example.test") + "/" + s["role"].(string)
		byWho[key] = x
		kinds = append(kinds, x["kind"].(string)+":"+key)
	}
	sort.Strings(kinds)
	got := strings.Join(kinds, " ")
	for _, want := range []string{"user:ann/Risk Analyst", "group:Ops/Executive Viewer", "mapped:Eng/Executive Viewer", "user:rev/Reviewer",
		"service_account:", "user:zed/Executive Viewer"} {
		if !strings.Contains(got, want) {
			t.Fatalf("items %s lack %s", got, want)
		}
	}
	if strings.Contains(got, "bob") || strings.Contains(got, "erin/") {
		t.Fatalf("items outside the subtree, or mapped assignments listed one by one: %s", got)
	}
	if m := byWho["Ops/Executive Viewer"]["snapshot"].(map[string]any)["members"]; len(m.([]any)) != 2 {
		t.Fatalf("group members: %v", m)
	}
	decide := func(cookie, itemID, decision, comment string) gwResp {
		return be.do(t, "POST", "/api/v1/access-reviews/"+id+"/items/"+itemID+"/decision", cookie, map[string]any{"decision": decision, "comment": comment}, be.hdrs(cookie))
	}
	rev, rev2, rev3 := be.login(t, "rev"), be.login(t, "rev2"), be.login(t, "rev3")
	scopeHas := func(user, typ, bu string) bool {
		s := e.scopeOf(user)
		if s == nil {
			return false
		}
		return slices.Contains(s.Read[typ], bu) // scopeOf gives BU codes
	}

	// Certify; revoke needs a comment and applies at once (the drain).
	if r := decide(rev, byWho["ann/Risk Analyst"]["id"].(string), "certify", ""); r.code != 200 || r.body["outcome"] != "kept" {
		t.Fatalf("certify: %d %s", r.code, r.raw)
	}
	ops := byWho["Ops/Executive Viewer"]["id"].(string)
	if r := decide(rev, ops, "revoke", ""); r.code != http.StatusBadRequest {
		t.Fatalf("revoke without a comment: %d %s", r.code, r.raw)
	}
	if !scopeHas("carol", "register", "A") {
		t.Fatal("carol has no access to revoke")
	}
	start := time.Now()
	if r := decide(rev, ops, "revoke", "Ops no longer needs register access"); r.code != 200 || r.body["outcome"] != "revoked" {
		t.Fatalf("revoke the group: %d %s", r.code, r.raw)
	}
	e.drain()
	if scopeHas("carol", "register", "A") || scopeHas("dave", "register", "A") || time.Since(start) > 60*time.Second {
		t.Fatal("the group's access outlived its revocation")
	}
	if r := decide(rev2, ops, "certify", ""); r.code != http.StatusConflict {
		t.Fatalf("deciding twice: %d %s", r.code, r.raw)
	}
	// Mapped: the mapping goes; the decision says to fix the IdP group too.
	if r := decide(rev, byWho["Eng/Executive Viewer"]["id"].(string), "revoke", "Eng mapping obsolete; remove at the IdP too"); r.code != 200 || r.body["outcome"] != "mapping_removed" {
		t.Fatalf("revoke the mapping: %d %s", r.code, r.raw)
	}
	e.drain()
	if scopeHas("erin", "register", "A") || e.adminQuery("SELECT count(*) FROM iam.group_role_mapping WHERE removed_at IS NULL") != "0" {
		t.Fatal("the mapping or erin's access survived")
	}
	// A service account is disabled.
	var saItem string
	for _, x := range items {
		if x["kind"] == "service_account" {
			saItem = x["id"].(string)
		}
	}
	if r := decide(rev2, saItem, "revoke", "unused integration"); r.code != 200 || r.body["outcome"] != "account_disabled" ||
		e.adminQuery("SELECT status FROM iam.app_user WHERE display_name = 'Reporter'") != "disabled" {
		t.Fatalf("revoke the service account: %d %s", r.code, r.raw)
	}
	// Nobody reviews their own access or access they granted.
	if r := decide(rev, byWho["rev/Reviewer"]["id"].(string), "certify", ""); r.code != http.StatusForbidden {
		t.Fatalf("self-review: %d %s", r.code, r.raw)
	}
	if r := decide(rev2, byWho["rev/Reviewer"]["id"].(string), "certify", ""); r.code != 200 {
		t.Fatalf("a peer's review: %d %s", r.code, r.raw)
	}
	if r := decide(rev3, byWho["zed/Executive Viewer"]["id"].(string), "revoke", "x"); r.code != http.StatusForbidden {
		t.Fatalf("reviewing access one granted: %d %s", r.code, r.raw)
	}
	// rev (no access.assign) revoked zed's assignment through the review.
	if r := decide(rev, byWho["zed/Executive Viewer"]["id"].(string), "revoke", "left the team"); r.code != 200 || r.body["outcome"] != "revoked" {
		t.Fatalf("a reviewer without access.assign revoking: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT revoked_by = " + uid("rev") + " FROM iam.assignment WHERE principal_id = " + uid("zed")); got != "t" {
		t.Fatalf("zed's revocation names its reviewer: %s", got)
	}
	// The audit trail.
	if got := e.adminQuery(`SELECT string_agg(payload->'attributes'->>'decision' || ':' || (payload->>'severity'), ',' ORDER BY id)
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'access_review.decided'`); got != "certify:info,revoke:high,revoke:high,revoke:high,certify:info,revoke:high" { // ann, Ops, Eng, the account, rev, zed
		t.Fatalf("decisions audited: %s", got)
	}
	// Managing campaigns is not deciding items: the admin holds
	// access_review.manage, not access_review.decide.
	if r := decide(admin, byWho["rev/Reviewer"]["id"].(string), "certify", ""); r.code != http.StatusNotFound {
		t.Fatalf("a manager deciding: %d %s", r.code, r.raw)
	}
	// Without the review permissions the routes do not exist.
	bob := be.login(t, "bob")
	if r := be.do(t, "GET", "/api/v1/access-reviews", bob, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("bob: %d", r.code)
	}
	// A reviewer sees the campaign and their open items.
	if r := be.do(t, "GET", "/api/v1/access-reviews", rev2, nil, nil); r.code != 200 || !strings.Contains(r.raw, id) {
		t.Fatalf("reviewer's list: %d %s", r.code, r.raw)
	}

	// Named reviewers narrow who decides.
	id2, items2 := open(admin, map[string]any{"name": "named", "bu_id": buA, "due_at": due, "reason": "x", "reviewers": []string{e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rev2@example.test'")}})
	if r := be.do(t, "POST", "/api/v1/access-reviews/"+id2+"/items/"+items2[0]["id"].(string)+"/decision", rev, map[string]any{"decision": "certify"}, be.hdrs(rev)); r.code != http.StatusForbidden {
		t.Fatalf("a reviewer not named: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/access-reviews", admin, map[string]any{"name": "x", "bu_id": buA, "due_at": due, "reason": "x",
		"reviewers": []string{e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'bob@example.test'")}}, be.hdrs(admin)); r.code != http.StatusBadRequest {
		t.Fatalf("naming a reviewer without access_review.decide: %d", r.code)
	}

	// Break-glass accounts are certified, never revoked here.
	idRoot, itemsRoot := open(admin, map[string]any{"name": "admins", "bu_id": e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL"), "due_at": due,
		"reason": "x", "role_ids": []string{e.adminQuery("SELECT id FROM iam.role WHERE name = 'Platform Admin'")}})
	rootrev := be.login(t, "rootrev")
	seenBG := false
	for _, x := range itemsRoot {
		if x["kind"] == "breakglass" {
			seenBG = true
			path := "/api/v1/access-reviews/" + idRoot + "/items/" + x["id"].(string) + "/decision"
			if r := be.do(t, "POST", path, rootrev, map[string]any{"decision": "revoke", "comment": "x"}, be.hdrs(rootrev)); r.code != http.StatusConflict {
				t.Fatalf("revoking break-glass: %d %s", r.code, r.raw)
			}
			if r := be.do(t, "POST", path, rootrev, map[string]any{"decision": "certify"}, be.hdrs(rootrev)); r.code != 200 {
				t.Fatalf("certifying break-glass: %d %s", r.code, r.raw)
			}
		}
	}
	if !seenBG {
		t.Fatal("no break-glass item")
	}

	// Policy at the due date: revoke ends undecided access as the system;
	// keep marks it unreviewed.
	idRevoke, itemsRevoke := open(admin, map[string]any{"name": "A1 strict", "bu_id": e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A1'"), "due_at": due,
		"on_expiry": "revoke", "reason": "x"})
	e.mustOwner("UPDATE iam.access_review_campaign SET created_at = now() - interval '3 days', due_at = now() - interval '1 minute' WHERE id IN ('" + idRevoke + "', '" + id2 + "')")
	// Past its due date, before the sweep runs, a campaign takes no decisions.
	if r := be.do(t, "POST", "/api/v1/access-reviews/"+idRevoke+"/items/"+itemsRevoke[0]["id"].(string)+"/decision", rev,
		map[string]any{"decision": "certify"}, be.hdrs(rev)); r.code != http.StatusConflict || !strings.Contains(r.raw, "the campaign is closed") {
		t.Fatalf("deciding past the due date: %d %s", r.code, r.raw)
	}
	if got, err := e.as("app_rw", "SELECT iam.access_review_sweep()"); err != nil || got != "2" {
		t.Fatalf("sweep closed %s %v", got, err)
	}
	e.drain()
	if scopeHas("ann", "register", "A1") {
		t.Fatal("ann's undecided access survived the revoke policy")
	}
	if got := e.adminQuery("SELECT revoked_by IS NULL FROM iam.assignment WHERE principal_id = " + uid("ann")); got != "t" {
		t.Fatalf("the policy revocation: %s", got)
	}
	if got := e.adminQuery("SELECT string_agg(DISTINCT decision, ',') FROM iam.access_review_item WHERE campaign_id = '" + id2 + "'"); got != "expired_unreviewed" {
		t.Fatalf("keep policy: %s", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'access_review.campaign_closed' AND payload->>'actor' = 'system:reviews'"); got != "2" {
		t.Fatalf("closes audited: %s", got)
	}
	// A closed campaign takes no decisions; a manager closes one early.
	if r := be.do(t, "POST", "/api/v1/access-reviews/"+id2+"/items/"+items2[0]["id"].(string)+"/decision", rev2, map[string]any{"decision": "certify"}, be.hdrs(rev2)); r.code != http.StatusConflict {
		t.Fatalf("deciding in a closed campaign: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/access-reviews/"+id+"/close", admin, map[string]any{"reason": "done"}, be.hdrs(admin)); r.code != 200 ||
		r.body["campaign"].(map[string]any)["state"] != "closed" {
		t.Fatalf("close: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/access-reviews/"+id+"/close", rev, map[string]any{"reason": "x"}, be.hdrs(rev)); r.code != http.StatusNotFound && r.code != http.StatusConflict {
		t.Fatalf("a reviewer closing: %d", r.code)
	}
	for _, tbl := range []string{"iam.access_review_campaign", "iam.access_review_item"} {
		e.mustFail("app_rw", "SELECT * FROM "+tbl, "permission denied")
	}
}

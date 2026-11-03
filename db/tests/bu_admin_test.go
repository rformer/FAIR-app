package tests

import (
	"net/http"
	"strings"
	"testing"
)

// F-001 T-30b (AC-15, AC-16, AC-17; design §6 /bus): BU administration over
// the API: create, rename, move (shown before it applies; leaving a
// restricted subtree by approval), archive, and the maximum depth.

type buAdminEnv struct {
	*sodEnv
	inner string // bu.manage at R (inside the restricted subtree) and at A
}

func buAdminFixture(t *testing.T) *buAdminEnv {
	t.Helper()
	se := sodFixture(t) // admin, admin2: Platform Admins at the root
	e := se.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'ENTERPRISE'")
	e.addBU("R1", "R")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R2', 'R2', id, true FROM iam.bu WHERE code = 'R'")
	for name, perms := range map[string]string{"Analysis Viewer": "'analysis.view', 'bu.view'", "BU Manager": "'bu.manage', 'bu.view'", "BU Viewer": "'bu.view'"} {
		e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('` + name + `') RETURNING id)
			INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY[` + perms + `], 'test' FROM r`)
	}
	e.mustOwner(grant("admin", "user:other", "Analysis Viewer", "A"))
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('inner@example.test', 'Inner')")
	e.mustOwner(grant("admin", "user:inner", "BU Manager", "R"))
	e.mustOwner(grant("admin", "user:inner", "BU Manager", "A"))
	e.drain()
	return &buAdminEnv{sodEnv: se, inner: se.login(t, "inner")}
}

func (be *buAdminEnv) id(code string) string {
	return be.e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + code + "'")
}

func (be *buAdminEnv) parent(code string) string {
	return be.e.adminQuery("SELECT p.code FROM iam.bu b JOIN iam.bu p ON p.id = b.parent_id WHERE b.code = '" + code + "'")
}

// move previews, then confirms; returns the confirming response.
func (be *buAdminEnv) move(t *testing.T, cookie, code, parent, reason string) gwResp {
	t.Helper()
	path := "/api/v1/bus/" + be.id(code) + "/move"
	body := map[string]any{"parent_id": be.id(parent), "reason": reason}
	pv := be.call(t, cookie, "POST", path, body)
	if pv.code != http.StatusConflict || pv.body["error"] != "confirm_required" {
		t.Fatalf("move %s under %s without confirm: %d %s", code, parent, pv.code, pv.raw)
	}
	body["confirm"] = pv.body["preview"].(map[string]any)["confirm"]
	return be.call(t, cookie, "POST", path, body)
}

func (be *buAdminEnv) audit(typ string) string {
	return be.e.adminQuery(`SELECT coalesce(string_agg((payload->>'severity') || ':' || coalesce(payload->>'reason', '') || ':' ||
		coalesce(payload->'attributes'->>'old_parent', payload->'attributes'->>'from', payload->'attributes'->>'parent', ''), '|' ORDER BY id), '')
		FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = '` + typ + `' AND payload->>'severity' = 'high'`)
}

func TestBUAdministrationCreateRenameArchive(t *testing.T) {
	be := buAdminFixture(t)
	e := be.e
	other := be.login(t, "other")

	// Create: bu.manage at the parent; restricted by default (AC-61).
	r := be.call(t, be.admin, "POST", "/api/v1/bus", map[string]any{"parent_id": be.id("A"), "code": "A2", "name": "Team A2", "reason": "new team"})
	if r.code != http.StatusCreated || r.body["code"] != "A2" || r.body["restricted"] != true || r.body["depth"] != float64(2) {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if got := be.audit("bu.created"); got != "high:new team:A" {
		t.Fatalf("created audit %q", got)
	}
	for name, c := range map[string]struct {
		cookie string
		body   map[string]any
		code   int
	}{
		"unrestricted by default refused":      {be.admin, map[string]any{"parent_id": be.id("A"), "code": "A3", "name": "x", "restricted": false, "reason": "x"}, 409},
		"duplicate code":                       {be.admin, map[string]any{"parent_id": be.id("B"), "code": "A2", "name": "x", "reason": "x"}, 409},
		"invalid code":                         {be.admin, map[string]any{"parent_id": be.id("A"), "code": "a b", "name": "x", "reason": "x"}, 400},
		"no reason":                            {be.admin, map[string]any{"parent_id": be.id("A"), "code": "A4", "name": "x", "reason": ""}, 400},
		"unknown parent":                       {be.admin, map[string]any{"parent_id": "00000000-0000-4000-8000-000000000000", "code": "A5", "name": "x", "reason": "x"}, 400},
		"without bu.manage":                    {other, map[string]any{"parent_id": be.id("A"), "code": "A6", "name": "x", "reason": "x"}, 403},
		"inside a restricted BU from the root": {be.admin, map[string]any{"parent_id": be.id("R"), "code": "R9", "name": "x", "reason": "x"}, 403},
	} {
		if r := be.call(t, c.cookie, "POST", "/api/v1/bus", c.body); r.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}
	if r := be.call(t, be.inner, "POST", "/api/v1/bus", map[string]any{"parent_id": be.id("R"), "code": "R3", "name": "Inner team", "reason": "x"}); r.code != http.StatusCreated {
		t.Fatalf("create inside R by its manager: %d %s", r.code, r.raw)
	}

	// Rename: the name only, audited with the old name.
	a2 := be.id("A2")
	if r := be.call(t, be.admin, "PATCH", "/api/v1/bus/"+a2, map[string]any{"name": "Team A-Two", "reason": "rebrand"}); r.code != http.StatusNoContent {
		t.Fatalf("rename: %d %s", r.code, r.raw)
	}
	if got := be.audit("bu.renamed"); got != "high:rebrand:Team A2" {
		t.Fatalf("renamed audit %q", got)
	}
	for name, c := range map[string]struct {
		cookie, id string
		body       map[string]any
		code       int
	}{
		"same name":          {be.admin, a2, map[string]any{"name": "Team A-Two", "reason": "x"}, 409},
		"no name":            {be.admin, a2, map[string]any{"reason": "x"}, 400},
		"code change":        {be.admin, a2, map[string]any{"name": "x", "code": "Z", "reason": "x"}, 400},
		"without bu.manage":  {other, be.id("A1"), map[string]any{"name": "x", "reason": "x"}, 403},
		"restricted, unseen": {other, a2, map[string]any{"name": "x", "reason": "x"}, 404},
		"not visible":        {other, be.id("B"), map[string]any{"name": "x", "reason": "x"}, 404},
		"unknown":            {be.admin, "00000000-0000-4000-8000-000000000000", map[string]any{"name": "x", "reason": "x"}, 404},
	} {
		if r := be.call(t, c.cookie, "PATCH", "/api/v1/bus/"+c.id, c.body); r.code != c.code {
			t.Errorf("rename %s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}

	// Archive: not the root, not with children; never deleted.
	for name, c := range map[string]struct {
		id   string
		code int
	}{
		"the root":      {be.id("ENTERPRISE"), 409},
		"with children": {be.id("A"), 409},
	} {
		if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+c.id+"/archive", map[string]any{"reason": "x"}); r.code != c.code || !strings.Contains(r.raw, map[string]string{"the root": "root", "with children": "A1, A2"}[name]) {
			t.Errorf("archive %s: %d %s", name, r.code, r.raw)
		}
	}
	if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+a2+"/archive", map[string]any{"reason": ""}); r.code != http.StatusBadRequest {
		t.Fatalf("archive without a reason: %d", r.code)
	}
	if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+a2+"/archive", map[string]any{"reason": "team dissolved"}); r.code != http.StatusNoContent {
		t.Fatalf("archive: %d %s", r.code, r.raw)
	}
	if got := be.audit("bu.archived"); got != "high:team dissolved:" {
		t.Fatalf("archived audit %q", got)
	}
	if e.adminQuery("SELECT archived_at IS NOT NULL FROM iam.bu WHERE id = '"+a2+"'") != "t" {
		t.Fatal("not archived")
	}
	if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+a2+"/archive", map[string]any{"reason": "again"}); r.code != http.StatusNotFound {
		t.Fatalf("archive twice: %d", r.code)
	}
	if r := be.call(t, be.admin, "POST", "/api/v1/bus", map[string]any{"parent_id": a2, "code": "A2x", "name": "x", "reason": "x"}); r.code != http.StatusConflict {
		t.Fatalf("create under an archived BU: %d %s", r.code, r.raw)
	}
	// T-31's guard still applies (active records), through the API.
	e.mustOwner(`CREATE TABLE iam.bu_admin_guarded (id serial PRIMARY KEY, bu_id uuid NOT NULL);
		SELECT authz.apply_bu_rls('iam.bu_admin_guarded', 'register');`)
	e.adminQuery("INSERT INTO iam.bu_admin_guarded (bu_id) VALUES ('" + be.id("A1") + "')") // the superuser, past RLS
	if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+be.id("A1")+"/archive", map[string]any{"reason": "x"}); r.code != http.StatusConflict || !strings.Contains(r.raw, "active records") {
		t.Fatalf("archive with active records: %d %s", r.code, r.raw)
	}

	// Without bu.view anywhere, the routes do not exist.
	user := be.login(t, "user")
	for _, c := range [][2]string{{"POST", "/api/v1/bus"}, {"PATCH", "/api/v1/bus/" + be.id("A")}, {"POST", "/api/v1/bus/" + be.id("A") + "/move"},
		{"POST", "/api/v1/bus/" + be.id("A") + "/archive"}, {"GET", "/api/v1/bus/max-depth"}, {"PUT", "/api/v1/bus/max-depth"}} {
		var body any
		if c[0] != "GET" {
			body = map[string]any{"reason": "x"}
		}
		if r := be.call(t, user, c[0], c[1], body); r.code != http.StatusNotFound {
			t.Errorf("%s %s without bu.view: %d", c[0], c[1], r.code)
		}
	}
}

func TestBUAdministrationMove(t *testing.T) {
	be := buAdminFixture(t)
	e := be.e
	a1 := be.id("A1")
	inScope := func() bool {
		return e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = "+uid("other")+" AND read_bus::text LIKE '%"+a1+"%'") == "1"
	}
	if !inScope() {
		t.Fatal("setup: A1 is not in other's scope")
	}

	// A dry run shows what the move changes, and changes nothing.
	path := "/api/v1/bus/" + a1 + "/move"
	pv := be.call(t, be.admin, "POST", path+"?dry_run=true", map[string]any{"parent_id": be.id("B"), "reason": "reorg"})
	p, _ := pv.body["preview"].(map[string]any)
	if pv.code != 200 || pv.body["status"] != "preview" || p["from_parent"] != "A" || p["to_parent"] != "B" ||
		strs(p["reach_lost"])[0] != "A" || strs(p["reach_gained"])[0] != "B" || p["assignments_losing"] != float64(2) ||
		p["needs_approval"] != false || len(p["confirm"].(string)) != 64 {
		t.Fatalf("dry run: %d %s", pv.code, pv.raw)
	}
	if be.parent("A1") != "A" {
		t.Fatal("a dry run moved the BU")
	}
	// A stale fingerprint asks again.
	e.mustOwner(grant("admin", "user:other", "Analysis Viewer", "B"))
	if r := be.call(t, be.admin, "POST", path, map[string]any{"parent_id": be.id("B"), "reason": "reorg", "confirm": p["confirm"]}); r.code != http.StatusConflict ||
		r.body["error"] != "confirm_required" {
		t.Fatalf("a stale confirm: %d %s", r.code, r.raw)
	}
	e.mustOwner("UPDATE iam.assignment SET revoked_at = now(), revoked_by = " + uid("admin") + " WHERE bu_id = '" + be.id("B") + "'")
	e.drain()

	// AC-17: the move, the closure, the scopes, and the audit of both parents.
	if r := be.move(t, be.admin, "A1", "B", "reorg"); r.code != 200 || r.body["status"] != "moved" {
		t.Fatalf("move: %d %s", r.code, r.raw)
	}
	if be.parent("A1") != "B" || e.adminQuery("SELECT count(*) FROM iam.bu_closure WHERE descendant_id = '"+a1+"' AND ancestor_id = '"+be.id("A")+"'") != "0" {
		t.Fatal("the tree or closure did not follow")
	}
	e.drain()
	if inScope() {
		t.Fatal("the assignment at A still reaches A1 after the move")
	}
	if got := be.audit("bu.moved"); got != "high:reorg:A" {
		t.Fatalf("moved audit %q", got)
	}
	if got := e.adminQuery(`SELECT payload->'attributes'->>'new_parent' FROM iam.event_outbox WHERE payload->>'type' = 'bu.moved' AND payload->>'severity' = 'high'`); got != "B" {
		t.Fatalf("moved audit new parent %q", got)
	}

	// Refusals. inner sees B (bu.view) but does not manage it.
	e.mustOwner(grant("admin", "user:inner", "BU Viewer", "B"))
	e.drain()
	for name, c := range map[string]struct {
		cookie, bu, parent string
		code               int
	}{
		"the root":                           {be.admin, "ENTERPRISE", "A", 409},
		"same parent":                        {be.admin, "A1", "B", 409},
		"into its own subtree":               {be.admin, "B", "A1", 409},
		"no authority at the current parent": {be.inner, "A1", "A", 403},
		"no authority at the new parent":     {be.inner, "R1", "B", 403},
		"a BU the caller cannot see":         {be.login(t, "other"), "A1", "A", 404},
	} {
		r := be.call(t, c.cookie, "POST", "/api/v1/bus/"+be.id(c.bu)+"/move?dry_run=true", map[string]any{"parent_id": be.id(c.parent), "reason": "x"})
		if r.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}

	// Into a restricted subtree: shown, confirmed, applied (no approval).
	r := be.call(t, be.inner, "POST", "/api/v1/bus/"+be.id("A1")+"/move?dry_run=true", map[string]any{"parent_id": be.id("R"), "reason": "x"})
	if r.code != http.StatusForbidden { // inner does not manage B, A1's parent now (sees it)
		t.Fatalf("inner moving out of B: %d %s", r.code, r.raw)
	}
	e.mustOwner(grant("admin", "user:inner", "BU Manager", "B"))
	e.drain()
	pin := be.call(t, be.inner, "POST", "/api/v1/bus/"+be.id("A1")+"/move?dry_run=true", map[string]any{"parent_id": be.id("R"), "reason": "x"})
	if pp := pin.body["preview"].(map[string]any); strs(pp["restricted_entered"])[0] != "R" || pp["needs_approval"] != false {
		t.Fatalf("into R preview: %s", pin.raw)
	}
	if r := be.move(t, be.inner, "A1", "R", "join the deal team"); r.code != 200 {
		t.Fatalf("into R: %d %s", r.code, r.raw)
	}

	// Out of a restricted subtree: a second administrator's approval.
	path = "/api/v1/bus/" + be.id("R1") + "/move"
	if r := be.call(t, be.admin, "POST", path+"?dry_run=true", map[string]any{"parent_id": be.id("A"), "reason": "x"}); r.code != http.StatusNotFound {
		t.Fatalf("the root's admin moving R1 (inside R, unseen) out: %d %s", r.code, r.raw)
	}
	out := be.move(t, be.inner, "R1", "A", "deal closed")
	approval, _ := out.body["approval_id"].(string)
	if op, _ := out.body["preview"].(map[string]any); out.code != http.StatusAccepted || approval == "" || op["needs_approval"] != true ||
		strs(op["restricted_left"])[0] != "R" || be.parent("R1") != "R" {
		t.Fatalf("out of R: %d %s", out.code, out.raw)
	}
	if a := be.call(t, be.inner, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": approval}); a.code != http.StatusConflict {
		t.Fatalf("apply before approval: %d %s", a.code, a.raw)
	}
	if d := be.call(t, be.inner, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "x"}); d.code != http.StatusForbidden {
		t.Fatalf("approval without bu.restrict at R's parent: %d", d.code)
	}
	if d := be.call(t, be.admin2, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "confirmed"}); d.code != 200 {
		t.Fatalf("approve: %d %s", d.code, d.raw)
	}
	if a := be.call(t, be.inner, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": approval}); a.code != 200 || a.body["result"] != "moved" {
		t.Fatalf("apply: %d %s", a.code, a.raw)
	}
	if be.parent("R1") != "A" {
		t.Fatal("R1 did not move")
	}
	if got := e.adminQuery(`SELECT (payload->'attributes'->>'approved_by') = (SELECT id::text FROM iam.app_user WHERE email = 'admin2@example.test')
		FROM iam.event_outbox WHERE payload->>'type' = 'bu.moved' AND payload->'attributes'->>'new_parent' = 'A' AND payload->>'severity' = 'high'`); got != "t" {
		t.Fatalf("the approved move's audit does not name the approver: %q", got)
	}

	// An approved move whose preview changed meanwhile is refused.
	out = be.move(t, be.inner, "A1", "A", "back again")
	approval, _ = out.body["approval_id"].(string)
	if out.code != http.StatusAccepted {
		t.Fatalf("A1 out of R: %d %s", out.code, out.raw)
	}
	be.call(t, be.admin2, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "ok"})
	e.mustOwner(grant("admin", "user:other", "Analysis Viewer", "R"))
	if a := be.call(t, be.inner, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": approval}); a.code != http.StatusConflict ||
		!strings.Contains(a.raw, "changed") || be.parent("A1") != "R" {
		t.Fatalf("a stale approved move: %d %s", a.code, a.raw)
	}

	// A restricted BU keeps its own wall: leaving R needs no approval.
	if r := be.move(t, be.inner, "R2", "A", "spin out"); r.code != 200 || r.body["preview"].(map[string]any)["needs_approval"] != false {
		t.Fatalf("restricted R2 out of R: %d %s", r.code, r.raw)
	}
}

func TestBUAdministrationMaxDepth(t *testing.T) {
	be := buAdminFixture(t) // deepest: A1 and R1 at depth 2
	e := be.e
	g := be.do(t, "GET", "/api/v1/bus/max-depth", be.admin, nil, nil)
	if g.code != 200 || g.body["max_depth"] != float64(6) || g.body["deepest"] != float64(2) {
		t.Fatalf("max depth: %d %s", g.code, g.raw)
	}
	for name, c := range map[string]struct {
		cookie string
		body   map[string]any
		code   int
	}{
		"below the deepest BU": {be.admin, map[string]any{"max_depth": 1, "reason": "x"}, 409},
		"zero":                 {be.admin, map[string]any{"max_depth": 0, "reason": "x"}, 400},
		"too deep":             {be.admin, map[string]any{"max_depth": 33, "reason": "x"}, 400},
		"unchanged":            {be.admin, map[string]any{"max_depth": 6, "reason": "x"}, 409},
		"no reason":            {be.admin, map[string]any{"max_depth": 3, "reason": " "}, 400},
		"not at the root":      {be.inner, map[string]any{"max_depth": 3, "reason": "x"}, 403},
	} {
		if r := be.call(t, c.cookie, "PUT", "/api/v1/bus/max-depth", c.body); r.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}
	if r := be.call(t, be.admin, "PUT", "/api/v1/bus/max-depth", map[string]any{"max_depth": 2, "reason": "flatter tree"}); r.code != 200 {
		t.Fatalf("set: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery(`SELECT payload->>'reason' || ':' || (payload->'attributes'->>'from') || '>' || (payload->'attributes'->>'to')
		FROM iam.event_outbox WHERE payload->>'type' = 'bu.max_depth_changed'`); got != "flatter tree:6>2" {
		t.Fatalf("audit %q", got)
	}
	// AC-15 at depth 2: no BU below A1; no move that would go deeper.
	if r := be.call(t, be.admin, "POST", "/api/v1/bus", map[string]any{"parent_id": be.id("A1"), "code": "A1x", "name": "x", "reason": "x"}); r.code != http.StatusConflict ||
		!strings.Contains(r.raw, "maximum") {
		t.Fatalf("create beyond the maximum: %d %s", r.code, r.raw)
	}
	if r := be.call(t, be.admin, "POST", "/api/v1/bus/"+be.id("A")+"/move?dry_run=true", map[string]any{"parent_id": be.id("B"), "reason": "x"}); r.code != http.StatusConflict ||
		!strings.Contains(r.raw, "maximum") {
		t.Fatalf("move beyond the maximum: %d %s", r.code, r.raw)
	}
}

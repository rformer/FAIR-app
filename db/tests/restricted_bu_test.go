package tests

import (
	"net/http"
	"sort"
	"strings"
	"testing"
)

// F-001 T-30 (AC-26, AC-59 to AC-64): restricted BU administration, and
// roll-up leakage for every mode.

func TestRestrictedBUAdministration(t *testing.T) {
	se := sodFixture(t) // admin and admin2: Platform Admins at the root
	e := se.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("A1a", "A1")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Analysis Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['analysis.view', 'bu.view'], 'test' FROM r`)
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Restrictor') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['bu.restrict', 'bu.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:other", "Analysis Viewer", "A"))
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('inner@example.test', 'Inner')")
	e.mustOwner(grant("admin", "user:inner", "Restrictor", "A1"))
	e.drain()
	a1 := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A1'")
	reads := func() string {
		return e.adminQuery("SELECT iam.user_has_permission(" + uid("other") + ", 'analysis.view', '" + a1 + "')")
	}
	if reads() != "t" {
		t.Fatal("setup: A's assignment does not reach A1")
	}

	// AC-59, AC-60, AC-63: restricting takes effect at once, audited high.
	if r := se.call(t, se.admin, "POST", "/api/v1/bus/"+a1+"/restriction", map[string]any{"restricted": true, "reason": "M&A team"}); r.code != 200 {
		t.Fatalf("restrict: %d %s", r.code, r.raw)
	}
	if reads() != "f" {
		t.Fatal("an ancestor's assignment still reaches the restricted BU (AC-60)")
	}
	if got := e.adminQuery("SELECT payload->>'severity' || ':' || (payload->>'reason') FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'bu.restricted'"); got != "high:M&A team" {
		t.Fatalf("restrict audit %q", got)
	}
	for name, c := range map[string]struct {
		cookie, bu string
		body       map[string]any
		code       int
	}{
		"already restricted": {se.admin, a1, map[string]any{"restricted": true, "reason": "x"}, 409},
		"the root":           {se.admin, e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'"), map[string]any{"restricted": true, "reason": "x"}, 409},
		"no reason":          {se.admin, a1, map[string]any{"restricted": false, "reason": " "}, 400},
	} {
		if r := se.call(t, c.cookie, "POST", "/api/v1/bus/"+c.bu+"/restriction", c.body); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	// Authority sits at the parent: someone holding bu.restrict only inside
	// A1 cannot loosen A1, but manages A1's children.
	inner := se.login(t, "inner")
	if r := se.call(t, inner, "POST", "/api/v1/bus/"+a1+"/restriction", map[string]any{"restricted": false, "reason": "let us out"}); r.code != http.StatusForbidden {
		t.Fatalf("un-restrict from inside: %d %s", r.code, r.raw)
	}
	if r := se.call(t, inner, "POST", "/api/v1/bus/"+e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A1a'")+"/restriction", map[string]any{"restricted": true, "reason": "inner team"}); r.code != 200 {
		t.Fatalf("restrict a child from its parent: %d %s", r.code, r.raw)
	}

	// Un-restricting: a request, a second administrator's approval, applied.
	r := se.call(t, se.admin, "POST", "/api/v1/bus/"+a1+"/restriction", map[string]any{"restricted": false, "reason": "deal closed"})
	approval, _ := r.body["approval_id"].(string)
	if r.code != http.StatusAccepted || approval == "" || reads() != "f" {
		t.Fatalf("un-restrict request: %d %s", r.code, r.raw)
	}
	if a := se.call(t, se.admin, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": approval}); a.code != http.StatusConflict {
		t.Fatalf("apply before approval: %d %s", a.code, a.raw)
	}
	if d := se.call(t, se.admin, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true}); d.code != http.StatusForbidden {
		t.Fatalf("self-approval: %d", d.code)
	}
	if d := se.call(t, se.admin2, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "confirmed"}); d.code != 200 {
		t.Fatalf("approve: %d %s", d.code, d.raw)
	}
	if a := se.call(t, se.admin, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": approval}); a.code != 200 || a.body["result"] != "unrestricted" {
		t.Fatalf("apply: %d %s", a.code, a.raw)
	}
	e.drain()
	if reads() != "t" {
		t.Fatal("un-restricting did not restore inheritance")
	}
	if got := e.adminQuery(`SELECT (payload->'attributes'->>'approved_by') = (SELECT id::text FROM iam.app_user WHERE email = 'admin2@example.test')
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'bu.unrestricted' AND payload->>'severity' = 'high'`); got != "t" {
		t.Fatal("the un-restriction's audit does not name the approver")
	}

	// Roll-up mode: tightening at once; loosening by approval, refused if
	// the mode moved meanwhile.
	se.call(t, se.admin, "POST", "/api/v1/bus/"+a1+"/restriction", map[string]any{"restricted": true, "reason": "again"})
	lr := se.call(t, se.admin, "PUT", "/api/v1/bus/"+a1+"/rollup-mode", map[string]any{"mode": "full", "reason": "board reporting"})
	loosen, _ := lr.body["approval_id"].(string)
	if lr.code != http.StatusAccepted {
		t.Fatalf("loosen request: %d %s", lr.code, lr.raw)
	}
	se.call(t, se.admin2, "POST", "/api/v1/approvals/"+loosen+"/decision", map[string]any{"approve": true})
	if a := se.call(t, se.admin, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": loosen}); a.code != 200 || a.body["result"] != "full" {
		t.Fatalf("apply loosening: %d %s", a.code, a.raw)
	}
	if t2 := se.call(t, se.admin, "PUT", "/api/v1/bus/"+a1+"/rollup-mode", map[string]any{"mode": "aggregate", "reason": "less detail"}); t2.code != 200 {
		t.Fatalf("tighten: %d %s", t2.code, t2.raw)
	}
	l2 := se.call(t, se.admin, "PUT", "/api/v1/bus/"+a1+"/rollup-mode", map[string]any{"mode": "full", "reason": "again"})
	se.call(t, se.admin2, "POST", "/api/v1/approvals/"+l2.body["approval_id"].(string)+"/decision", map[string]any{"approve": true})
	se.call(t, se.admin, "PUT", "/api/v1/bus/"+a1+"/rollup-mode", map[string]any{"mode": "excluded", "reason": "lockdown"})
	e.mustOwner("UPDATE iam.bu SET rollup_mode = 'full' WHERE id = '" + a1 + "'") // moved meanwhile
	if a := se.call(t, se.admin, "POST", "/api/v1/bus/apply", map[string]any{"approval_id": l2.body["approval_id"].(string)}); a.code != http.StatusConflict {
		t.Fatalf("a stale loosening: %d %s", a.code, a.raw)
	}
	if r := se.call(t, se.admin, "PUT", "/api/v1/bus/"+a1+"/rollup-mode", map[string]any{"mode": "everything", "reason": "x"}); r.code != 400 {
		t.Fatalf("unknown mode: %d", r.code)
	}

	// The tree: admins see and manage restricted BUs; a viewer outside sees
	// none of them (AC-64).
	tree := se.do(t, "GET", "/api/v1/bus", se.admin, nil, nil)
	list, ok := tree.body["bus"].([]any)
	if tree.code != 200 || !ok {
		t.Fatalf("GET /bus: %d %s", tree.code, tree.raw)
	}
	codes := map[string]bool{}
	for _, b := range list {
		m := b.(map[string]any)
		codes[m["code"].(string)] = m["manageable"].(bool)
	}
	// A1a sits inside the restricted A1: the root's admins neither see nor
	// manage it; its parent's holder (inner) does.
	if !codes["A1"] || len(codes) != 3 {
		t.Fatalf("admin tree: %v", codes)
	}
	if r := se.do(t, "GET", "/api/v1/bus", inner, nil, nil); !strings.Contains(r.raw, `"code":"A1a"`) || !strings.Contains(r.raw, `"manageable":true`) {
		t.Fatalf("inner tree: %s", r.raw)
	}
	viewer := se.do(t, "GET", "/api/v1/bus", se.login(t, "other"), nil, nil)
	if strings.Contains(viewer.raw, `"code":"A1"`) || !strings.Contains(viewer.raw, `"code":"A"`) {
		t.Fatalf("a viewer at A sees the restricted A1: %s", viewer.raw)
	}
	if r := se.do(t, "GET", "/api/v1/bus", se.login(t, "user"), nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without bu.view: %d", r.code)
	}
}

// AC-61: new BUs follow bu.new_restricted_default.
func TestNewBURestrictedDefault(t *testing.T) {
	e := setup(t)
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id) SELECT 'N1', 'N1', id FROM iam.bu WHERE code = 'ENTERPRISE'")
	if got := e.adminQuery("SELECT restricted FROM iam.bu WHERE code = 'N1'"); got != "t" {
		t.Fatalf("default without settings: %s", got)
	}
	postureAdmins(e)
	seedPosture(t, e)
	setInstance(e, "bu.new_restricted_default", "false")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id) SELECT 'N2', 'N2', id FROM iam.bu WHERE code = 'ENTERPRISE'")
	if got := e.adminQuery("SELECT restricted FROM iam.bu WHERE code = 'N2'"); got != "f" {
		t.Fatalf("default with the setting off: %s", got)
	}
	setInstance(e, "bu.new_restricted_default", "true")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id) SELECT 'N3', 'N3', id FROM iam.bu WHERE code = 'ENTERPRISE'")
	if got := e.adminQuery("SELECT restricted FROM iam.bu WHERE code = 'N3'"); got != "t" {
		t.Fatalf("default with the setting on: %s", got)
	}
}

// AC-26, AC-62: for every roll-up mode, what an ancestor's reader sees
// through RLS and through a roll-up definer function written as the
// pattern says, and what the coverage reports.
func TestRollupLeakage(t *testing.T) {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'A'")
	e.addBU("R1", "R")
	for _, u := range []string{"vic", "rita", "platform"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.addCtxKey(ctxKey1)
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Analysis Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['analysis.view'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:vic", "Analysis Viewer", "A"))  // an ancestor's reader
	e.mustOwner(grant("platform", "user:rita", "Analysis Viewer", "R")) // explicitly inside R

	// A BU-owned table and a roll-up function as features write them.
	e.mustOwner(`CREATE SCHEMA rollup_demo;
		CREATE TABLE rollup_demo.amounts (id serial PRIMARY KEY, bu_id uuid NOT NULL, amount numeric NOT NULL);
		SELECT authz.apply_bu_rls('rollup_demo.amounts', 'analysis');
		CREATE FUNCTION rollup_demo.total(root uuid) RETURNS numeric
		LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
		  SELECT coalesce(sum(a.amount), 0) FROM rollup_demo.amounts a
		  WHERE a.bu_id IN (SELECT c.bu_id FROM authz.rollup_coverage('analysis', root) c WHERE c.mode <> 'excluded');
		$f$;
		GRANT EXECUTE ON FUNCTION rollup_demo.total(uuid) TO app_rw;
		GRANT CREATE ON SCHEMA rollup_demo TO rollup_definer;
		ALTER FUNCTION rollup_demo.total(uuid) OWNER TO rollup_definer;
		REVOKE CREATE ON SCHEMA rollup_demo FROM rollup_definer;
		-- an ordinary fair_owner definer function that reads rows
		SET ROLE authz_definer;
		GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text), authz.scope_excludes(text, text), authz.scope_hides(text, text) TO fair_owner;
		SET ROLE fair_owner;
		CREATE FUNCTION rollup_demo.rows_sum() RETURNS numeric
		LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
		  SELECT coalesce(sum(amount), 0) FROM rollup_demo.amounts;
		$f$;
		GRANT EXECUTE ON FUNCTION rollup_demo.rows_sum() TO app_rw;
		GRANT USAGE ON SCHEMA rollup_demo TO app_rw;
		GRANT SELECT ON rollup_demo.amounts TO app_rw;`)
	e.admin(e.db, `INSERT INTO rollup_demo.amounts (bu_id, amount)
		SELECT id, CASE code WHEN 'A' THEN 1 WHEN 'A1' THEN 10 WHEN 'R' THEN 100 WHEN 'R1' THEN 1000 END FROM iam.bu WHERE code IN ('A', 'A1', 'R', 'R1')`)
	a := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")

	codes := map[string]string{}
	for _, l := range strings.Split(e.adminQuery("SELECT id::text || '=' || code FROM iam.bu"), "\n") {
		id, code, _ := strings.Cut(l, "=")
		codes[id] = code
	}
	look := func(user string) (rows, total, coverage string) {
		t.Helper()
		rows = e.mustAsUser("app_rw", user, "SELECT coalesce(sum(amount), 0) FROM rollup_demo.amounts")
		total = e.mustAsUser("app_rw", user, "SELECT rollup_demo.total('"+a+"')")
		var cov []string
		for _, l := range strings.Split(e.mustAsUser("app_rw", user, "SELECT bu_id::text || '=' || mode FROM authz.rollup_coverage('analysis', '"+a+"')"), "\n") {
			id, mode, _ := strings.Cut(l, "=")
			cov = append(cov, codes[id]+"="+mode)
		}
		sort.Strings(cov)
		return rows, total, strings.Join(cov, ",")
	}
	for _, c := range []struct {
		mode, rows, total, coverage string
	}{
		// excluded (the default): R and R1 contribute nothing, and the
		// roll-up says they are left out.
		{"excluded", "11", "11", "A1=full,A=full,R1=excluded,R=excluded"},
		// aggregate: totals include R and R1, rows never do.
		{"aggregate", "11", "1111", "A1=full,A=full,R1=aggregate,R=aggregate"},
		// full: rows and totals both.
		{"full", "1111", "1111", "A1=full,A=full,R1=full,R=full"},
	} {
		e.mustOwner("UPDATE iam.bu SET rollup_mode = '" + c.mode + "' WHERE code = 'R'")
		e.drain()
		rows, total, coverage := look("vic")
		if rows != c.rows || total != c.total || coverage != c.coverage {
			t.Errorf("%s: rows %s total %s coverage %s; want %s %s %s", c.mode, rows, total, coverage, c.rows, c.total, c.coverage)
		}
		// Other definer functions do not get the roll-up policy.
		if got := e.mustAsUser("app_rw", "vic", "SELECT rollup_demo.rows_sum()"); got != c.rows {
			t.Errorf("%s: a fair_owner definer function read %s", c.mode, got)
		}
		// An explicit grant inside R sees R's rows whatever the mode.
		if rows, _, _ := look("rita"); rows != "1100" {
			t.Errorf("%s: rita (assigned in R) reads %s", c.mode, rows)
		}
	}
	// Without a signed context nothing at all.
	if got, _ := e.as("app_rw", "SELECT rollup_demo.total('"+a+"')"); strings.TrimSpace(got) != "0" {
		t.Fatalf("no context: %q", got)
	}
}

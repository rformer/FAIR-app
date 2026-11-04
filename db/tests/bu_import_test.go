package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// F-001 T-31 (AC-18, AC-19): the archive guard, and BU import/export.

// AC-18: a BU with active records is not archived; archived BUs are
// read-only at once.
func TestBUArchiveGuard(t *testing.T) {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	e.addBU("B", "ENTERPRISE")
	for _, u := range []string{"wes", "platform"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.addCtxKey(ctxKey1)
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Register Editor') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['register.view', 'register.edit'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:wes", "Register Editor", "ENTERPRISE"))
	e.mustOwner(`CREATE TABLE iam.guard_docs (id serial PRIMARY KEY, bu_id uuid NOT NULL, archived_at timestamptz);
		SELECT authz.apply_bu_rls('iam.guard_docs', 'register', 'archived_at');
		CREATE TABLE iam.guard_plain (id serial PRIMARY KEY, bu_id uuid NOT NULL);
		SELECT authz.apply_bu_rls('iam.guard_plain', 'register');
		GRANT SELECT, INSERT, UPDATE ON iam.guard_docs, iam.guard_plain TO app_rw;
		GRANT USAGE ON SEQUENCE iam.guard_docs_id_seq, iam.guard_plain_id_seq TO app_rw;`)
	e.drain()
	a := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	e.mustAsUser("app_rw", "wes", "INSERT INTO iam.guard_docs (bu_id) VALUES ('"+a+"'); INSERT INTO iam.guard_plain (bu_id) VALUES ('"+a+"')")

	archive := "UPDATE iam.bu SET archived_at = now() WHERE code = 'A'"
	e.ownerFails(archive, "iam.guard_docs (1), iam.guard_plain (1)")
	// An inactive row no longer blocks; the plain table's row does until it
	// is reassigned.
	e.mustAsUser("app_rw", "wes", "UPDATE iam.guard_docs SET archived_at = now()")
	e.ownerFails(archive, "reassign them before archiving: iam.guard_plain (1)")
	e.mustAsUser("app_rw", "wes", "UPDATE iam.guard_plain SET bu_id = '"+e.adminQuery("SELECT id FROM iam.bu WHERE code = 'B'")+"'")
	e.mustOwner(archive)
	if got := e.adminQuery("SELECT archived_at IS NOT NULL FROM iam.bu WHERE code = 'A'"); got != "t" {
		t.Fatal("A was not archived")
	}

	// Read-only at once, before any scope recompute: rows stay readable,
	// nothing new is written into the archived BU, and nothing is moved in.
	if got := e.mustAsUser("app_rw", "wes", "SELECT count(*) FROM iam.guard_docs"); got != "1" {
		t.Fatalf("archived BU's rows readable: %s", got)
	}
	if out, err := e.asUser("app_rw", "wes", "INSERT INTO iam.guard_plain (bu_id) VALUES ('"+a+"')"); err == nil || !strings.Contains(out, "row-level security") {
		t.Fatalf("insert into an archived BU: %v %s", err, out)
	}
	if got := e.mustAsUser("app_rw", "wes", "WITH m AS (UPDATE iam.guard_docs SET archived_at = NULL RETURNING 1) SELECT count(*) FROM m"); got != "0" {
		t.Fatalf("updated a row in an archived BU: %s", got)
	}
	if out, err := e.asUser("app_rw", "wes", "UPDATE iam.guard_plain SET bu_id = '"+a+"'"); err == nil || !strings.Contains(out, "row-level security") {
		t.Fatalf("moved a row into an archived BU: %v %s", err, out)
	}

	// The count is the guard's alone; tables register a real inactive column.
	e.mustFail("app_rw", "SELECT * FROM iam.bu_active_records('"+a+"')", "permission denied")
	e.mustOwner("CREATE TABLE iam.guard_bad (id serial PRIMARY KEY, bu_id uuid NOT NULL, closed text)")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.guard_bad', 'register', 'closed')", "timestamp or date column")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.guard_bad', 'register', 'nope')", "timestamp or date column")
}

// AC-19: export and import of the BU tree, JSON and CSV.
func TestBUImportExport(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	e.addBU("A", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'Restricted', 'R', id, true FROM iam.bu WHERE code = 'A'")
	e.addBU("R1", "R")
	e.mustOwner("UPDATE iam.bu SET name = '=HYPERLINK(1)' WHERE code = 'A'")
	e.drain()

	// Export: what the caller manages; the restricted R as metadata, not R1.
	ex := se.do(t, "GET", "/api/v1/bus/export", se.admin, nil, nil)
	var doc struct {
		Format string           `json:"format"`
		BUs    []map[string]any `json:"bus"`
	}
	if ex.code != 200 || json.Unmarshal([]byte(ex.raw), &doc) != nil || doc.Format != "fair.bus.v1" {
		t.Fatalf("export: %d %s", ex.code, ex.raw)
	}
	var codes []string
	for _, b := range doc.BUs {
		codes = append(codes, b["code"].(string))
	}
	if strings.Join(codes, ",") != "ENTERPRISE,A,R" {
		t.Fatalf("exported %v", codes)
	}
	csv := se.do(t, "GET", "/api/v1/bus/export?format=csv", se.admin, nil, nil)
	if csv.code != 200 || !strings.HasPrefix(csv.raw, "code,parent_code,name,restricted,rollup_mode\n") ||
		!strings.Contains(csv.raw, "A,ENTERPRISE,'=HYPERLINK(1),false,excluded") || !strings.Contains(csv.raw, "R,A,Restricted,true,excluded") {
		t.Fatalf("csv export: %d %q", csv.code, csv.raw)
	}

	// Dry run: outcomes, nothing saved.
	body := map[string]any{"reason": "reorg", "document": map[string]any{"format": "fair.bus.v1", "bus": []map[string]any{
		{"code": "A", "parent_code": "ENTERPRISE", "name": "Americas"},
		{"code": "N", "parent_code": "A", "name": "New"},
		{"code": "N1", "parent_code": "N", "name": "New child"}, // under a new (restricted) BU
		{"code": "R", "parent_code": "A", "name": "Restricted", "restricted": true, "rollup_mode": "excluded"},
	}}}
	dry := se.call(t, se.admin, "POST", "/api/v1/bus/import?dry_run=true", body)
	if dry.code != 200 || dry.body["applied"] != false || dry.body["errors"] != float64(0) ||
		!strings.Contains(dry.raw, `"code":"A","changes":{"name":{"to":"Americas","from":"=HYPERLINK(1)"}},"outcome":"updated"`) ||
		!strings.Contains(dry.raw, `"code":"N1","changes":{},"outcome":"created"`) || !strings.Contains(dry.raw, `"code":"R","changes":{},"outcome":"unchanged"`) {
		t.Fatalf("dry run: %d %s", dry.code, dry.raw)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.bu WHERE code IN ('N', 'N1')"); got != "0" {
		t.Fatal("the dry run saved BUs")
	}

	// Applied: created (restricted by default), renamed, audited.
	if r := se.call(t, se.admin, "POST", "/api/v1/bus/import", body); r.code != 200 || r.body["applied"] != true {
		t.Fatalf("import: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT string_agg(b.code || ':' || p.code || ':' || b.restricted || ':' || b.name, ',' ORDER BY b.code) FROM iam.bu b JOIN iam.bu p ON p.id = b.parent_id WHERE b.code IN ('A', 'N', 'N1')"); got != "A:ENTERPRISE:false:Americas,N:A:true:New,N1:N:true:New child" {
		t.Fatalf("after import: %s", got)
	}
	if got := e.adminQuery(`SELECT string_agg(payload->>'type' || ':' || (payload->'attributes'->>'code') || ':' || (payload->>'reason'), ',' ORDER BY payload->'attributes'->>'code')
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' IN ('bu.created', 'bu.renamed') AND payload->>'severity' = 'high'`); got != "bu.renamed:A:reorg,bu.created:N:reorg,bu.created:N1:reorg" {
		t.Fatalf("import audit: %s", got)
	}

	// Refusals: the whole document fails, with every reason, and its valid
	// entry is not created either.
	bad := map[string]any{"reason": "bad", "document": map[string]any{"format": "fair.bus.v1", "bus": []map[string]any{
		{"code": "OK", "parent_code": "A", "name": "Would be fine"},
		{"code": "A", "parent_code": "N", "name": "Americas"},                        // a move
		{"code": "R", "parent_code": "A", "name": "Restricted", "restricted": false}, // un-restricting
		{"code": "N", "parent_code": "A", "name": "New", "rollup_mode": "full"},      // loosening
		{"code": "OPEN", "parent_code": "A", "name": "Open", "restricted": false},    // new, open
		{"code": "OK", "parent_code": "A", "name": "Twice"},                          // duplicate
		{"code": "ORPHAN", "parent_code": "NOPE", "name": "Orphan"},                  // unknown parent
		{"code": "R1", "parent_code": "R", "name": "Hidden"},                         // a code in use out of sight
		{"code": "INSIDE", "parent_code": "R", "name": "Inside a restricted BU"},     // no bu.manage inside R
		{"code": "bad code!", "parent_code": "A", "name": "Bad"},                     // invalid code
	}}}
	r := se.call(t, se.admin, "POST", "/api/v1/bus/import", bad)
	if r.code != http.StatusConflict || r.body["applied"] != false || r.body["errors"] != float64(9) {
		t.Fatalf("bad import: %d %s", r.code, r.raw)
	}
	for _, want := range []string{"moves are not imported", "un-restricting needs", "loosening BU N", "new BUs are restricted here",
		"code OK appears twice", "parent NOPE not found", "code R1 is already in use", "bu.manage is required at R"} {
		if !strings.Contains(r.raw, want) {
			t.Errorf("bad import report lacks %q: %s", want, r.raw)
		}
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.bu WHERE code = 'OK'"); got != "0" {
		t.Fatal("a failed import applied its valid entry")
	}

	// CSV in, with the formula guard undone; restricting an existing BU.
	in := "code,parent_code,name,restricted,rollup_mode\nC,A,'=Calc,,\nA,ENTERPRISE,Americas,true,\n"
	if r := se.call(t, se.admin, "POST", "/api/v1/bus/import", map[string]any{"reason": "csv", "csv": in}); r.code != 200 {
		t.Fatalf("csv import: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT name || ':' || restricted FROM iam.bu WHERE code IN ('C', 'A') ORDER BY code DESC"); got != "=Calc:true\nAmericas:true" {
		t.Fatalf("after csv import: %q", got)
	}

	for name, c := range map[string]struct {
		cookie string
		body   map[string]any
		code   int
	}{
		"no reason":      {se.admin, map[string]any{"reason": " ", "document": map[string]any{"format": "fair.bus.v1", "bus": []any{}}}, 400},
		"wrong format":   {se.admin, map[string]any{"reason": "x", "document": map[string]any{"format": "fair.roles.v1", "bus": []any{}}}, 400},
		"bad csv header": {se.admin, map[string]any{"reason": "x", "csv": "code,name\nX,Y\n"}, 400},
		"both forms":     {se.admin, map[string]any{"reason": "x", "csv": "", "document": map[string]any{}}, 400},
		"no bu.manage":   {se.login(t, "user"), map[string]any{"reason": "x", "csv": ""}, 404},
	} {
		if r := se.call(t, c.cookie, "POST", "/api/v1/bus/import", c.body); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := se.do(t, "GET", "/api/v1/bus/export", se.login(t, "user"), nil, nil); r.code != http.StatusNotFound {
		t.Errorf("export without bu.manage: %d", r.code)
	}
	if r := se.do(t, "GET", "/api/v1/bus/export?format=xml", se.admin, nil, nil); r.code != http.StatusBadRequest {
		t.Errorf("unknown format: %d", r.code)
	}
}

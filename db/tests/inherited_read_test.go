package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-003 T-01 (F-003-AC-08, AC-18; design §4.4, §11; ADR-007 amendment 2):
// inherited read. A shared-down table shows a caller the rows of the
// ancestors of their read scope on paths without a restricted BU, never for
// writing; every other table is unchanged.

const visibleShared = "SELECT coalesce(string_agg(title, ',' ORDER BY title), '-') FROM iam.shared_doc"

// sharedDocFixture is docFixture (ENTERPRISE > A > {A1, R (restricted) > R1},
// ENTERPRISE > B) plus iam.shared_doc, a shared-down table with one row per
// BU titled by the BU's code.
func sharedDocFixture(t *testing.T) *env {
	e := docFixture(t)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	sample := `CREATE TABLE iam.shared_doc (id serial PRIMARY KEY, bu_id uuid NOT NULL, title text NOT NULL);
SELECT authz.apply_bu_rls('iam.shared_doc', 'register', shared_down => true);
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.shared_doc TO app_rw;
GRANT USAGE ON SEQUENCE iam.shared_doc_id_seq TO app_rw;
`
	if err := os.WriteFile(filepath.Join(dir, "9101_shared_doc.sql"), []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.migrate(dir); err != nil {
		t.Fatalf("shared table: %v", err)
	}
	return e
}

func TestRLSHarnessPassesSharedTable(t *testing.T) {
	e := sharedDocFixture(t)
	for _, f := range e.harness(docRowFixture("iam.shared_doc")) {
		t.Errorf("shared_doc: %s", f)
	}
	if got := e.adminQuery("SELECT table_name::text || '/' || shared_down FROM iam.bu_owned_tables WHERE table_name::text IN ('iam.shared_doc', 'iam.sample_doc') ORDER BY 1"); got != "iam.sample_doc/false\niam.shared_doc/true" {
		t.Fatalf("registry: %q", got)
	}
}

func TestInheritedRead(t *testing.T) {
	e := sharedDocFixture(t)
	for _, code := range []string{"A2", "A3", "A4"} {
		e.addBU(code, "A")
	}
	e.admin(e.db, "INSERT INTO iam.shared_doc (bu_id, title) SELECT id, lower(code) FROM iam.bu")
	// erin: A and its children (docFixture), five of nine BUs: the exclude
	// form. mallory: R1, inside R: the include form. buadmin3: R itself.
	e.mustOwner(grant("platform", "user:mallory", "Executive Viewer", "R1"))
	e.mustOwner(grant("platform", "user:buadmin3", "Executive Viewer", "R"))
	e.drain()

	form := func(user string) string {
		out, err := e.asCtx(e.mint(user, ctxKey1), "SELECT CASE WHEN authz.scope_excludes('register', 'read') THEN 'exclude' ELSE 'include' END")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if f := form("erin"); f != "exclude" {
		t.Fatalf("erin's form %s", f)
	}
	if f := form("mallory"); f != "include" {
		t.Fatalf("mallory's form %s", f)
	}
	for _, c := range []struct{ user, shared, plain string }{
		// Their own scope, plus the root: no sibling (B), no restricted R.
		{"erin", "a,a1,a2,a3,a4,enterprise", "a,a1"},
		// Inside a restricted subtree: R1 inherits R, nothing above it.
		{"mallory", "r,r1", "r1"},
		// The restricted BU itself inherits nothing.
		{"buadmin3", "r,r1", "r,r1"},
	} {
		tok := e.mint(c.user, ctxKey1)
		if got, err := e.asCtx(tok, visibleShared); err != nil || got != c.shared {
			t.Errorf("%s sees shared rows %q (%v), want %q", c.user, got, err, c.shared)
		}
		// The ordinary table shows no inherited rows.
		if got, err := e.asCtx(tok, visibleDocs); err != nil || got != c.plain {
			t.Errorf("%s sees plain rows %q (%v), want %q", c.user, got, err, c.plain)
		}
	}

	// Inherited rows are never writable, in either form.
	for user, anc := range map[string]string{"erin": "ENTERPRISE", "mallory": "R"} {
		tok := e.mint(user, ctxKey1)
		for _, q := range []string{
			"UPDATE iam.shared_doc SET title = title WHERE title = lower('" + anc + "') RETURNING 1",
			"DELETE FROM iam.shared_doc WHERE title = lower('" + anc + "') RETURNING 1",
		} {
			if got, err := e.asCtx(tok, q); err != nil || got != "" {
				t.Errorf("%s: %s: %q %v", user, q, got, err)
			}
		}
		id := e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + anc + "'")
		if out, err := e.asCtx(tok, "INSERT INTO iam.shared_doc (bu_id, title) VALUES ('"+id+"', 'x')"); err == nil || !strings.Contains(out, "row-level security") {
			t.Errorf("%s inserts into %s: %v %s", user, anc, err, out)
		}
	}

	// Without a valid context: nothing, and inherited_bus is NULL.
	for name, tok := range map[string]string{"missing": "", "forged": sign(ctxKey1, "v1.k1.00000000-0000-0000-0000-000000000000.1.9999999999.00")} {
		got, err := e.asCtx(tok, visibleShared+"; SELECT coalesce(authz.inherited_bus('register')::text, 'null')")
		if err != nil || got != "-\nnull" {
			t.Errorf("%s context: %q %v", name, got, err)
		}
	}
	// The functions are for the roles that query BU-owned tables.
	e.mustFail("app_posture", "SELECT authz.inherited_bus('register')", "permission denied for function inherited_bus")
}

func TestRestrictedRoot(t *testing.T) {
	e := assignmentFixture(t)
	for code, want := range map[string]string{"R1": "R", "R": "R", "A1": "", "A": "", "ENTERPRISE": ""} {
		got := e.adminQuery("SELECT coalesce((SELECT code FROM iam.bu WHERE id = iam.restricted_root((SELECT id FROM iam.bu WHERE code = '" + code + "'))), '')")
		if got != want {
			t.Errorf("restricted_root(%s) = %q, want %q", code, got, want)
		}
	}
	// A restricted BU inside a restricted subtree is its own root.
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R2', 'R2', id, true FROM iam.bu WHERE code = 'R1'")
	if got := e.adminQuery("SELECT code FROM iam.bu WHERE id = iam.restricted_root((SELECT id FROM iam.bu WHERE code = 'R2'))"); got != "R2" {
		t.Errorf("restricted_root(R2) = %q", got)
	}
	if out, err := e.as("app_rw", "SELECT iam.restricted_root(gen_random_uuid())"); err != nil {
		t.Fatalf("app_rw: %v %s", err, out)
	}
	e.mustFail("app_posture", "SELECT iam.restricted_root(gen_random_uuid())", "permission denied")
}

// The harness catches broken shared-down tables, and inherited read on a
// table not registered for it.
func TestRLSHarnessDetectsBrokenSharedTables(t *testing.T) {
	e := docFixture(t)
	inherited := "OR bu_id = ANY ((SELECT authz.inherited_bus('register'))::uuid[])"
	cases := []struct {
		name, shared, sabotage, wantCheck string
	}{
		{"registered shared, plain read policy", "true", "SELECT authz.apply_bu_rls('%[1]s', 'register'); UPDATE iam.bu_owned_tables SET shared_down = true WHERE table_name = '%[1]s'::regclass", "structure"},
		{"inherited read on a plain table", "false", "DROP POLICY bu_select ON %[1]s; CREATE POLICY bu_select ON %[1]s FOR SELECT USING ((" + "%[2]s" + ") " + inherited + ")", "inherited"},
		{"inherited write", "true", "DROP POLICY bu_update ON %[1]s; CREATE POLICY bu_update ON %[1]s FOR UPDATE USING ((%[3]s) " + inherited + ") WITH CHECK (%[3]s)", "inherited"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			table := fmt.Sprintf("iam.broken_shared_%d", i)
			e.mustOwner(fmt.Sprintf(`CREATE TABLE %[1]s (id serial PRIMARY KEY, bu_id uuid NOT NULL, title text NOT NULL);
				SELECT authz.apply_bu_rls('%[1]s', 'register', shared_down => %[2]s);
				GRANT SELECT, INSERT, UPDATE, DELETE ON %[1]s TO app_rw;
				GRANT USAGE ON SEQUENCE %[1]s_id_seq TO app_rw;`, table, c.shared))
			read := e.adminQuery("SELECT authz.bu_scope_expr('register', 'read')")
			write := e.adminQuery("SELECT authz.bu_scope_expr('register', 'write')")
			e.mustOwner(fmt.Sprintf(c.sabotage, table, read, write))
			findings := e.harness(docRowFixture(table))
			if !slices.ContainsFunc(findings, func(f rlstest.Finding) bool { return strings.HasPrefix(f.Check, c.wantCheck) }) {
				t.Fatalf("harness missed %q: findings %v", c.name, findings)
			}
		})
	}
}

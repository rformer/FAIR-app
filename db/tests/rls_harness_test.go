package tests

// F-001 T-10 (AC-24, AC-25): the RLS negative-test harness as a CI suite.
// Every feature that registers a BU-owned table adds its rlstest.Fixture to
// rlsFixtures; TestRLSHarnessEveryBUOwnedTable then fails until it does.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/rlstest"
)

// rlsFixtures lists a fixture for every BU-owned table created by the
// platform's migrations, keyed by table name.
var rlsFixtures = map[string]rlstest.Fixture{}

// docRowFixture creates rows in a table shaped like iam.sample_doc.
func docRowFixture(table string) rlstest.Fixture {
	return rlstest.Fixture{
		Table: table, PK: "id", Missing: "-1", Touch: "title = title",
		Insert: func(bu string) string {
			return fmt.Sprintf("INSERT INTO %s (bu_id, title) VALUES ('%s', 'harness') RETURNING id::text", table, bu)
		},
	}
}

// adminConn connects to the test database as the admin (superuser) role.
func (e *env) adminConn() *pgx.Conn {
	e.t.Helper()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		e.t.Fatal(err)
	}
	cfg.Database = e.db
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func (e *env) harness(fx rlstest.Fixture) []rlstest.Finding {
	e.t.Helper()
	findings, err := rlstest.Check(context.Background(), rlstest.Env{Admin: e.adminConn(), App: e.appPool()}, fx)
	if err != nil {
		e.t.Fatal(err)
	}
	return findings
}

// The CI gate: every registered BU-owned table has a fixture and passes, and
// every table with a bu_id column that an application role can touch is
// registered (so it went through authz.apply_bu_rls).
// unregisteredBUTables lists tables with a bu_id column that an application
// role can access but that were not made BU-owned with authz.apply_bu_rls.
func (e *env) unregisteredBUTables() string {
	e.t.Helper()
	return e.mustOwner(`SELECT coalesce(string_agg(DISTINCT c.oid::regclass::text, ', '), '')
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'bu_id' AND NOT a.attisdropped
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND (has_table_privilege('app_rw', c.oid, 'SELECT,INSERT,UPDATE,DELETE')
		    OR has_table_privilege('app_engine', c.oid, 'SELECT,INSERT,UPDATE,DELETE'))
		  AND NOT EXISTS (SELECT 1 FROM iam.bu_owned_tables r WHERE r.table_name = c.oid)`)
}

func TestRLSHarnessEveryBUOwnedTable(t *testing.T) {
	e := setup(t)
	if unregistered := e.unregisteredBUTables(); unregistered != "" {
		t.Fatalf("tables with bu_id that application roles can access but are not BU-owned via authz.apply_bu_rls: %s", unregistered)
	}
	registered := e.mustOwner("SELECT coalesce(string_agg(table_name::text, ',' ORDER BY table_name::text), '') FROM iam.bu_owned_tables")
	if registered == "" {
		t.Log("no BU-owned tables registered yet")
		return
	}
	for _, table := range strings.Split(registered, ",") {
		fx, ok := rlsFixtures[table]
		if !ok {
			t.Errorf("%s is BU-owned but has no rlstest.Fixture in rlsFixtures (db/tests/rls_harness_test.go)", table)
			continue
		}
		for _, f := range e.harness(fx) {
			t.Errorf("%s: %s", table, f)
		}
	}
}

func TestRLSGateCatchesUnregisteredTable(t *testing.T) {
	e := setup(t)
	e.mustOwner("CREATE TABLE iam.leaky (id int, bu_id uuid NOT NULL); GRANT SELECT ON iam.leaky TO app_rw")
	if got := e.unregisteredBUTables(); got != "iam.leaky" {
		t.Fatalf("gate reported %q, want iam.leaky", got)
	}
}

func TestRLSHarnessPassesSampleTable(t *testing.T) {
	e := docFixture(t)
	for _, f := range e.harness(docRowFixture("iam.sample_doc")) {
		t.Errorf("sample_doc: %s", f)
	}
}

// The harness must catch each way a BU-owned table can be broken.
func TestRLSHarnessDetectsBrokenTables(t *testing.T) {
	e := docFixture(t)
	cases := []struct {
		name, sabotage, wantCheck string
	}{
		{"not forced", "ALTER TABLE %s NO FORCE ROW LEVEL SECURITY", "structure"},
		{"RLS disabled", "ALTER TABLE %s DISABLE ROW LEVEL SECURITY", "control"},
		{"extra permissive policy", "CREATE POLICY open ON %s FOR SELECT USING (true)", "control"},
		{"read policy opened", "DROP POLICY bu_select ON %[1]s; CREATE POLICY bu_select ON %[1]s FOR SELECT USING (true)", "control"},
		{"update without check", "DROP POLICY bu_update ON %[1]s; CREATE POLICY bu_update ON %[1]s FOR UPDATE USING (bu_id = ANY ((SELECT authz.visible_bus('register', 'write'))::uuid[])) WITH CHECK (true)", "writes"},
		{"insert checks read scope", "DROP POLICY bu_insert ON %[1]s; CREATE POLICY bu_insert ON %[1]s FOR INSERT WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus('register', 'read'))::uuid[]))", "writes"},
		{"wrong resource type", "UPDATE iam.bu_owned_tables SET resource_type = 'analysis' WHERE table_name = '%s'::regclass", "structure"},
		{"granted to PUBLIC", "GRANT SELECT ON %s TO PUBLIC", "structure"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			table := fmt.Sprintf("iam.broken_%d", i)
			e.mustOwner(fmt.Sprintf(`CREATE TABLE %[1]s (id serial PRIMARY KEY, bu_id uuid NOT NULL, title text NOT NULL);
				SELECT authz.apply_bu_rls('%[1]s', 'register');
				GRANT SELECT, INSERT, UPDATE, DELETE ON %[1]s TO app_rw;
				GRANT USAGE ON SEQUENCE %[1]s_id_seq TO app_rw;`, table))
			e.mustOwner(fmt.Sprintf(c.sabotage, table))
			findings := e.harness(docRowFixture(table))
			if !slices.ContainsFunc(findings, func(f rlstest.Finding) bool { return strings.HasPrefix(f.Check, c.wantCheck) }) {
				t.Fatalf("harness missed %q: findings %v", c.name, findings)
			}
		})
	}
}

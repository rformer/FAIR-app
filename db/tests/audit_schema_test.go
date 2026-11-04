package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-02 (F-002-AC-04, AC-08; design §4.1, §4.3): the audit schema, its
// access model, audit.submit, append-only records and the event catalog sync.

var auditTables = []string{"event_type", "intake", "record", "head", "checkpoint", "signing_key", "archive",
	"hold", "hold_segment", "export", "verification", "destination"}

// superuser runs SQL as the admin (superuser) connection and returns its output.
func (e *env) superuser(sql string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "psql", "--no-psqlrc", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", e.db, "-c", sql)
	cmd.Env = e.adminEnv
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestAuditSchemaAccess(t *testing.T) {
	e := setup(t)
	for _, role := range []string{"app_rw", "app_posture", "app_gateway", "app_engine", "app_migrator"} {
		for _, tbl := range auditTables {
			e.mustFail(role, "SELECT * FROM audit."+tbl, "permission denied")
			e.mustFail(role, "DELETE FROM audit."+tbl, "permission denied")
		}
		e.mustFail(role, "INSERT INTO audit.intake (event_id, producer, body) VALUES ('x', 'me', '{}')", "permission denied")
		e.mustFail(role, "UPDATE audit.head SET seq = 0", "permission denied")
		e.mustFail(role, "SELECT audit.ensure_partition(now())", "permission denied")
		e.mustFail(role, "SELECT audit.sync_event_types('{}')", "permission denied")
	}
	// Function grants on their own, apart from schema USAGE: who may execute what.
	grants := e.mustOwner(`SELECT string_agg(r.rolname || ':' || f.fn, ',' ORDER BY f.fn, r.rolname)
		FROM (VALUES ('audit.submit(jsonb)'), ('audit.ensure_partition(timestamptz)'), ('audit.sync_event_types(jsonb)')) f(fn)
		CROSS JOIN pg_roles r
		WHERE r.rolname IN ('public', 'app_rw', 'app_posture', 'app_gateway', 'app_engine', 'app_migrator', 'fair_owner')
		  AND has_function_privilege(r.oid, f.fn::regprocedure, 'EXECUTE')`)
	if grants != "app_gateway:audit.submit(jsonb),app_posture:audit.submit(jsonb),app_rw:audit.submit(jsonb),fair_owner:audit.sync_event_types(jsonb)" {
		t.Fatalf("function grants: %s", grants)
	}
	if out := e.mustOwner(`SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'audit' AND has_function_privilege('public', p.oid, 'EXECUTE')`); out != "0" {
		t.Fatalf("audit functions executable by PUBLIC: %s", out)
	}
	// Only the producing services may submit.
	e.mustFail("app_engine", `SELECT audit.submit('{}')`, "permission denied")
	e.mustFail("app_migrator", `SELECT audit.submit('{}')`, "permission denied")

	// The schema owner sees no rows either (forced RLS, one policy for
	// audit_definer), and cannot take over the record table.
	sub := submitEvent(map[string]any{"type": "db.migrated", "severity": "info", "actor": "system:test"})
	if _, err := e.as("app_rw", "SELECT audit.submit('"+sub+"')"); err != nil {
		t.Fatal(err)
	}
	if out := e.mustOwner("SELECT count(*) FROM audit.intake"); out != "0" {
		t.Fatalf("fair_owner sees %s intake rows", out)
	}
	e.ownerFails("ALTER TABLE audit.record DISABLE TRIGGER record_append_only", "must be owner")

	// Every table has RLS forced with only the definer policy.
	out := e.mustOwner(`SELECT string_agg(c.relname || ':' || c.relrowsecurity || ':' || c.relforcerowsecurity, ',' ORDER BY c.relname)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'audit' AND c.relkind IN ('r', 'p')`)
	for _, tbl := range auditTables {
		if !strings.Contains(","+out+",", ","+tbl+":true:true,") {
			t.Fatalf("audit.%s: RLS not enabled and forced (%s)", tbl, out)
		}
	}
	pol := e.mustOwner(`SELECT string_agg(DISTINCT polname || ':' || array_to_string(ARRAY(SELECT rolname FROM pg_roles WHERE oid = ANY (polroles)), '|'), ',')
		FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'audit'`)
	if pol != "definer_only:audit_definer" {
		t.Fatalf("audit policies: %s", pol)
	}
	// SECURITY DEFINER functions are owned by audit_definer with a fixed search_path.
	fns := e.mustOwner(`SELECT string_agg(p.proname || ':' || pg_get_userbyid(p.proowner) || ':' || coalesce(array_to_string(p.proconfig, '|'), ''), ',' ORDER BY p.proname)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'audit' AND p.prosecdef`)
	want := "ensure_partition:audit_definer:search_path=pg_catalog, pg_temp,submit:audit_definer:search_path=pg_catalog, pg_temp,sync_event_types:audit_definer:search_path=pg_catalog, pg_temp"
	if fns != want {
		t.Fatalf("definer functions\n got: %s\nwant: %s", fns, want)
	}
}

func submitEvent(m map[string]any) string {
	b, _ := json.Marshal(m)
	return strings.ReplaceAll(string(b), "'", "''")
}

// intakeRow returns producer|body of one intake row, read as audit_definer.
func (e *env) intakeRow(id string) string {
	e.t.Helper()
	out, err := e.superuser(fmt.Sprintf("SET ROLE audit_definer; SELECT producer || '|' || body::text FROM audit.intake WHERE event_id = '%s'", id))
	if err != nil {
		e.t.Fatalf("%v: %s", err, out)
	}
	return out
}

func TestAuditSubmit(t *testing.T) {
	e := setup(t)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")

	ok := map[string]any{"id": "evt-1", "type": "access.assignment_expired", "severity": "low", "actor": "system:iam",
		"target": "assignment:1", "time": "2026-11-04T10:00:00Z", "bu_id": root, "source_ip": "192.0.2.7",
		"before": map[string]any{"n": 1.5}, "attributes": map[string]any{"role": "v"}, "request_id": "r-1"}
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		out, err := e.as(role, "SELECT audit.submit('"+submitEvent(ok)+"')")
		if err != nil || out != "evt-1" {
			t.Fatalf("%s submit: %q %v", role, out, err)
		}
	}
	// Accepted once (retries are no-ops); the producer is the first caller's role.
	if n, _ := e.superuser("SET ROLE audit_definer; SELECT count(*) FROM audit.intake"); n != "1" {
		t.Fatalf("intake rows: %s", n)
	}
	row := e.intakeRow("evt-1")
	if !strings.HasPrefix(row, "app_rw|") || !strings.Contains(row, `"time": "2026-11-04T10:00:00.000000Z"`) {
		t.Fatalf("intake row: %s", row)
	}

	// The producer comes from the DB role, never from the body.
	spoof := map[string]any{"id": "evt-2", "type": "db.migrated", "severity": "info", "actor": "system:x", "producer": "iam"}
	e.mustFail("app_posture", "SELECT audit.submit('"+submitEvent(spoof)+"')", "unknown field producer")

	// An event without id or time gets both.
	out, err := e.as("app_posture", `SELECT audit.submit('{"type":"db.migrated","severity":"info","actor":"system:x"}')`)
	if err != nil || len(out) != 32 {
		t.Fatalf("generated id: %q %v", out, err)
	}
	if row := e.intakeRow(out); !strings.HasPrefix(row, "app_posture|") || !strings.Contains(row, `"time": "20`) {
		t.Fatalf("generated row: %s", row)
	}

	// In the caller's transaction: rolled back with it.
	if _, err := e.as("app_rw", `BEGIN; SELECT audit.submit('{"id":"evt-rb","type":"db.migrated","severity":"info","actor":"system:x"}'); ROLLBACK;`); err != nil {
		t.Fatal(err)
	}
	if row := e.intakeRow("evt-rb"); row != "" {
		t.Fatalf("rolled-back event recorded: %s", row)
	}

	// Refusals (PF011).
	// base is a valid event with the given fields changed (nil: removed).
	type kv map[string]any
	base := func(over kv) string {
		m := map[string]any{"type": "db.migrated", "severity": "info", "actor": "system:x"}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return "SELECT audit.submit('" + submitEvent(m) + "')"
	}
	for _, tc := range []struct{ sql, want string }{
		{"SELECT audit.submit(NULL)", "an object is required"},
		{"SELECT audit.submit('[]')", "an object is required"},
		{base(kv{"type": "no.such_type"}), "is not in the catalog"},
		{base(kv{"type": nil}), "is not in the catalog"},
		{base(kv{"severity": "critical"}), "with severity critical"},
		{base(kv{"severity": nil}), "with severity (none)"},
		{base(kv{"actor": " "}), "without an actor"},
		{base(kv{"actor": nil}), "without an actor"},
		{base(kv{"type": "access.assignment_expired", "severity": "low"}), "without target"},
		{base(kv{"extra": "x"}), "unknown field extra"},
		{base(kv{"target": 7}), "target must be a string"},
		{base(kv{"attributes": []any{"x"}}), "attributes must be an object"},
		{base(kv{"attributes": map[string]any{"n": 1}}), "attribute n must be a string"},
		{base(kv{"bu_id": "not-a-uuid"}), "is not a UUID"},
		{base(kv{"bu_id": "00000000-0000-0000-0000-000000000000"}), "unknown BU"},
		{base(kv{"source_ip": "not-an-ip"}), "is not an address"},
		{base(kv{"time": "yesterday-ish"}), "is not a timestamp"},
		{base(kv{"id": "bad id!"}), "is not valid"},
		{base(kv{"reason": strings.Repeat("x", 70000)}), "larger than 64 KiB"},
		// T-03: only the catalog's attributes, and nothing that looks like a secret.
		{base(kv{"attributes": map[string]any{"nope": "x"}}), "with attribute nope (not in the catalog)"},
		{base(kv{"reason": "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln"}), "looks like a secret"},
		{base(kv{"attributes": map[string]any{"applied": "Bearer abcdefghijklmnopqrstuvwxyz0123"}}), "looks like a secret"},
		{base(kv{"before": map[string]any{"pem": "-----BEGIN RSA PRIVATE KEY-----"}}), "looks like a secret"}, // #nosec G101 -- a header only, to test the refusal
	} {
		out, err := e.as("app_rw", tc.sql)
		if err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "audit event") {
			t.Errorf("%.80s: want %q, got %q (%v)", tc.sql, tc.want, out, err)
		}
	}
	// A type the catalog marks bu: required needs a bu_id (T-03 sets the
	// field from the catalog; here it is set directly).
	if out, err := e.superuser("SET ROLE audit_definer; UPDATE audit.event_type SET bu = 'required' WHERE type = 'db.migrated'"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	e.mustFail("app_rw", base(kv{}), "db.migrated without bu_id")
	if _, err := e.as("app_rw", base(kv{"bu_id": root})); err != nil {
		t.Fatalf("with bu_id: %v", err)
	}
	// The reserved event_id attribute is accepted on any type.
	if _, err := e.as("app_rw", base(kv{"attributes": map[string]any{"event_id": "7"}, "bu_id": root})); err != nil {
		t.Fatalf("event_id attribute: %v", err)
	}
	// The catalog's attribute lists reached the database.
	if out, _ := e.superuser("SET ROLE audit_definer; SELECT count(*) FROM audit.event_type WHERE attributes IS NULL"); out != "0" {
		t.Fatalf("event types without attribute lists: %s", out)
	}
	// The error class is PF011.
	if _, err := e.as("app_rw", `DO $$ BEGIN PERFORM audit.submit('{}'); EXCEPTION WHEN SQLSTATE 'PF011' THEN NULL; END $$`); err != nil {
		t.Fatalf("submit's refusal is not PF011: %v", err)
	}
}

// Records and checkpoints are append-only for every role (AC-08).
func TestAuditAppendOnly(t *testing.T) {
	e := setup(t)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	h := strings.Repeat("ab", 32)
	setup := fmt.Sprintf(`SET ROLE audit_definer;
SELECT audit.ensure_partition('2026-11-04T10:00:00Z');
SELECT audit.ensure_partition('2026-11-20T10:00:00Z');
SELECT audit.ensure_partition('2026-12-01T00:00:00Z');
INSERT INTO audit.record (seq, event_id, event_time, received_at, producer, type, category, severity, actor, bu_id, body, leaf_hash, chain_hash, segment)
VALUES (1, 'e1', '2026-11-04T10:00:00Z', now(), 'app_rw', 'db.migrated', 'system', 'info', 'system:x', '%[1]s', '\x7b7d', '\x%[2]s', '\x%[2]s', 1);
INSERT INTO audit.checkpoint (segment, seq_from, seq_to, merkle_root, chain_hash, prev_checkpoint_hash, issued_at, key_id, statement, signature)
VALUES (1, 1, 1, '\x%[2]s', '\x%[2]s', '\x%[2]s', now(), '%[2]s', '\x7b7d', '\x00');
INSERT INTO audit.signing_key (key_id, public_pem) VALUES ('%[2]s', '-----BEGIN PUBLIC KEY-----x');`, root, h)
	if out, err := e.superuser(setup); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if out, _ := e.superuser(`SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit.record'::regclass`); out != "record_202611,record_202612" {
		t.Fatalf("partitions: %s", out)
	}
	for _, who := range []string{"SET ROLE audit_definer;", ""} { // the definer, and a superuser
		for _, sql := range []string{
			"UPDATE audit.record SET actor = 'someone else'",
			"DELETE FROM audit.record",
			"TRUNCATE audit.record",
			"DELETE FROM audit.record_202611",
			"TRUNCATE audit.record_202611",
			"UPDATE audit.checkpoint SET seq_to = 2",
			"UPDATE audit.checkpoint SET worm_key = 'k', seq_to = 0",
			"DELETE FROM audit.checkpoint",
			"TRUNCATE audit.checkpoint CASCADE",
			"UPDATE audit.signing_key SET public_pem = '-----BEGIN PUBLIC KEY-----y'",
			"DELETE FROM audit.signing_key",
		} {
			out, err := e.superuser(who + sql)
			// audit_definer may also be stopped earlier by its grants.
			refused := strings.Contains(out, "append-only") || who != "" && strings.Contains(out, "permission denied")
			if err == nil || !refused {
				t.Errorf("%q %q: %v %s", who, sql, err, out)
			}
		}
	}
	// The flag only the retention function sets (T-18) lets a delete through.
	if out, err := e.superuser("SET ROLE audit_definer; BEGIN; SET LOCAL audit.archiving = 'on'; DELETE FROM audit.record WHERE seq = 1; ROLLBACK;"); err != nil {
		t.Fatalf("archiving delete: %v %s", err, out)
	}
	// worm_key is written once; retired_at once.
	if out, err := e.superuser("SET ROLE audit_definer; UPDATE audit.checkpoint SET worm_key = 'checkpoints/i/1.json'"); err != nil {
		t.Fatalf("worm_key: %v %s", err, out)
	}
	if out, err := e.superuser("SET ROLE audit_definer; UPDATE audit.checkpoint SET worm_key = 'other'"); err == nil || !strings.Contains(out, "append-only") {
		t.Fatalf("worm_key rewritten: %v %s", err, out)
	}
	if out, err := e.superuser("SET ROLE audit_definer; UPDATE audit.signing_key SET retired_at = now()"); err != nil {
		t.Fatalf("retire key: %v %s", err, out)
	}
	if out, err := e.superuser("SET ROLE audit_definer; UPDATE audit.signing_key SET retired_at = now() + interval '1 day'"); err == nil || !strings.Contains(out, "append-only") {
		t.Fatalf("retired_at rewritten: %v %s", err, out)
	}
	// Partitions have RLS forced with the definer policy, and no grants.
	if out, _ := e.superuser(`SELECT string_agg(c.relname || ':' || c.relrowsecurity || ':' || c.relforcerowsecurity || ':' || (cardinality(c.relacl) = 1 AND c.relacl::text LIKE '{audit_definer=%/audit_definer}') || ':' ||
		(SELECT string_agg(polname, '|') FROM pg_policy WHERE polrelid = c.oid), ',' ORDER BY c.relname)
		FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit.record'::regclass`); out != "record_202611:true:true:true:definer_only,record_202612:true:true:true:definer_only" {
		t.Fatalf("partition security: %s", out)
	}
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		e.mustFail(role, "SELECT * FROM audit.record_202611", "permission denied")
	}
	// ensure_partition is idempotent.
	if out, err := e.superuser("SET ROLE audit_definer; SELECT audit.ensure_partition('2026-11-30T23:59:59Z')"); err != nil || out != "record_202611" {
		t.Fatalf("ensure_partition again: %q %v", out, err)
	}
	if out, err := e.superuser("SET ROLE audit_definer; SELECT audit.ensure_partition(NULL)"); err == nil {
		t.Fatalf("ensure_partition(NULL): %s", out)
	}
}

func TestAuditEventTypeSync(t *testing.T) {
	e := setup(t)
	c, err := audit.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	// The install synced every catalog type.
	if got := len(e.install.Events.Added); got != len(c.Entries) {
		t.Fatalf("install added %d event types, catalog has %d", got, len(c.Entries))
	}
	out, _ := e.superuser("SET ROLE audit_definer; SELECT count(*) FROM audit.event_type WHERE retired_at IS NULL")
	if out != fmt.Sprint(len(c.Entries)) {
		t.Fatalf("event types: %s", out)
	}
	// Columns follow the catalog.
	ent := c.Entries["access.assignment_expired"]
	row, _ := e.superuser(`SET ROLE audit_definer; SELECT category || '|' || array_to_string(severities, ',') || '|' || array_to_string(requires, ',') || '|' || bu || '|' || description
		FROM audit.event_type WHERE type = 'access.assignment_expired'`)
	if row != fmt.Sprintf("%s|low|target|required|%s", ent.Category, ent.Description) {
		t.Fatalf("event_type row: %s", row)
	}

	// A second run changes nothing.
	res, err := e.migrate("")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events.Added)+len(res.Events.Changed)+len(res.Events.Retired)+len(res.Events.Restored) != 0 {
		t.Fatalf("second sync: %+v", res.Events)
	}

	// A catalog without a type retires it: submit refuses it, then it comes back.
	payload, _ := c.SyncPayload()
	var p struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal(payload, &p)
	var kept []map[string]any
	for _, ev := range p.Events {
		if ev["type"] != "db.migrated" {
			if ev["type"] == "approval.requested" {
				ev["description"] = "changed"
			}
			kept = append(kept, ev)
		}
	}
	smaller, _ := json.Marshal(map[string]any{"events": kept})
	out = e.mustOwner("SELECT audit.sync_event_types('" + strings.ReplaceAll(string(smaller), "'", "''") + "')")
	if out != `{"added": [], "changed": ["approval.requested"], "retired": ["db.migrated"], "restored": []}` {
		t.Fatalf("sync without db.migrated: %s", out)
	}
	e.mustFail("app_rw", `SELECT audit.submit('{"type":"db.migrated","severity":"info","actor":"system:x"}')`, "not in the catalog")
	out = e.mustOwner("SELECT audit.sync_event_types('" + strings.ReplaceAll(string(payload), "'", "''") + "')")
	if out != `{"added": [], "changed": ["approval.requested"], "retired": [], "restored": ["db.migrated"]}` {
		t.Fatalf("sync restoring db.migrated: %s", out)
	}
	if _, err := e.as("app_rw", `SELECT audit.submit('{"type":"db.migrated","severity":"info","actor":"system:x"}')`); err != nil {
		t.Fatal(err)
	}

	// Malformed payloads are refused.
	for _, bad := range []string{`{}`, `{"events":[]}`, `{"events":[{"type":1}]}`, `{"events":[{"category":"system","severities":["info"],"description":"d"}]}`,
		`{"events":[{"type":"a.b","severities":["info"],"description":"d"}]}`, `{"events":[{"type":"a.b","category":"system","description":"d"}]}`,
		`{"events":[{"type":"a.b","category":"system","severities":["info"]}]}`, `{"events":[{"type":"a.b","category":"system","severities":["info"],"description":"d","bu":"sometimes"}]}`,
		`{"events":[{"type":"a.b","category":"system","severities":["info"],"description":"d"},{"type":"a.b","category":"system","severities":["info"],"description":"d"}]}`,
		`{"events":[{"type":"a.b","category":"system","severities":["urgent"],"description":"d"}]}`} {
		e.ownerFails("SELECT audit.sync_event_types('"+bad+"')", "")
	}
	// Nothing was retired by the refused payloads.
	if out, _ := e.superuser("SET ROLE audit_definer; SELECT count(*) FROM audit.event_type WHERE retired_at IS NOT NULL"); out != "0" {
		t.Fatalf("retired by refused payloads: %s", out)
	}
}

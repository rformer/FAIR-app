package tests

// F-001 T-09 (AC-24, AC-25, AC-27; ADR-007): signed database context and BU
// row-level security on a sample BU-owned table.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

var (
	ctxKey1 = authz.ContextKey{ID: "k1", Secret: []byte("k1-secret-0123456789abcdef-012345")}
	ctxKey2 = authz.ContextKey{ID: "k2", Secret: []byte("k2-secret-0123456789abcdef-012345")}
)

func (e *env) addCtxKey(k authz.ContextKey) {
	e.t.Helper()
	e.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'))", k.ID, hex.EncodeToString(k.Secret)))
}

// docFixture: the assignment fixture plus erin with read on A (and below) and
// write on A1, a sample BU-owned table iam.sample_doc with one row per BU, and
// context key k1.
func docFixture(t *testing.T) *env {
	e := assignmentFixture(t)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	sample := `CREATE TABLE iam.sample_doc (id serial PRIMARY KEY, bu_id uuid NOT NULL, title text NOT NULL);
SELECT authz.apply_bu_rls('iam.sample_doc', 'register');
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.sample_doc TO app_rw;
GRANT USAGE ON SEQUENCE iam.sample_doc_id_seq TO app_rw;
`
	if err := os.WriteFile(filepath.Join(dir, "9100_sample_doc.sql"), []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.migrate(dir); err != nil {
		t.Fatalf("sample table: %v", err)
	}
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	e.mustOwner(grant("platform", "user:erin", "Risk Owner", "A1"))
	e.drain()
	// Superuser inserts bypass RLS: one row per BU.
	e.admin(e.db, `INSERT INTO iam.sample_doc (bu_id, title) SELECT id, lower(code) FROM iam.bu WHERE code IN ('A', 'A1', 'B', 'R', 'R1')`)
	e.addCtxKey(ctxKey1)
	return e
}

// mint returns a context token for user at their current scope version.
func (e *env) mint(user string, k authz.ContextKey) string {
	e.t.Helper()
	out := e.mustOwner(fmt.Sprintf("SELECT u.id || '|' || coalesce(s.scope_version, 0) FROM iam.app_user u LEFT JOIN authz.user_scope s ON s.user_id = u.id WHERE u.id = %s", uid(user)))
	id, ver, _ := strings.Cut(out, "|")
	v, _ := strconv.ParseInt(ver, 10, 64)
	tok, err := authz.MintDBContext(k, id, v, time.Minute, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// asCtx runs sql as app_rw with authz.ctx set to tok ("" = not set).
func (e *env) asCtx(tok, sql string) (string, error) {
	if tok != "" {
		sql = fmt.Sprintf("SET authz.ctx = '%s'; %s", strings.ReplaceAll(tok, "'", "''"), sql)
	}
	return e.as("app_rw", sql)
}

const visibleDocs = "SELECT coalesce(string_agg(title, ',' ORDER BY title), '-') FROM iam.sample_doc"

// sign builds a token by hand, for shapes MintDBContext refuses to produce.
func sign(k authz.ContextKey, body string) string {
	mac := hmac.New(sha256.New, k.Secret)
	mac.Write([]byte(body))
	return body + "." + hex.EncodeToString(mac.Sum(nil))
}

func TestDBContextScopesRows(t *testing.T) {
	e := docFixture(t)
	tok := e.mint("erin", ctxKey1)

	if out, err := e.asCtx(tok, visibleDocs); err != nil || out != "a,a1" {
		t.Fatalf("erin sees %q (%v), want a,a1: not B (unassigned) or R, R1 (restricted)", out, err)
	}
	// Writes need write scope (Risk Owner at A1 only). app_rw cannot read
	// iam.bu, so BU ids are passed as literals.
	a1 := e.mustOwner("SELECT " + buID("A1"))
	a := e.mustOwner("SELECT " + buID("A"))
	b := e.mustOwner("SELECT " + buID("B"))
	if out, err := e.asCtx(tok, fmt.Sprintf("INSERT INTO iam.sample_doc (bu_id, title) VALUES ('%s', 'new')", a1)); err != nil {
		t.Fatalf("insert in write scope: %s", out)
	}
	for name, sql := range map[string]string{
		"insert at read-only BU":  fmt.Sprintf("INSERT INTO iam.sample_doc (bu_id, title) VALUES ('%s', 'x')", a),
		"insert at unassigned BU": fmt.Sprintf("INSERT INTO iam.sample_doc (bu_id, title) VALUES ('%s', 'x')", b),
		"move a row out of scope": fmt.Sprintf("UPDATE iam.sample_doc SET bu_id = '%s' WHERE title = 'a1'", b),
		"move a row to read-only": fmt.Sprintf("UPDATE iam.sample_doc SET bu_id = '%s' WHERE title = 'a1'", a),
	} {
		if out, err := e.asCtx(tok, sql); err == nil || !strings.Contains(out, "row-level security") {
			t.Errorf("%s: want an RLS violation, got %q %v", name, out, err)
		}
	}
	affected := func(sql string) string {
		out, err := e.asCtx(tok, "WITH x AS ("+sql+" RETURNING 1) SELECT count(*) FROM x")
		if err != nil {
			t.Fatalf("%s: %v %s", sql, err, out)
		}
		return out
	}
	if n := affected("UPDATE iam.sample_doc SET title = 'zz' WHERE title = 'a'"); n != "0" {
		t.Errorf("updated %s read-only rows", n)
	}
	if n := affected("DELETE FROM iam.sample_doc WHERE title IN ('a', 'b', 'r')"); n != "0" {
		t.Errorf("deleted %s rows outside write scope", n)
	}
	if n := affected("DELETE FROM iam.sample_doc WHERE title = 'new'"); n != "1" {
		t.Errorf("delete in write scope affected %s rows", n)
	}
}

// Every invalid context fails closed to an empty scope.
func TestDBContextFailsClosed(t *testing.T) {
	e := docFixture(t)
	good := e.mint("erin", ctxKey1)
	parts := strings.Split(good, ".")
	body := strings.Join(parts[:6], ".")
	now := time.Now().Unix()
	withExp := func(exp int64) string {
		p := append([]string(nil), parts[:6]...)
		p[4] = strconv.FormatInt(exp, 10)
		return sign(ctxKey1, strings.Join(p, "."))
	}
	flip := func(s string) string {
		last := s[len(s)-1]
		if last == '0' {
			return s[:len(s)-1] + "1"
		}
		return s[:len(s)-1] + "0"
	}
	otherUser := strings.Replace(body, parts[2], e.mustOwner("SELECT "+uid("platform")), 1)

	cases := map[string]string{
		"no context":           "",
		"empty":                " ",
		"garbage":              "not-a-token",
		"wrong version tag":    "v2" + good[2:],
		"tampered signature":   flip(good),
		"forged user id":       otherUser + "." + parts[6],
		"unknown key id":       sign(authz.ContextKey{ID: "k9", Secret: ctxKey1.Secret}, strings.Replace(body, "v1.k1.", "v1.k9.", 1)),
		"signed with k2 as k1": sign(ctxKey2, body),
		"expired":              withExp(now - 1),
		"lifetime over max":    withExp(now + 3600),
		"bad user id":          sign(ctxKey1, strings.Replace(body, parts[2], "not-a-uuid", 1)),
		"sql in token":         good + "'; SELECT 1; --",
	}
	for name, tok := range cases {
		out, err := e.asCtx(tok, visibleDocs)
		if err != nil {
			t.Errorf("%s: query failed instead of returning nothing: %s", name, out)
		} else if out != "-" {
			t.Errorf("%s: saw rows %q", name, out)
		}
	}
	if out, _ := e.asCtx(good, visibleDocs); out != "a,a1" {
		t.Fatalf("control token sees %q", out)
	}

	// Stale scope version: a scope change invalidates earlier tokens.
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "B"))
	e.drain()
	if out, _ := e.asCtx(good, visibleDocs); out != "-" {
		t.Errorf("stale token sees %q", out)
	}
	if out, _ := e.asCtx(e.mint("erin", ctxKey1), visibleDocs); out != "a,a1,b" {
		t.Errorf("fresh token after the grant sees %q, want a,a1,b", out)
	}

	// Disabled users have no scope row at all.
	fresh := e.mint("erin", ctxKey1)
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE id = " + uid("erin"))
	e.drain()
	if out, _ := e.asCtx(fresh, visibleDocs); out != "-" {
		t.Errorf("disabled user's token sees %q", out)
	}
}

// Rotation: both keys work during the window; the old key stops after it.
func TestDBContextKeyRotation(t *testing.T) {
	e := docFixture(t)
	old := e.mint("erin", ctxKey1)
	e.addCtxKey(ctxKey2)
	e.mustOwner("SELECT authz.retire_ctx_key('k1', now() + interval '1 hour')")
	for name, tok := range map[string]string{"old key in window": old, "new key": e.mint("erin", ctxKey2)} {
		if out, _ := e.asCtx(tok, visibleDocs); out != "a,a1" {
			t.Errorf("%s sees %q", name, out)
		}
	}
	e.mustOwner("UPDATE authz.ctx_key SET retired_at = now() - interval '1 second' WHERE key_id = 'k1'")
	if out, _ := e.asCtx(old, visibleDocs); out != "-" {
		t.Errorf("retired key still accepted: %q", out)
	}
	e.ownerFails("SELECT authz.retire_ctx_key('k1')", "no active key")
	e.ownerFails("SELECT authz.add_ctx_key('k3', '\\x00')", "ctx_key_secret_check")
	e.ownerFails("SELECT authz.add_ctx_key('bad.id', decode(repeat('00', 32), 'hex'))", "ctx_key_id_format")
}

// AC-27: application roles cannot see keys, call the verifier, or bypass RLS;
// the owner is subject to forced RLS too.
func TestDBContextRoleBoundaries(t *testing.T) {
	e := docFixture(t)
	e.mustFail("app_rw", "SELECT * FROM authz.ctx_key", "permission denied")
	e.mustFail("app_rw", "SELECT authz.ctx_scope()", "permission denied")
	e.mustFail("app_rw", "SELECT * FROM authz.user_scope", "permission denied")
	e.mustFail("app_rw", "SET row_security = off; SELECT * FROM iam.sample_doc", "row-level security")
	e.mustFail("app_rw", "ALTER TABLE iam.sample_doc DISABLE ROW LEVEL SECURITY", "must be owner")
	// RLS is forced for the owner too: its query reaches the policy, which it
	// may not even evaluate (no EXECUTE on visible_bus), so it fails closed.
	e.ownerFails(visibleDocs, "permission denied for function visible_bus")
	if out := e.mustOwner("SELECT proowner::regrole FROM pg_proc WHERE oid = 'authz.visible_bus(text,text)'::regprocedure"); out != "authz_definer" {
		t.Fatalf("visible_bus owner = %s", out)
	}
	// visible_bus itself only ever reveals the caller's own scope.
	if out, err := e.asCtx("", "SELECT cardinality(authz.visible_bus('register'))"); err != nil || out != "0" {
		t.Fatalf("visible_bus without context = %q %v", out, err)
	}
}

func TestApplyBuRLSGuards(t *testing.T) {
	e := docFixture(t)
	if out := e.mustOwner("SELECT resource_type FROM iam.bu_owned_tables WHERE table_name = 'iam.sample_doc'::regclass"); out != "register" {
		t.Fatalf("registry = %q", out)
	}
	if out := e.mustOwner("SELECT count(*) FROM pg_constraint WHERE conrelid = 'iam.sample_doc'::regclass AND contype = 'f'"); out != "1" {
		t.Fatalf("bu_id foreign keys = %s", out)
	}
	e.mustOwner("CREATE TABLE iam.no_bu (id int); CREATE TABLE iam.null_bu (bu_id uuid); CREATE TABLE iam.extra (bu_id uuid NOT NULL)")
	e.mustOwner("ALTER TABLE iam.extra ENABLE ROW LEVEL SECURITY; CREATE POLICY open ON iam.extra USING (true)")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.no_bu', 'register')", "NOT NULL uuid column bu_id")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.null_bu', 'register')", "NOT NULL uuid column bu_id")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.extra', 'register')", "other policies")
	e.ownerFails("SELECT authz.apply_bu_rls('iam.sample_doc', 'nonsense')", "unknown resource type")
	// Re-applying is idempotent.
	e.mustOwner("SELECT authz.apply_bu_rls('iam.sample_doc', 'register')")
	if out := e.mustOwner("SELECT count(*) FROM pg_policy WHERE polrelid = 'iam.sample_doc'::regclass"); out != "4" {
		t.Fatalf("policies after re-apply = %s", out)
	}
}

package tests

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-11d (ADR-007 amendment 1; AC-24, AC-25): BU policies check the
// smaller of the caller's visible BUs and the BUs they cannot see. Both forms
// admit exactly the rows of the visible set, and the exclude form never makes
// a BU visible by default.
func TestScopeForms(t *testing.T) {
	e := docFixture(t) // BUs ENTERPRISE, A, A1, B, R (restricted), R1; one sample_doc row per BU but ENTERPRISE
	e.mustOwner(grant("platform", "user:analyst", "Executive Viewer", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:analyst", "Risk Owner", "ENTERPRISE"))
	e.drain()

	form := func(user, mode string) string {
		out, err := e.asCtx(e.mint(user, ctxKey1), "SELECT CASE WHEN authz.scope_excludes('register', '"+mode+"') THEN 'exclude' ELSE 'include' END")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// The root reader sees 4 of 6 BUs: the exclude form; erin sees 2: include.
	if f := form("analyst", "read"); f != "exclude" {
		t.Fatalf("analyst read form %s", f)
	}
	if f := form("analyst", "write"); f != "exclude" {
		t.Fatalf("analyst write form %s", f)
	}
	if f := form("erin", "read"); f != "include" {
		t.Fatalf("erin read form %s", f)
	}

	// Both forms admit exactly the rows in the visible set.
	same := func(user string) {
		t.Helper()
		tok := e.mint(user, ctxKey1)
		vis, err := e.asCtx(tok, "SELECT coalesce(array_to_string(authz.visible_bus('register', 'read'), ','), '')")
		if err != nil {
			t.Fatal(err)
		}
		want := e.adminQuery("SELECT coalesce(string_agg(title, ',' ORDER BY title), '-') FROM iam.sample_doc WHERE bu_id::text = ANY (string_to_array('" + vis + "', ','))")
		if got, _ := e.asCtx(tok, visibleDocs); got != want {
			t.Errorf("%s sees %s, the visible set holds %s", user, got, want)
		}
	}
	for _, u := range []string{"analyst", "erin", "mallory"} {
		same(u)
	}
	if got, _ := e.asCtx(e.mint("analyst", ctxKey1), visibleDocs); got != "a,a1,b" {
		t.Fatalf("analyst sees %s", got)
	}

	// A BU created after the caller's scope was computed is hidden, even
	// unrestricted, until the scope is recomputed.
	before := e.mint("analyst", ctxKey1)
	e.addBU("N", "ENTERPRISE")
	e.admin(e.db, "INSERT INTO iam.sample_doc (bu_id, title) SELECT id, 'n' FROM iam.bu WHERE code = 'N'")
	if got, _ := e.asCtx(before, visibleDocs); got != "a,a1,b" {
		t.Fatalf("a BU created after the scope: %s", got)
	}
	// app_rw cannot read iam.bu: ids go in as literals.
	insertInto := func(tok, code, title string) (string, error) {
		return e.asCtx(tok, "INSERT INTO iam.sample_doc (bu_id, title) VALUES ('"+e.adminQuery("SELECT id FROM iam.bu WHERE code = '"+code+"'")+"', '"+title+"')")
	}
	if out, err := insertInto(before, "N", "x"); err == nil || !strings.Contains(out, "row-level security") {
		t.Fatalf("a write into a BU created after the scope: %v %s", err, out)
	}
	e.drain()
	if got, _ := e.asCtx(e.mint("analyst", ctxKey1), visibleDocs); got != "a,a1,b,n" {
		t.Fatalf("after the recompute: %s", got)
	}

	// Archived BUs leave the write scope at once, in the exclude form too.
	e.addBU("C", "ENTERPRISE")
	e.drain()
	tok := e.mint("analyst", ctxKey1)
	if f := form("analyst", "write"); f != "exclude" {
		t.Fatalf("analyst write form after C: %s", f)
	}
	if out, err := insertInto(tok, "C", "c"); err != nil {
		t.Fatalf("write into C: %v %s", err, out)
	}
	if _, err := e.asCtx(tok, "DELETE FROM iam.sample_doc WHERE title = 'c'"); err != nil {
		t.Fatal(err)
	}
	e.mustOwner("UPDATE iam.bu SET archived_at = now() WHERE code = 'C'")
	if out, err := insertInto(tok, "C", "c"); err == nil || !strings.Contains(out, "row-level security") {
		t.Fatalf("write into an archived BU: %v %s", err, out)
	}

	// And in the include form: erin writes in a new BU D below A1 until it is
	// archived.
	e.addBU("D", "A1")
	e.drain()
	tok = e.mint("erin", ctxKey1)
	if f := form("erin", "write"); f != "include" {
		t.Fatalf("erin write form %s", f)
	}
	if out, err := insertInto(tok, "D", "d"); err != nil {
		t.Fatalf("erin writes into D: %v %s", err, out)
	}
	if _, err := e.asCtx(tok, "DELETE FROM iam.sample_doc WHERE title = 'd'"); err != nil {
		t.Fatal(err)
	}
	e.mustOwner("UPDATE iam.bu SET archived_at = now() WHERE code = 'D'")
	if out, err := insertInto(tok, "D", "d"); err == nil || !strings.Contains(out, "row-level security") {
		t.Fatalf("include form, write into an archived BU: %v %s", err, out)
	}

	// Fail closed with an exclude-form user: forged, expired and stale
	// contexts see nothing, and scope_hides is NULL for them.
	analyst := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	ver, _ := strconv.ParseInt(e.mustOwner("SELECT scope_version FROM authz.user_scope WHERE user_id = '"+analyst+"'"), 10, 64)
	expired, _ := authz.MintDBContext(ctxKey1, analyst, ver, time.Minute, time.Now().Add(-10*time.Minute))
	stale, _ := authz.MintDBContext(ctxKey1, analyst, ver-1, time.Minute, time.Now())
	forged, _ := authz.MintDBContext(ctxKey2, analyst, ver, time.Minute, time.Now()) // k2 is not registered
	// ctx_user itself refuses each of them (its callers also match the
	// version; this is its own contract), and application roles cannot call it.
	for name, tk := range map[string]string{"expired": expired, "stale": stale, "forged": forged} {
		if got := e.adminQuery("SET authz.ctx = '" + tk + "'; SELECT coalesce((authz.ctx_user()).user_id::text, 'null')"); got != "null" {
			t.Errorf("ctx_user accepts a %s context: %q", name, got)
		}
	}
	e.mustFail("app_rw", "SELECT authz.ctx_user()", "permission denied")
	// The scope functions are for the roles that query BU-owned tables:
	// app_posture reaches the authz schema (grant_snapshot) but not them.
	e.mustFail("app_posture", "SELECT authz.scope_hides('register', 'read')", "permission denied for function scope_hides")
	e.mustFail("app_posture", "SELECT authz.scope_excludes('register', 'read')", "permission denied for function scope_excludes")
	for name, tk := range map[string]string{"expired": expired, "stale": stale, "forged": forged, "missing": ""} {
		got, err := e.asCtx(tk, visibleDocs+"; SELECT coalesce(authz.scope_hides('register', 'read')::text, 'null')")
		if err != nil || got != "-\nnull" {
			t.Errorf("%s context: %q %v", name, got, err)
		}
	}

	// A caller who sees every BU: an empty hidden set, every row.
	e.mustOwner(grant("platform", "user:analyst", "Executive Viewer", "R"))
	e.drain()
	tok = e.mint("analyst", ctxKey1)
	if got, _ := e.asCtx(tok, "SELECT authz.scope_hides('register', 'read')::text"); got != "{}" {
		t.Fatalf("hidden set of a caller who sees everything: %q", got)
	}
	if got, _ := e.asCtx(tok, visibleDocs); got != "a,a1,b,n,r,r1" {
		t.Fatalf("a caller who sees everything sees %s", got)
	}
	same("analyst")
}

package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/internal/server"
)

// F-001 T-27 (AC-29, AC-53): separation-of-duties rules block custom roles
// that combine a conflicting pair, unless a second administrator approved a
// time-boxed exception; an expired or revoked exception suspends the role.

type sodEnv struct {
	*idpEnv
	admin2 string // the second Platform Admin's session
	n      int
}

func sodFixture(t *testing.T) *sodEnv {
	t.Helper()
	ie := idpFixture(t)
	return &sodEnv{idpEnv: ie, admin2: ie.login(t, "admin2")}
}

// call sends a state-changing request as cookie's user with a fresh key.
func (se *sodEnv) call(t *testing.T, cookie, method, path string, body any) gwResp {
	t.Helper()
	se.n++
	h := se.csrf(t, cookie)
	h[server.IdempotencyHeader] = "sod-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+se.n%26)) + strings.Repeat("z", se.n/26)
	return se.do(t, method, path, cookie, body, h)
}

// customRole creates a custom role with perms (as the T-28 editor will).
func (se *sodEnv) customRole(name string, perms ...string) error {
	return ownerErr(se.e.owner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('` + name + `') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['` + strings.Join(perms, "','") + `'], 'test' FROM r`))
}

func (se *sodEnv) newVersion(name string, perms ...string) error {
	return ownerErr(se.e.owner(`INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, current_version + 1, ARRAY['` + strings.Join(perms, "','") + `'], 'test' FROM iam.role WHERE name = '` + name + `'`))
}

// ownerErr folds psql's output into the error.
func ownerErr(out string, err error) error {
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func (se *sodEnv) builtinRule() string {
	return se.e.adminQuery("SELECT id FROM iam.sod_rule WHERE builtin")
}

// exception runs the whole flow: request by admin, approval by admin2,
// application by admin. It returns the exception id.
func (se *sodEnv) exception(t *testing.T, role, rule string, expires time.Time) string {
	t.Helper()
	r := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions", map[string]any{"role_id": role, "rule_id": rule,
		"expires_at": expires.UTC().Format(time.RFC3339), "reason": "pilot needs both for a quarter"})
	approval, _ := r.body["approval_id"].(string)
	if r.code != http.StatusAccepted || approval == "" {
		t.Fatalf("request: %d %s", r.code, r.raw)
	}
	if d := se.call(t, se.admin2, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "ok for Q1"}); d.code != 200 {
		t.Fatalf("approve: %d %s", d.code, d.raw)
	}
	a := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions/apply", map[string]any{"approval_id": approval})
	if a.code != 201 {
		t.Fatalf("apply: %d %s", a.code, a.raw)
	}
	return a.body["id"].(string)
}

func TestSoDBlocksCustomRolesUnlessExcepted(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	// AC-29: the built-in rule, over catalog permissions.
	if got := e.adminQuery("SELECT permission_a || '+' || permission_b || ':' || enabled || ':' || (SELECT count(*) FROM iam.permission p WHERE p.key IN (r.permission_a, r.permission_b)) FROM iam.sod_rule r WHERE builtin"); got != "acceptance.approve+analysis.edit:true:2" {
		t.Fatalf("built-in rule %q", got)
	}
	// AC-53: a custom role combining the pair is refused; one side alone is fine.
	if err := se.customRole("Author-Approver", "analysis.edit", "acceptance.approve"); err == nil || !strings.Contains(err.Error(), "separation of duties") {
		t.Fatalf("conflicting custom role: %v", err)
	}
	if err := se.customRole("Editor", "analysis.view", "analysis.edit"); err != nil {
		t.Fatal(err)
	}
	if err := se.newVersion("Editor", "analysis.edit", "acceptance.approve"); err == nil {
		t.Fatal("a conflicting version was saved")
	}
	editor := e.adminQuery("SELECT id FROM iam.role WHERE name = 'Editor'")
	rule := se.builtinRule()

	// The exception flow: requested, refused before approval, never
	// self-approved, approved by a second Platform Admin, applied once.
	r := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions", map[string]any{"role_id": editor, "rule_id": rule,
		"expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339), "reason": "pilot"})
	approval := r.body["approval_id"].(string)
	if r.code != http.StatusAccepted {
		t.Fatalf("request: %d %s", r.code, r.raw)
	}
	if a := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions/apply", map[string]any{"approval_id": approval}); a.code != http.StatusConflict {
		t.Fatalf("apply before approval: %d %s", a.code, a.raw)
	}
	if d := se.call(t, se.admin, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true}); d.code != http.StatusForbidden {
		t.Fatalf("self-approval: %d %s", d.code, d.raw)
	}
	user := se.login(t, "user") // no sod.manage: the request does not exist for them
	if d := se.call(t, user, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true}); d.code != http.StatusNotFound {
		t.Fatalf("approval by someone without sod.manage: %d %s", d.code, d.raw)
	}
	pending := se.do(t, "GET", "/api/v1/approvals?pending=true", se.admin2, nil, nil)
	if pending.code != 200 || !strings.Contains(pending.raw, approval) {
		t.Fatalf("the approver's pending list: %d %s", pending.code, pending.raw)
	}
	if l := se.do(t, "GET", "/api/v1/approvals", user, nil, nil); strings.Contains(l.raw, approval) {
		t.Fatal("an unrelated user sees the request")
	}
	if d := se.call(t, se.admin2, "POST", "/api/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "reason": "Q1 only"}); d.code != 200 {
		t.Fatalf("approval: %d %s", d.code, d.raw)
	}
	a := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions/apply", map[string]any{"approval_id": approval})
	if a.code != 201 {
		t.Fatalf("apply: %d %s", a.code, a.raw)
	}
	if again := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions/apply", map[string]any{"approval_id": approval}); again.code != http.StatusConflict {
		t.Fatalf("applied twice: %d %s", again.code, again.raw)
	}
	// With the exception, the conflicting version saves.
	if err := se.newVersion("Editor", "analysis.edit", "acceptance.approve"); err != nil {
		t.Fatalf("version under an exception: %v", err)
	}
	got := e.adminQuery(`SELECT (payload->'attributes'->>'approved_by') = (SELECT id::text FROM iam.app_user WHERE email = 'admin2@example.test')
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'sod.exception_granted'`)
	if got != "t" {
		t.Fatal("the exception's audit does not name the approver")
	}
	// Bounds: expiry within a year, a custom role, an enabled rule; role.manage.
	for name, body := range map[string]map[string]any{
		"past expiry":     {"role_id": editor, "rule_id": rule, "expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "reason": "x"},
		"beyond a year":   {"role_id": editor, "rule_id": rule, "expires_at": time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339), "reason": "x"},
		"a built-in role": {"role_id": e.adminQuery("SELECT id FROM iam.role WHERE name = 'Approver'"), "rule_id": rule, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "reason": "x"},
	} {
		if r := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions", body); r.code != 400 && r.code != 404 {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := se.call(t, user, "POST", "/api/v1/sod-exceptions", map[string]any{"role_id": editor, "rule_id": rule,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "reason": "x"}); r.code != http.StatusNotFound {
		t.Fatalf("a request without role.view: %d", r.code)
	}
}

func TestSoDExpiryRevocationSuspend(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	if err := se.customRole("Editor", "analysis.edit"); err != nil {
		t.Fatal(err)
	}
	editor := e.adminQuery("SELECT id FROM iam.role WHERE name = 'Editor'")
	rule := se.builtinRule()
	x := se.exception(t, editor, rule, time.Now().Add(24*time.Hour))
	if err := se.newVersion("Editor", "analysis.edit", "acceptance.approve"); err != nil {
		t.Fatal(err)
	}
	e.mustOwner(grant("admin", "user:other", "Editor", "ENTERPRISE"))
	e.drain()
	holds := func() string {
		return e.adminQuery("SELECT iam.user_has_permission(" + uid("other") + ", 'acceptance.approve', " + buID("ENTERPRISE") + ")")
	}
	if holds() != "t" {
		t.Fatal("the excepted role grants nothing")
	}

	// Expiry: the hourly sweep ends the exception and suspends the role,
	// which then grants nothing and takes no new assignments.
	e.mustOwner("UPDATE iam.sod_exception SET created_at = now() - interval '2 days', expires_at = now() - interval '1 minute' WHERE id = '" + x + "'")
	w := scope.New(scope.Options{Pool: e.appPool()})
	if n, err := w.SweepSoD(context.Background()); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got := e.adminQuery("SELECT status FROM iam.role WHERE id = '" + editor + "'"); got != "suspended" {
		t.Fatalf("role after expiry: %s", got)
	}
	if holds() != "f" {
		t.Fatal("a suspended role still grants")
	}
	e.ownerFails(grant("admin", "user:user", "Editor", "ENTERPRISE"), "not assignable")
	if got := e.adminQuery("SELECT count(*) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' IN ('sod.exception_expired', 'role.suspended') AND payload->>'severity' = 'high'"); got != "2" {
		t.Fatalf("%s expiry events", got)
	}
	// A clean version makes it active again.
	if err := se.newVersion("Editor", "analysis.edit"); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT status FROM iam.role WHERE id = '" + editor + "'"); got != "active" {
		t.Fatalf("after a clean version: %s", got)
	}

	// Revocation suspends at once; a new exception restores the role.
	x2 := se.exception(t, editor, rule, time.Now().Add(24*time.Hour))
	if err := se.newVersion("Editor", "analysis.edit", "acceptance.approve"); err != nil {
		t.Fatal(err)
	}
	if r := se.call(t, se.admin, "DELETE", "/api/v1/sod-exceptions/"+x2+"?reason=audit+finding", nil); r.code != 200 || r.body["role_status"] != "suspended" {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	se.exception(t, editor, rule, time.Now().Add(24*time.Hour))
	if got := e.adminQuery("SELECT status FROM iam.role WHERE id = '" + editor + "'"); got != "active" {
		t.Fatalf("after a new exception: %s", got)
	}
	if l := se.do(t, "GET", "/api/v1/sod-exceptions", se.admin, nil, nil); l.code != 200 || len(l.body["exceptions"].([]any)) != 3 {
		t.Fatalf("exceptions: %d %s", l.code, l.raw)
	}
	// The sweep also expires overdue approval requests (T-26).
	pr := se.call(t, se.admin, "POST", "/api/v1/sod-exceptions", map[string]any{"role_id": editor, "rule_id": rule,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "reason": "later"})
	e.mustOwner("UPDATE iam.approval_request SET created_at = now() - interval '4 days', expires_at = now() - interval '1 minute' WHERE id = '" + pr.body["approval_id"].(string) + "'")
	if _, err := w.SweepSoD(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT status FROM iam.approval_request WHERE id = '" + pr.body["approval_id"].(string) + "'"); got != "expired" {
		t.Fatalf("an overdue request: %s", got)
	}
}

func TestSoDRuleManagement(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	if err := se.customRole("Runner", "analysis.edit", "analysis.run"); err != nil {
		t.Fatal(err)
	}
	add := func(cookie, a, b string) gwResp {
		return se.call(t, cookie, "POST", "/api/v1/sod-rules", map[string]any{"permission_a": a, "permission_b": b,
			"description": "maker-checker for simulations", "reason": "audit finding 12"})
	}
	// A rule existing custom roles break is refused, naming them.
	if r := add(se.admin, "analysis.run", "analysis.edit"); r.code != http.StatusConflict || !strings.Contains(r.raw, "Runner") {
		t.Fatalf("a rule Runner breaks: %d %s", r.code, r.raw)
	}
	r := add(se.admin, "register.edit", "treatment.edit")
	if r.code != 201 {
		t.Fatalf("add: %d %s", r.code, r.raw)
	}
	id := r.body["id"].(string)
	if got := e.adminQuery("SELECT permission_a || '+' || permission_b FROM iam.sod_rule WHERE id = '" + id + "'"); got != "register.edit+treatment.edit" {
		t.Fatalf("stored %s", got)
	}
	for name, c := range map[string][2]string{"same permission": {"register.edit", "register.edit"}, "unknown": {"register.edit", "nope.nope"}} {
		if r := add(se.admin, c[0], c[1]); r.code != 400 {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := add(se.admin, "treatment.edit", "register.edit"); r.code != http.StatusConflict {
		t.Fatalf("the same pair again: %d", r.code)
	}
	// The built-in rule stays enabled; others toggle (enabling re-checks).
	if r := se.call(t, se.admin, "PATCH", "/api/v1/sod-rules/"+se.builtinRule(), map[string]any{"enabled": false, "reason": "x"}); r.code != http.StatusConflict {
		t.Fatalf("disable the built-in rule: %d %s", r.code, r.raw)
	}
	if r := se.call(t, se.admin, "PATCH", "/api/v1/sod-rules/"+id, map[string]any{"enabled": false, "reason": "pilot"}); r.code != 204 {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if err := se.customRole("Owner-Treater", "register.edit", "treatment.edit"); err != nil {
		t.Fatalf("a disabled rule still blocks: %v", err)
	}
	if r := se.call(t, se.admin, "PATCH", "/api/v1/sod-rules/"+id, map[string]any{"enabled": true, "reason": "pilot over"}); r.code != http.StatusConflict || !strings.Contains(r.raw, "Owner-Treater") {
		t.Fatalf("enable while broken: %d %s", r.code, r.raw)
	}
	// Disabling a rule reactivates roles suspended only for it.
	e.mustOwner("UPDATE iam.role SET status = 'suspended' WHERE name = 'Owner-Treater'")
	if r := se.call(t, se.admin, "PATCH", "/api/v1/sod-rules/"+id, map[string]any{"enabled": false, "reason": "still off"}); r.code != 204 {
		t.Fatalf("disable again: %d", r.code)
	}
	// Who: role.view to see, sod.manage to change.
	bu := se.login(t, "user")
	if r := se.do(t, "GET", "/api/v1/sod-rules", bu, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without role.view: %d", r.code)
	}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('roles@example.test', 'Roles')")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Role Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['role.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:roles", "Role Viewer", "ENTERPRISE"))
	e.drain()
	viewer := se.login(t, "roles")
	if r := se.do(t, "GET", "/api/v1/sod-rules", viewer, nil, nil); r.code != 200 || len(r.body["rules"].([]any)) != 2 {
		t.Fatalf("viewer list: %d %s", r.code, r.raw)
	}
	if r := add(viewer, "library.edit", "report.view"); r.code != http.StatusForbidden {
		t.Fatalf("add without sod.manage: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT string_agg(payload->>'type', ',' ORDER BY id) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' LIKE 'sod.rule_%'"); got != "sod.rule_created,sod.rule_disabled" {
		t.Fatalf("rule audit %q", got)
	}
}

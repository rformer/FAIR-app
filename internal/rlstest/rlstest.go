// Package rlstest is the reusable RLS negative-test harness (F-001 T-10;
// AC-24, AC-25; ADR-007). Every feature that adds a BU-owned table runs it
// against that table in CI.
//
// Check sets up its own BUs, user, scope row and context key. The user can
// read and write BU "in", only read BU "ro", and has no access to BU "out";
// the Fixture inserts one row in each. Check then reports a Finding for every
// way the table's protection falls short:
//
//   - structure: RLS enabled and forced, exactly the apply_bu_rls policies
//     bound to the table's registered resource type (the four command
//     policies, and bu_rollup: SELECT, for rollup_definer alone, aggregate
//     BUs only; F-001 T-30; bu_guard: SELECT, for bu_guard_definer alone,
//     every row, for the archive guard's count; F-001 T-31), owned by
//     fair_owner, nothing granted to PUBLIC and nothing but SELECT to
//     rollup_definer and bu_guard_definer;
//   - context: missing, malformed, forged, wrong-key, expired, overlong and
//     stale tokens see and change nothing;
//   - writes: write scope, not read scope, governs inserts, updates and
//     deletes, and no row can be moved into a BU the user cannot write;
//   - AC-25: an out-of-scope row is indistinguishable from a missing one;
//   - inherited read (ADR-007 amendment 2; F-003): "in" and "ro" sit under
//     an ancestor BU "anc". A table registered shared_down shows the rows of
//     anc and the root, never writable, and never a sibling's, a restricted
//     BU's from outside, or anything above a restricted BU to a user inside
//     it; any other table shows none of them;
//   - SQL injection: arbitrary SQL run as the application role cannot switch
//     RLS off, change role, read keys or scope, forge context, or get rows out
//     through COPY, TRUNCATE or DDL.
//
// Admin must be a superuser connection (it seeds rows past RLS); App must be
// a pool connected as an application role (app_rw).
package rlstest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/authz"
)

// Fixture tells the harness how to create rows in one BU-owned table.
type Fixture struct {
	Table string // schema-qualified, e.g. "risk.analysis"
	PK    string // primary key column
	// Insert returns SQL that inserts one valid row at the given BU id and
	// RETURNING the primary key as text. It runs as superuser, and again as
	// the application role to check that out-of-scope inserts are refused.
	Insert func(buID string) string
	// Missing is a primary-key literal that matches no row (AC-25 check).
	Missing string
	// Touch is a harmless SET clause for update checks, e.g. "title = title".
	Touch string
}

// Finding is one way the table's protection falls short.
type Finding struct {
	Check  string
	Detail string
}

func (f Finding) String() string { return f.Check + ": " + f.Detail }

// Env holds the connections the harness uses.
type Env struct {
	Admin *pgx.Conn     // superuser
	App   *pgxpool.Pool // application role (app_rw)
}

// bu is one of the harness's BUs and the fixture row in it.
type bu struct {
	name string // "in" (read+write), "ro" (read only), "out" (no access)
	id   string
	pk   string
}

type run struct {
	ctx      context.Context
	env      Env
	fx       Fixture
	rt       string
	shared   bool // registered shared_down (inherited read)
	key      authz.ContextKey
	userID   string
	version  int64
	in       bu
	ro       bu
	out      bu
	tree     map[string]*bu // the inherited-read BUs: anc, root, sib, rst, rkid
	findings []Finding
}

func (r *run) fail(check, format string, args ...any) {
	r.findings = append(r.findings, Finding{Check: check, Detail: fmt.Sprintf(format, args...)})
}

// Check runs every harness check against fx.Table and returns the findings;
// an empty result means the table passed. An error means the harness could
// not set up.
func Check(ctx context.Context, env Env, fx Fixture) ([]Finding, error) {
	r := &run{ctx: ctx, env: env, fx: fx, in: bu{name: "in"}, ro: bu{name: "ro"}, out: bu{name: "out"}}
	if err := r.setup(); err != nil {
		return nil, fmt.Errorf("rlstest %s: setup: %w", fx.Table, err)
	}
	r.structure()
	if !r.control() {
		return r.findings, nil // nothing below is meaningful
	}
	r.badContexts()
	r.writes()
	r.indistinguishable()
	r.inherited()
	r.injection()
	return r.findings, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *run) setup() error {
	a := r.env.Admin
	if err := a.QueryRow(r.ctx, "SELECT resource_type, shared_down FROM iam.bu_owned_tables WHERE table_name = $1::regclass", r.fx.Table).Scan(&r.rt, &r.shared); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		r.fail("registry", "%s is not registered in iam.bu_owned_tables (create it with authz.apply_bu_rls)", r.fx.Table)
		r.rt = "unregistered"
	}
	tag := randHex(4)
	// root, and under it: anc (with in, ro, sib and the restricted rst, with
	// rkid under rst) and out.
	r.tree = map[string]*bu{}
	for _, n := range []string{"root", "anc", "sib", "rst", "rkid"} {
		r.tree[n] = &bu{name: n}
	}
	if err := a.QueryRow(r.ctx, "SELECT id::text FROM iam.bu WHERE parent_id IS NULL").Scan(&r.tree["root"].id); err != nil {
		return err
	}
	for _, c := range []struct {
		b          *bu
		parent     string
		restricted bool
	}{
		{r.tree["anc"], "root", false}, {&r.in, "anc", false}, {&r.ro, "anc", false}, {&r.out, "root", false},
		{r.tree["sib"], "anc", false}, {r.tree["rst"], "anc", true}, {r.tree["rkid"], "rst", false},
	} {
		if err := a.QueryRow(r.ctx, `INSERT INTO iam.bu (name, code, parent_id, restricted)
			VALUES ('rls harness', $1, $2, $3) RETURNING id::text`,
			"RLSH_"+strings.ToUpper(c.b.name)+"_"+tag, r.tree[c.parent].id, c.restricted).Scan(&c.b.id); err != nil {
			return err
		}
	}
	if err := a.QueryRow(r.ctx, "INSERT INTO iam.app_user (email) VALUES ('rlsh-' || $1 || '@harness.test') RETURNING id::text", tag).Scan(&r.userID); err != nil {
		return err
	}
	read := fmt.Sprintf(`{%q: [%q, %q]}`, r.rt, r.in.id, r.ro.id)
	write := fmt.Sprintf(`{%q: [%q]}`, r.rt, r.in.id)
	if err := a.QueryRow(r.ctx, `INSERT INTO authz.user_scope (user_id, scope_version, read_bus, write_bus, rollup_aggregate_bus)
		VALUES ($1, nextval('authz.scope_version_seq'), $2::jsonb, $3::jsonb, '{}') RETURNING scope_version`,
		r.userID, read, write).Scan(&r.version); err != nil {
		return err
	}
	r.key = authz.ContextKey{ID: "rlsh" + tag, Secret: []byte(randHex(32))}
	if _, err := a.Exec(r.ctx, "INSERT INTO authz.ctx_key (key_id, secret) VALUES ($1, $2)", r.key.ID, r.key.Secret); err != nil {
		return err
	}
	for _, b := range []*bu{&r.in, &r.ro, &r.out, r.tree["root"], r.tree["anc"], r.tree["sib"], r.tree["rst"], r.tree["rkid"]} {
		if err := a.QueryRow(r.ctx, r.fx.Insert(b.id)).Scan(&b.pk); err != nil {
			return fmt.Errorf("fixture insert: %w", err)
		}
	}
	return nil
}

// scopeToken creates another harness user whose read and write scope is
// the given BU and returns a context token for it.
func (r *run) scopeToken(buID string) (string, error) {
	tag := randHex(4)
	var user string
	if err := r.env.Admin.QueryRow(r.ctx, "INSERT INTO iam.app_user (email) VALUES ('rlsh-' || $1 || '@harness.test') RETURNING id::text", tag).Scan(&user); err != nil {
		return "", err
	}
	set := fmt.Sprintf(`{%q: [%q]}`, r.rt, buID)
	var version int64
	if err := r.env.Admin.QueryRow(r.ctx, `INSERT INTO authz.user_scope (user_id, scope_version, read_bus, write_bus, rollup_aggregate_bus)
		VALUES ($1, nextval('authz.scope_version_seq'), $2::jsonb, $2::jsonb, '{}') RETURNING scope_version`, user, set).Scan(&version); err != nil {
		return "", err
	}
	return authz.MintDBContext(r.key, user, version, time.Minute, time.Now())
}

func (r *run) token() string {
	t, err := authz.MintDBContext(r.key, r.userID, r.version, time.Minute, time.Now())
	if err != nil {
		panic(err) // the harness's own key and inputs are always valid
	}
	return t
}

// asApp runs fn as the application role in a transaction with authz.ctx set
// to tok (none when tok is nil). The transaction is always rolled back.
func (r *run) asApp(tok *string, fn func(pgx.Tx) error) error {
	tx, err := r.env.App.Begin(r.ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(r.ctx)) }()
	if tok != nil {
		if _, err := tx.Exec(r.ctx, "SELECT set_config('authz.ctx', $1, true)", *tok); err != nil {
			return err
		}
	}
	return fn(tx)
}

// affected runs a write and returns rows affected, or -1 with the error.
func (r *run) affected(tok *string, sql string, args ...any) (int64, error) {
	var n int64 = -1
	err := r.asApp(tok, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.ctx, sql, args...)
		if err == nil {
			n = tag.RowsAffected()
		}
		return err
	})
	return n, err
}

func (r *run) structure() {
	var enabled, forced bool
	var owner string
	if err := r.env.Admin.QueryRow(r.ctx, "SELECT relrowsecurity, relforcerowsecurity, relowner::regrole::text FROM pg_class WHERE oid = $1::regclass",
		r.fx.Table).Scan(&enabled, &forced, &owner); err != nil {
		r.fail("structure", "cannot inspect table: %v", err)
		return
	}
	if !enabled || !forced {
		r.fail("structure", "row-level security enabled=%v forced=%v; both must be true", enabled, forced)
	}
	if owner != "fair_owner" {
		r.fail("structure", "owned by %s; BU-owned tables must be owned by fair_owner", owner)
	}
	want := map[string]string{"bu_select": "r", "bu_insert": "a", "bu_update": "w", "bu_delete": "d", "bu_rollup": "r", "bu_guard": "r"}
	rows, err := r.env.Admin.Query(r.ctx, `SELECT polname, polcmd::text,
		coalesce(pg_get_expr(polqual, polrelid), ''), coalesce(pg_get_expr(polwithcheck, polrelid), ''),
		(SELECT string_agg(CASE WHEN o = 0 THEN 'PUBLIC' ELSE o::regrole::text END, ',' ORDER BY o) FROM unnest(polroles) o)
		FROM pg_policy WHERE polrelid = $1::regclass`, r.fx.Table)
	if err != nil {
		r.fail("structure", "cannot read policies: %v", err)
		return
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name, cmd, qual, check, roles string
		if err := rows.Scan(&name, &cmd, &qual, &check, &roles); err != nil {
			r.fail("structure", "policy scan: %v", err)
			continue
		}
		seen[name] = true
		wantCmd, known := want[name]
		if !known {
			r.fail("structure", "unexpected policy %s (permissive policies are OR-ed and can widen access)", name)
			continue
		}
		if cmd != wantCmd {
			r.fail("structure", "policy %s applies to command %s, want %s", name, cmd, wantCmd)
		}
		if name == "bu_guard" {
			// Every row, for the archive guard's count alone (AC-18).
			if roles != "bu_guard_definer" || qual != "true" || check != "" {
				r.fail("structure", "policy bu_guard (roles %s, %q) must be for bu_guard_definer alone", roles, qual)
			}
			continue
		}
		if name == "bu_rollup" {
			// Aggregate-only rows, for roll-up functions alone (AC-62).
			ref := fmt.Sprintf("rollup_bus('%s'::text)", r.rt)
			if roles != "rollup_definer" || check != "" || !strings.Contains(qual, ref) || !strings.Contains(qual, "'aggregate'::text") {
				r.fail("structure", "policy bu_rollup (roles %s, %q) must be for rollup_definer alone and admit only %s's aggregate BUs", roles, qual, ref)
			}
			continue
		}
		if roles != "PUBLIC" {
			r.fail("structure", "policy %s applies to %s, want every role", name, roles)
		}
		mode := "write"
		if name == "bu_select" {
			mode = "read"
		}
		for _, expr := range []string{qual, check} {
			if name == "bu_select" && r.shared {
				if expr != "" && !inheritedForm(expr, r.rt) {
					r.fail("structure", "policy bu_select expression %q is not the shared-down read form for %s (ADR-007 amendment 2)", expr, r.rt)
				}
				continue
			}
			if expr != "" && !scopeForm(expr, r.rt, mode) {
				r.fail("structure", "policy %s expression %q is not the %s scope form for %s (ADR-007 amendment 1)", name, expr, mode, r.rt)
			}
		}
	}
	rows.Close()
	for name := range want {
		if !seen[name] {
			r.fail("structure", "missing policy %s", name)
		}
	}
	var public bool
	if err := r.env.Admin.QueryRow(r.ctx, `SELECT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a
		WHERE c.oid = $1::regclass AND a.grantee = 0)`, r.fx.Table).Scan(&public); err == nil && public {
		r.fail("structure", "privileges granted to PUBLIC")
	}
	var extra bool
	if err := r.env.Admin.QueryRow(r.ctx, `SELECT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a
		WHERE c.oid = $1::regclass AND a.grantee IN ('rollup_definer'::regrole, 'bu_guard_definer'::regrole) AND a.privilege_type <> 'SELECT')`,
		r.fx.Table).Scan(&extra); err == nil && extra {
		r.fail("structure", "rollup_definer or bu_guard_definer holds more than SELECT")
	}
}

// scopeForm reports whether a policy expression (as pg_get_expr prints it)
// is exactly authz.bu_scope_expr(rt, mode): scope_excludes chooses the
// exclude form over scope_hides or the include form over visible_bus
// (ADR-007 amendment 1).
func scopeForm(expr, rt, mode string) bool {
	return strings.Join(strings.Fields(expr), " ") == scopeExpr(rt, mode)
}

// inheritedForm reports whether a SELECT policy expression is exactly
// authz.bu_inherited_expr(rt): the read scope form, or a BU in
// authz.inherited_bus(rt) (ADR-007 amendment 2).
func inheritedForm(expr, rt string) bool {
	want := fmt.Sprintf("( %s OR (bu_id = ANY (( SELECT authz.inherited_bus('%s'::text) AS inherited_bus)::uuid[])))", scopeExpr(rt, "read"), rt)
	if expr == "" {
		return false
	}
	return strings.Join(strings.Fields(expr), " ") == want
}

func scopeExpr(rt, mode string) string {
	return fmt.Sprintf("CASE WHEN ( SELECT authz.scope_excludes('%[1]s'::text, '%[2]s'::text) AS scope_excludes)"+
		" THEN (bu_id <> ALL (( SELECT authz.scope_hides('%[1]s'::text, '%[2]s'::text) AS scope_hides)::uuid[]))"+
		" ELSE (bu_id = ANY (( SELECT authz.visible_bus('%[1]s'::text, '%[2]s'::text) AS visible_bus)::uuid[])) END", rt, mode)
}

// treeSet returns which of the inherited-read rows (anc, root, sib, rst,
// rkid) the context can see, in that order.
func (r *run) treeSet(tok *string) (string, error) {
	var got []string
	err := r.asApp(tok, func(tx pgx.Tx) error {
		for _, n := range []string{"anc", "root", "sib", "rst", "rkid"} {
			var c int
			if err := tx.QueryRow(r.ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s::text = $1", r.fx.Table, r.fx.PK), r.tree[n].pk).Scan(&c); err != nil {
				return err
			}
			if c > 0 {
				got = append(got, n)
			}
		}
		return nil
	})
	return strings.Join(got, ","), err
}

// inherited checks the inherited read of shared-down tables, and its
// absence everywhere else.
func (r *run) inherited() {
	want := func(shared string) string {
		if r.shared {
			return shared
		}
		return ""
	}
	tok := r.token()
	if got, err := r.treeSet(&tok); err != nil || got != want("anc,root") {
		r.fail("inherited", "a user at in and ro sees [%s] (err=%v); want [%s]: ancestors only, no sibling, no restricted BU", got, err, want("anc,root"))
	}
	// Inherited rows are never writable.
	anc := r.tree["anc"]
	for op, q := range map[string]string{
		"update": fmt.Sprintf("UPDATE %s SET %s WHERE %s::text = $1", r.fx.Table, r.fx.Touch, r.fx.PK),
		"delete": fmt.Sprintf("DELETE FROM %s WHERE %s::text = $1", r.fx.Table, r.fx.PK),
	} {
		if n, err := r.affected(&tok, q, anc.pk); err != nil || n != 0 {
			r.fail("inherited", "%s of an inherited row: affected=%d err=%v; want 0", op, n, err)
		}
	}
	if _, err := r.affected(&tok, r.fx.Insert(anc.id)); !isRLSViolation(err) {
		r.fail("inherited", "inserting into an ancestor BU: err=%v; want an RLS violation", err)
	}
	if n, err := r.affected(&tok, fmt.Sprintf("UPDATE %s SET bu_id = $1 WHERE %s::text = $2", r.fx.Table, r.fx.PK), anc.id, r.in.pk); !isRLSViolation(err) {
		r.fail("inherited", "moving a writable row into an ancestor BU: affected=%d err=%v; want an RLS violation", n, err)
	}
	// Inside a restricted subtree: rkid inherits rst and nothing above it;
	// rst itself inherits nothing.
	for _, c := range []struct{ user, want string }{{"rkid", want("rst")}, {"rst", ""}} {
		t, err := r.scopeToken(r.tree[c.user].id)
		if err != nil {
			r.fail("inherited", "setting up a user at %s: %v", c.user, err)
			continue
		}
		got, err := r.treeSet(&t)
		// The user's own row is visible through the scope form.
		got = strings.Trim(strings.ReplaceAll(","+got+",", ","+c.user+",", ","), ",")
		if err != nil || got != c.want {
			r.fail("inherited", "a user at %s sees [%s] besides its own row (err=%v); want [%s]", c.user, got, err, c.want)
		}
	}
	// No context, no inherited rows.
	for name, bad := range r.badTokens() {
		if got, err := r.treeSet(bad); err != nil || got != "" {
			r.fail("inherited", "context %s sees [%s] (err=%v); want none", name, got, err)
		}
	}
}

// visibleSet returns which of the harness rows the context can see, e.g. "in,ro".
func (r *run) visibleSet(tok *string) (string, error) {
	var got []string
	err := r.asApp(tok, func(tx pgx.Tx) error {
		for _, b := range []bu{r.in, r.ro, r.out} {
			var n int
			if err := tx.QueryRow(r.ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s::text = $1", r.fx.Table, r.fx.PK), b.pk).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				got = append(got, b.name)
			}
		}
		return nil
	})
	return strings.Join(got, ","), err
}

func (r *run) control() bool {
	tok := r.token()
	got, err := r.visibleSet(&tok)
	switch {
	case err != nil:
		r.fail("control", "valid context query failed: %v", err)
		return false
	case got != "in,ro":
		r.fail("control", "valid context sees rows [%s], want [in,ro]", got)
		return false
	}
	return true
}

func (r *run) sign(body string) string {
	mac := hmac.New(sha256.New, r.key.Secret)
	mac.Write([]byte(body))
	return body + "." + hex.EncodeToString(mac.Sum(nil))
}

// badTokens returns every invalid context the harness tries.
func (r *run) badTokens() map[string]*string {
	good := r.token()
	parts := strings.Split(good, ".")
	with := func(i int, v string) string {
		p := append([]string(nil), parts[:6]...)
		p[i] = v
		return r.sign(strings.Join(p, "."))
	}
	now := time.Now().Unix()
	s := func(v string) *string { return &v }
	last := "0"
	if strings.HasSuffix(good, "0") {
		last = "1"
	}
	otherSig, _ := authz.MintDBContext(authz.ContextKey{ID: r.key.ID, Secret: []byte(randHex(32))}, r.userID, r.version, time.Minute, time.Now())
	return map[string]*string{
		"missing":            nil,
		"empty":              s(""),
		"garbage":            s("garbage"),
		"wrong format":       s(strings.Replace(good, "v1.", "v2.", 1)),
		"tampered signature": s(good[:len(good)-1] + last),
		"wrong secret":       s(otherSig),
		"unknown key id":     s(with(1, "nosuchkey")),
		"other user":         s(with(2, "00000000-0000-0000-0000-000000000000")),
		"stale version":      s(with(3, strconv.FormatInt(r.version-1, 10))),
		"future version":     s(with(3, strconv.FormatInt(r.version+1, 10))),
		"expired":            s(with(4, strconv.FormatInt(now-1, 10))),
		"overlong lifetime":  s(with(4, strconv.FormatInt(now+24*3600, 10))),
		"quote injection":    s(good + "' OR '1'='1"),
	}
}

func (r *run) badContexts() {
	in := fmt.Sprintf("%s::text IN ($1, $2, $3)", r.fx.PK)
	pks := []any{r.in.pk, r.ro.pk, r.out.pk}
	for name, tok := range r.badTokens() {
		if got, err := r.visibleSet(tok); err != nil || got != "" {
			r.fail("context:"+name, "sees rows [%s] (err=%v); want none", got, err)
		}
		if n, err := r.affected(tok, fmt.Sprintf("UPDATE %s SET %s WHERE %s", r.fx.Table, r.fx.Touch, in), pks...); n > 0 {
			r.fail("context:"+name, "update affected %d rows (err=%v)", n, err)
		}
		if n, err := r.affected(tok, fmt.Sprintf("DELETE FROM %s WHERE %s", r.fx.Table, in), pks...); n > 0 {
			r.fail("context:"+name, "delete affected %d rows (err=%v)", n, err)
		}
		if _, err := r.affected(tok, r.fx.Insert(r.in.id)); err == nil {
			r.fail("context:"+name, "insert succeeded")
		}
	}
}

func isRLSViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "row-level security")
}

// writes checks that write scope, not read scope, governs every write.
func (r *run) writes() {
	tok := r.token()
	move := fmt.Sprintf("UPDATE %s SET bu_id = $1 WHERE %s::text = $2", r.fx.Table, r.fx.PK)
	touch := fmt.Sprintf("UPDATE %s SET %s WHERE %s::text = $1", r.fx.Table, r.fx.Touch, r.fx.PK)
	del := fmt.Sprintf("DELETE FROM %s WHERE %s::text = $1", r.fx.Table, r.fx.PK)

	for _, target := range []bu{r.ro, r.out} {
		if n, err := r.affected(&tok, move, target.id, r.in.pk); !isRLSViolation(err) {
			r.fail("writes", "moving a writable row into the %s BU: affected=%d err=%v; want an RLS violation", target.name, n, err)
		}
		if _, err := r.affected(&tok, r.fx.Insert(target.id)); !isRLSViolation(err) {
			r.fail("writes", "inserting into the %s BU: err=%v; want an RLS violation", target.name, err)
		}
		for op, q := range map[string]string{"update": touch, "delete": del} {
			if n, err := r.affected(&tok, q, target.pk); err != nil || n != 0 {
				r.fail("writes", "%s of the %s row: affected=%d err=%v; want 0", op, target.name, n, err)
			}
		}
	}
	if n, err := r.affected(&tok, touch, r.in.pk); err != nil || n != 1 {
		r.fail("writes", "updating the writable row: affected=%d err=%v; want 1", n, err)
	}
	if _, err := r.affected(&tok, r.fx.Insert(r.in.id)); err != nil {
		r.fail("writes", "inserting into the writable BU: %v", err)
	}
}

// AC-25: with a valid context, an out-of-scope row and a missing row look
// the same for reads and writes.
func (r *run) indistinguishable() {
	tok := r.token()
	for _, op := range []struct{ name, sql string }{
		{"select", "SELECT count(*) FROM %s WHERE %s::text = $1"},
		{"update", "UPDATE %s SET " + r.fx.Touch + " WHERE %s::text = $1"},
		{"delete", "DELETE FROM %s WHERE %s::text = $1"},
	} {
		q := fmt.Sprintf(op.sql, r.fx.Table, r.fx.PK)
		res := func(pk string) string {
			if op.name == "select" {
				var n int
				err := r.asApp(&tok, func(tx pgx.Tx) error { return tx.QueryRow(r.ctx, q, pk).Scan(&n) })
				return fmt.Sprintf("%d/%v", n, err)
			}
			n, err := r.affected(&tok, q, pk)
			return fmt.Sprintf("%d/%v", n, err)
		}
		if out, missing := res(r.out.pk), res(r.fx.Missing); out != missing {
			r.fail("AC-25", "%s: out-of-scope row gives %s, missing row gives %s", op.name, out, missing)
		}
	}
}

// injection simulates an attacker who can run arbitrary SQL as the
// application role (SQL injection or a compromised service) without a valid
// context. Each statement must fail or reveal nothing.
func (r *run) injection() {
	t := r.fx.Table
	// Well-formed and current, but with a signature the attacker cannot compute.
	forged := strings.Join([]string{"v1", r.key.ID, r.userID, strconv.FormatInt(r.version, 10),
		strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10), "00", strings.Repeat("0", 64)}, ".")
	mustFail := []string{
		"SET row_security = off; SELECT count(*) FROM " + t,
		"SET ROLE fair_owner",
		"SET ROLE authz_definer",
		"SET SESSION AUTHORIZATION postgres",
		"SELECT count(*) FROM authz.ctx_key",
		"SELECT count(*) FROM authz.user_scope",
		"SELECT authz.ctx_scope()",
		"ALTER TABLE " + t + " DISABLE ROW LEVEL SECURITY",
		"ALTER TABLE " + t + " NO FORCE ROW LEVEL SECURITY",
		"DROP POLICY bu_select ON " + t,
		"CREATE POLICY open ON " + t + " USING (true)",
		"CREATE FUNCTION public.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
		"CREATE TEMP TABLE leak AS SELECT * FROM " + t,
		"TRUNCATE " + t,
		"INSERT INTO authz.ctx_key VALUES ('evil', decode(repeat('00', 32), 'hex'))",
		"UPDATE authz.user_scope SET read_bus = '{}'",
	}
	for _, sql := range mustFail {
		if err := r.asApp(nil, func(tx pgx.Tx) error {
			_, err := tx.Exec(r.ctx, sql)
			return err
		}); err == nil {
			r.fail("injection", "%q succeeded as the application role", sql)
		}
	}
	reveal := []string{
		fmt.Sprintf("SELECT count(*) FROM %s WHERE %s::text = '' OR 1 = 1", t, r.fx.PK),
		fmt.Sprintf("SELECT count(*) FROM (SELECT * FROM %s UNION ALL SELECT * FROM %s) x", t, t),
		fmt.Sprintf("SELECT count(*) FROM %s, (SELECT set_config('authz.ctx', '%s', false)) s", t, forged),
		fmt.Sprintf("WITH c AS (SELECT set_config('authz.ctx', '%s', true)) SELECT count(*) FROM c, %s", forged, t),
		fmt.Sprintf("SELECT cardinality(authz.visible_bus('%s', 'read')) + cardinality(authz.visible_bus('%s', 'write'))", r.rt, r.rt),
	}
	for _, sql := range reveal {
		var n int
		err := r.asApp(nil, func(tx pgx.Tx) error { return tx.QueryRow(r.ctx, sql).Scan(&n) })
		if err == nil && n != 0 {
			r.fail("injection", "%q revealed %d", sql, n)
		}
	}
	// COPY TO is filtered by the SELECT policy (PostgreSQL), so it must copy nothing.
	err := r.asApp(nil, func(tx pgx.Tx) error {
		var buf bytes.Buffer
		tag, err := tx.Conn().PgConn().CopyTo(r.ctx, &buf, "COPY "+t+" TO STDOUT")
		if err == nil && tag.RowsAffected() != 0 {
			r.fail("injection", "COPY TO STDOUT copied %d rows", tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		r.fail("injection", "COPY check: %v", err)
	}
}

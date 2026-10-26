// Package rlstest is the reusable RLS negative-test harness (F-001 T-10;
// AC-24, AC-25; ADR-007). Every feature that adds a BU-owned table runs it
// against that table in CI.
//
// Check sets up its own BUs, user, scope row and context key. The user can
// read and write BU "in", only read BU "ro", and has no access to BU "out";
// the Fixture inserts one row in each. Check then reports a Finding for every
// way the table's protection falls short:
//
//   - structure: RLS enabled and forced, exactly the four apply_bu_rls
//     policies bound to the table's registered resource type, owned by
//     fair_owner, nothing granted to PUBLIC;
//   - context: missing, malformed, forged, wrong-key, expired, overlong and
//     stale tokens see and change nothing;
//   - writes: write scope, not read scope, governs inserts, updates and
//     deletes, and no row can be moved into a BU the user cannot write;
//   - AC-25: an out-of-scope row is indistinguishable from a missing one;
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
	key      authz.ContextKey
	userID   string
	version  int64
	in       bu
	ro       bu
	out      bu
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
	if err := a.QueryRow(r.ctx, "SELECT resource_type FROM iam.bu_owned_tables WHERE table_name = $1::regclass", r.fx.Table).Scan(&r.rt); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		r.fail("registry", "%s is not registered in iam.bu_owned_tables (create it with authz.apply_bu_rls)", r.fx.Table)
		r.rt = "unregistered"
	}
	tag := randHex(4)
	for _, b := range []*bu{&r.in, &r.ro, &r.out} {
		if err := a.QueryRow(r.ctx, `INSERT INTO iam.bu (name, code, parent_id, restricted)
			SELECT 'rls harness', $1, id, false FROM iam.bu WHERE parent_id IS NULL RETURNING id::text`,
			"RLSH_"+strings.ToUpper(b.name)+"_"+tag).Scan(&b.id); err != nil {
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
	for _, b := range []*bu{&r.in, &r.ro, &r.out} {
		if err := a.QueryRow(r.ctx, r.fx.Insert(b.id)).Scan(&b.pk); err != nil {
			return fmt.Errorf("fixture insert: %w", err)
		}
	}
	return nil
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
	want := map[string]string{"bu_select": "r", "bu_insert": "a", "bu_update": "w", "bu_delete": "d"}
	rows, err := r.env.Admin.Query(r.ctx, `SELECT polname, polcmd::text,
		coalesce(pg_get_expr(polqual, polrelid), ''), coalesce(pg_get_expr(polwithcheck, polrelid), '')
		FROM pg_policy WHERE polrelid = $1::regclass`, r.fx.Table)
	if err != nil {
		r.fail("structure", "cannot read policies: %v", err)
		return
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name, cmd, qual, check string
		if err := rows.Scan(&name, &cmd, &qual, &check); err != nil {
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
		mode := "write"
		if name == "bu_select" {
			mode = "read"
		}
		ref := fmt.Sprintf("visible_bus('%s'::text, '%s'::text)", r.rt, mode)
		for _, expr := range []string{qual, check} {
			if expr != "" && !strings.Contains(expr, ref) {
				r.fail("structure", "policy %s expression %q does not use %s", name, expr, ref)
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

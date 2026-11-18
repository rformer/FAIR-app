package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/pkg/authz"
)

// rolePool is a pool as the given login role.
func rolePool(t *testing.T, e *env, role string) *pgxpool.Pool {
	t.Helper()
	cc, err := dbconn.Config("development", role, e.secrets[role], "fair-test")
	if err != nil {
		t.Fatal(err)
	}
	cc.Database = e.db
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig = cc
	p, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// pgState is err's SQLSTATE and hint ("ok" without an error).
func pgState(err error) string {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &pg) && pg.Hint != "":
		return pg.Code + "/" + pg.Hint
	case errors.As(err, &pg):
		return pg.Code
	}
	return err.Error()
}

// integrationFixture: the assignment fixture (ENTERPRISE -> {A -> {A1, R
// (restricted) -> R1}, B}) with "platform" (Platform Admin at the root:
// integration.manage and view), "aud" (Auditor at the root: view), "rman"
// (integration.manage and view inside R), "mallory" (Directory Reader at B:
// neither), and service accounts "sa-root"
// at the root and "sa-b" at B.
type integrationEnv struct {
	*env
	pool *pgxpool.Pool // app_integrate
}

func integrationFixture(t *testing.T) *integrationEnv {
	t.Helper()
	e := assignmentFixture(t)
	e.addCtxKey(ctxKey1)
	for _, u := range []string{"aud", "rman"} {
		e.mustOwner(fmt.Sprintf("INSERT INTO iam.app_user (email, display_name) VALUES ('%s@example.test', '%s')", u, u))
	}
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Integration Manager') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['integration.manage', 'integration.view'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:rman", "Integration Manager", "R"))
	e.mustOwner(grant("platform", "user:mallory", "Directory Reader", "B")) // a context, no integration permission
	for _, sa := range [][2]string{{"sa-root", "ENTERPRISE"}, {"sa-b", "B"}} {
		e.mustOwner(fmt.Sprintf(`WITH u AS (INSERT INTO iam.app_user (email, display_name, source) VALUES ('%[1]s@service.invalid', '%[1]s', 'service') RETURNING id),
			r AS (INSERT INTO iam.role (name) VALUES ('sa role %[1]s') RETURNING id)
			INSERT INTO iam.service_account (id, name, bu_id, role_id, auth_method, created_by)
			SELECT u.id, '%[1]s', %[2]s, r.id, 'client_credentials', %[3]s FROM u, r`, sa[0], buID(sa[1]), uid("platform")))
	}
	e.drain()
	return &integrationEnv{env: e, pool: rolePool(t, e, "app_integrate")}
}

// as runs fn as app_integrate for user.
func (f *integrationEnv) as(user string, fn func(tx pgx.Tx) error) error {
	return authz.WithDBContext(context.Background(), f.pool, f.principal(user).DBToken, fn)
}

func (f *integrationEnv) create(user, bu, name, delivery, connector, sa string) (string, error) {
	var id string
	err := f.as(user, func(tx pgx.Tx) error {
		var c, s any
		if connector != "" {
			c = connector
		}
		if sa != "" {
			s = f.adminQuery("SELECT id FROM iam.service_account WHERE name = '" + sa + "'")
		}
		return tx.QueryRow(context.Background(), "SELECT integration.add($1, $2, 'assets', $3, '{}', $4::jsonb, $5, false)::text",
			f.adminQuery("SELECT id FROM iam.bu WHERE code = '"+bu+"'"), name, delivery, c, s).Scan(&id)
	})
	return id, err
}

func (f *integrationEnv) exec(user, sql string, args ...any) error {
	return f.as(user, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
}

func (f *integrationEnv) get(user, id string) (map[string]any, error) {
	var raw []byte
	err := f.as(user, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT integration.get($1)", id).Scan(&raw)
	})
	var m map[string]any
	if err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m, err
}

func (f *integrationEnv) list(user string, deleted bool) []string {
	var names []string
	if err := f.as(user, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT x ->> 'name' FROM integration.list($1) x", deleted)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			names = append(names, n)
		}
		return rows.Err()
	}); err != nil {
		f.t.Fatal(err)
	}
	return names
}

const okConnector = `{"type": "http_json", "source": "https://cmdb.example.com/api/assets", "schedule_minutes": 60, "settings": {"list": "/items"}}`

// F-011 T-07 (F-011-AC-01 to AC-03, AC-05, AC-26; design §3.1, §5).
func TestIntegrations(t *testing.T) {
	f := integrationFixture(t)
	events := func(typ, id string) string {
		return f.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' = 'integration:" + id + "'")
	}

	// Who may create (AC-01, AC-02): manage at the BU; view only, 42501;
	// neither, or above a restricted BU, as if the BU did not exist.
	push, err := f.create("platform", "A", "CMDB push", "push", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if events("integration.created", push) != "1" {
		t.Error("no integration.created")
	}
	for _, c := range []struct{ user, bu, want string }{
		{"aud", "A", "42501/forbidden"},
		{"mallory", "A", "P0002"},
		{"platform", "R", "P0002"}, // the root's grant does not reach R
		{"platform", "R1", "P0002"},
	} {
		if _, err := f.create(c.user, c.bu, "x-"+c.user+c.bu, "push", "", ""); pgState(err) != c.want {
			t.Errorf("%s at %s: %s, want %s", c.user, c.bu, pgState(err), c.want)
		}
	}
	inR, err := f.create("rman", "R1", "Case CMDB", "push", "", "")
	if err != nil {
		t.Fatalf("rman inside R: %v", err)
	}

	// Connectors: settings checked; a service account at the BU or above.
	for name, c := range map[string]struct{ connector, sa string }{
		"no service account":     {okConnector, ""},
		"an http source":         {strings.Replace(okConnector, "https://", "http://", 1), "sa-root"},
		"a user in the URL":      {strings.Replace(okConnector, "https://", "https://u:p@", 1), "sa-root"},
		"every 5 minutes":        {strings.Replace(okConnector, `"schedule_minutes": 60`, `"schedule_minutes": 5`, 1), "sa-root"},
		"an unknown type":        {strings.Replace(okConnector, "http_json", "ftp", 1), "sa-root"},
		"an unknown setting":     {strings.Replace(okConnector, `"settings"`, `"script"`, 1), "sa-root"},
		"a service account at B": {okConnector, "sa-b"},
	} {
		if _, err := f.create("platform", "A", "c-"+name, "connector", c.connector, c.sa); !strings.HasPrefix(pgState(err), "PF031") {
			t.Errorf("%s: %s", name, pgState(err))
		}
	}
	if _, err := f.create("platform", "A", "push with settings", "push", okConnector, ""); !strings.HasPrefix(pgState(err), "PF031") {
		t.Errorf("a push integration with connector settings: %s", pgState(err))
	}
	conn, err := f.create("platform", "A", "CMDB connector", "connector", okConnector, "sa-root")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.adminQuery("SELECT next_run_at IS NOT NULL FROM integration.integration WHERE id = '" + conn + "'"); got != "t" {
		t.Error("a new connector is not due")
	}

	// Reading: view or manage at the BU; restricted ones only inside.
	if _, err := f.get("aud", conn); err != nil {
		t.Errorf("aud reads: %v", err)
	}
	if _, err := f.get("mallory", conn); pgState(err) != "P0002" {
		t.Errorf("mallory reads: %s", pgState(err))
	}
	if _, err := f.get("aud", inR); pgState(err) != "P0002" {
		t.Errorf("aud reads inside R: %s", pgState(err))
	}
	if got := strings.Join(f.list("aud", false), ","); got != "CMDB connector,CMDB push" {
		t.Errorf("aud's list: %s", got)
	}
	if got := strings.Join(f.list("rman", false), ","); got != "Case CMDB" {
		t.Errorf("rman's list: %s", got)
	}

	// Changes: expected_version; kind, BU and delivery fixed by the schema.
	change := func(user, id string, version int, name string) error {
		return f.exec(user, "SELECT integration.change($1, $2, $3, '{}', $4::jsonb, $5, true)", id, version, name, okConnector,
			f.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-root'"))
	}
	if err := change("platform", conn, 9, "CMDB"); pgState(err) != "PF031/stale_version" {
		t.Errorf("a stale change: %s", pgState(err))
	}
	if err := change("aud", conn, 1, "CMDB"); pgState(err) != "42501/forbidden" {
		t.Errorf("aud changes: %s", pgState(err))
	}
	if err := change("platform", conn, 1, "CMDB"); err != nil {
		t.Fatal(err)
	}
	if got := f.adminQuery("SELECT body #>> '{attributes,changes}' FROM audit.intake WHERE body ->> 'type' = 'integration.changed' AND body ->> 'target' = 'integration:" + conn + "'"); got != "name,auto_accept" {
		t.Errorf("changes recorded: %q", got)
	}

	// Credentials (AC-03): connectors only; never returned; the runner's
	// function is app_integrate's alone.
	setSecret := func(user, id, purpose string) error {
		return f.exec(user, "SELECT integration.set_secret($1, $2, 'isk-1', $3, $4)", id, purpose, []byte("123456789012"), []byte("sealed-ciphertext-bytes"))
	}
	if err := setSecret("platform", push, "source"); !strings.HasPrefix(pgState(err), "PF031") {
		t.Errorf("a credential for a push integration: %s", pgState(err))
	}
	if err := setSecret("aud", conn, "source"); pgState(err) != "42501/forbidden" {
		t.Errorf("aud sets a credential: %s", pgState(err))
	}
	for _, p := range []string{"source", "client"} {
		if err := setSecret("platform", conn, p); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := f.get("aud", conn)
	raw, _ := json.Marshal(got)
	if creds, _ := got["credentials"].([]any); len(creds) != 2 || strings.Contains(string(raw), "c2VhbGVk") || strings.Contains(string(raw), "sealed") {
		t.Errorf("get shows: %s", raw)
	}
	if events("integration.credential_set", conn) != "2" {
		t.Error("credential events")
	}
	if out, err := f.env.as("app_rw", "SELECT count(*) FROM integration.secret_for_run('"+conn+"', 'source')"); err == nil {
		t.Errorf("app_rw reads a sealed credential: %s", out)
	}
	if out, err := f.env.as("app_integrate", "SELECT encode(ciphertext, 'escape') FROM integration.secret_for_run('"+conn+"', 'source')"); err != nil || out != "sealed-ciphertext-bytes" {
		t.Errorf("the runner's credential: %q %v", out, err)
	}
	if err := f.exec("platform", "SELECT integration.remove_secret($1, 'client')", conn); err != nil {
		t.Fatal(err)
	}
	if err := f.exec("platform", "SELECT integration.remove_secret($1, 'client')", conn); pgState(err) != "P0002" {
		t.Errorf("removing it twice: %s", pgState(err))
	}

	// Pause and resume (AC-05): a paused connector is not due and its
	// credential is not handed to the runner.
	if err := f.exec("platform", "SELECT integration.pause($1)", conn); err != nil {
		t.Fatal(err)
	}
	if err := f.exec("platform", "SELECT integration.pause($1)", conn); pgState(err) != "PF031/invalid_state" {
		t.Errorf("pausing twice: %s", pgState(err))
	}
	if out, _ := f.env.as("app_integrate", "SELECT count(*) FROM integration.secret_for_run('"+conn+"', 'source')"); out != "0" {
		t.Errorf("a paused integration's credential: %s", out)
	}
	if err := f.exec("platform", "SELECT integration.resume($1)", conn); err != nil {
		t.Fatal(err)
	}
	if f.adminQuery("SELECT state || ':' || (next_run_at IS NOT NULL) FROM integration.integration WHERE id = '"+conn+"'") != "active:true" {
		t.Error("not resumed")
	}

	// Delete (AC-05): a reason; credentials removed; kept for provenance.
	if err := f.exec("platform", "SELECT integration.remove($1, '')", conn); pgState(err) != "PF031/reason_required" {
		t.Errorf("deleting without a reason: %s", pgState(err))
	}
	if err := f.exec("platform", "SELECT integration.remove($1, 'replaced by the vendor feed')", conn); err != nil {
		t.Fatal(err)
	}
	if n := f.adminQuery("SELECT count(*) FROM integration.secret WHERE integration_id = '" + conn + "'"); n != "0" {
		t.Errorf("%s credentials left", n)
	}
	if err := change("platform", conn, 3, "again"); pgState(err) != "PF031/integration_deleted" {
		t.Errorf("changing a deleted integration: %s", pgState(err))
	}
	if got := strings.Join(f.list("platform", false), ","); got != "CMDB push" {
		t.Errorf("list without deleted: %s", got)
	}
	if got := strings.Join(f.list("platform", true), ","); got != "CMDB,CMDB push" {
		t.Errorf("list with deleted: %s", got)
	}
	for _, typ := range []string{"integration.paused", "integration.resumed", "integration.deleted", "integration.credential_removed"} {
		if events(typ, conn) != "1" {
			t.Errorf("%s: %s", typ, events(typ, conn))
		}
	}
	// Events carry the BU.
	if got := f.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'target' = 'integration:" + conn + "' AND (body ->> 'bu_id') IS DISTINCT FROM (SELECT id::text FROM iam.bu WHERE code = 'A')"); got != "0" {
		t.Errorf("%s events without the BU", got)
	}

	// Only the integrate service calls the writes.
	if out, err := f.env.as("app_rw", "SELECT integration.pause('"+push+"')"); err == nil {
		t.Errorf("app_rw pauses: %s", out)
	}
}

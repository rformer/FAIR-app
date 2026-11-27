package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/install"
	"github.com/rformer/fair-app/internal/server"
)

// installer connects as app_migrator, as fairctl does.
func installer(t *testing.T, e *env) *pgx.Conn {
	t.Helper()
	c, err := pgx.ConnectConfig(context.Background(), migratorConfig(t, e))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

const testInstallation = "8f1d2c3b-4a5e-4f60-9a7b-0c1d2e3f4a5b"

// F-014 T-05 (F-014-AC-09, AC-12, AC-13, AC-34; design §5): the install
// records are the definer's alone; the installation is recorded once (the
// same again is a resume); state moves follow the allowed moves; decisions
// are append-only with one value each; release records finish once;
// preflight runs and reports are kept as recorded, never with a secret; the
// install log's events reach the trail with their original ids and times,
// once however often they are replayed.
func TestInstallRecords(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, role := range []string{"app_rw", "app_posture", "app_gateway", "app_audit", "app_notify", "app_integrate", "app_migrator"} {
		for _, tbl := range []string{"installation", "decision", "release", "preflight", "report"} {
			if got := e.adminState("SET ROLE " + role + "; PERFORM count(*) FROM install." + tbl); got != "42501" {
				t.Errorf("%s reads install.%s: %s", role, tbl, got)
			}
		}
	}
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		if got := e.adminState("SET ROLE " + role + "; PERFORM install.set_state('closed', 'x', 'eve')"); got != "42501" {
			t.Errorf("%s moves the state: %s", role, got)
		}
	}
	for _, role := range []string{"app_rw", "app_gateway", "app_audit"} {
		if got := e.adminState("SET ROLE " + role + "; PERFORM install.status()"); got != "42501" {
			t.Errorf("%s reads the status: %s", role, got)
		}
	}

	c := installer(t, e)
	q := func(sql string, args ...any) string {
		t.Helper()
		var s string
		if err := c.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			return pgState(err)
		}
		return s
	}
	if got := q("SELECT install.state()"); got != "open" {
		t.Fatalf("before an installation: %s", got)
	}
	if got := q("SELECT install.record_installation($1, 'acme', 'self-hosted', 'Ops Olga')", testInstallation); got != "installing" {
		t.Fatalf("record: %s", got)
	}
	if got := q("SELECT install.record_installation($1, 'acme', 'self-hosted', 'Ops Olga')", testInstallation); got != "installing" {
		t.Errorf("resume: %s", got)
	}
	if got := q("SELECT install.record_installation($1, 'acme', 'air-gapped', 'Ops Olga')", testInstallation); got != "PF035/installed" {
		t.Errorf("another mode: %s", got)
	}
	if got := q("SELECT install.record_installation(gen_random_uuid(), 'acme', 'self-hosted', 'Ops Olga')"); got != "PF035/installed" {
		t.Errorf("another installation: %s", got)
	}

	// Decisions: one value each.
	if got := q(`SELECT install.record_decision('profile', '"fedramp-moderate"', false, NULL, 'Ops Olga')::text`); got != "true" {
		t.Fatalf("decide: %s", got)
	}
	if got := q(`SELECT install.record_decision('profile', '"fedramp-moderate"', false, NULL, 'Ops Olga')::text`); got != "false" {
		t.Errorf("the same again: %s", got)
	}
	if got := q(`SELECT install.record_decision('profile', '"enterprise-baseline"', false, NULL, 'Ops Olga')::text`); got != "PF035/decided" {
		t.Errorf("another value: %s", got)
	}
	if got := q(`SELECT install.record_decision('storage.encryption', '{"class":"gp3"}', true, 'the storage team''s statement', 'Ops Olga')::text`); got != "true" {
		t.Fatalf("attest: %s", got)
	}
	if got := q(`SELECT install.record_decision('database', '{"auth":"Bearer abcdefghijklmnopqrstuvwx"}', false, NULL, 'Ops Olga')::text`); got != "PF035/secret" {
		t.Errorf("a secret-looking decision: %s", got)
	}
	if got := e.adminQuery(`SELECT string_agg((body->>'target') || ':' || (body->'attributes'->>'attested') || ':' || (body->>'actor'), ',' ORDER BY id)
		FROM audit.intake WHERE body->>'type' = 'install.decision_recorded'`); got != "install_decision:profile:false:operator:Ops Olga,install_decision:storage.encryption:true:operator:Ops Olga" {
		t.Errorf("decision events: %s", got)
	}
	for name, sql := range map[string]string{
		"a decision changed":       "UPDATE install.decision SET value = '\"x\"'",
		"a decision deleted":       "DELETE FROM install.decision",
		"decisions truncated":      "TRUNCATE install.decision",
		"the identity changed":     "UPDATE install.installation SET mode = 'saas'",
		"a state skipped":          "UPDATE install.installation SET state = 'upgrading'", // installing -> upgrading
		"the installation removed": "DELETE FROM install.installation",
	} {
		if got := e.adminState(sql); !strings.HasPrefix(got, "PF035") {
			t.Errorf("%s (owner): %s", name, got)
		}
	}

	// State moves.
	for _, c := range []struct{ to, want string }{
		{"upgrading", "PF035/state_move"}, {"open", "open"}, {"upgrading", "upgrading"}, {"installing", "PF035/state_move"},
		{"open", "open"}, {"restoring", "restoring"}, {"closed", "closed"}, {"open", "open"}, {"open", "open"},
	} {
		if got := q("SELECT install.set_state($1, 'drill', 'Ops Olga')", c.to); got != c.want {
			t.Errorf("to %s: %s, want %s", c.to, got, c.want)
		}
	}
	if got := q("SELECT install.set_state('closed', 'x', ' ')"); got != "PF035/operator" {
		t.Errorf("no operator: %s", got)
	}

	// Releases finish once; reports and preflight runs as recorded.
	rel := q("SELECT install.start_release('v1.2.0', 'install', repeat('a', 64), repeat('b', 64), repeat('c', 64), 'Ops Olga')::text")
	if len(rel) != 36 {
		t.Fatalf("release: %s", rel)
	}
	x := func(sql string, args ...any) string {
		t.Helper()
		_, err := c.Exec(ctx, sql, args...)
		return pgState(err)
	}
	if got := x("SELECT install.finish_release($1, 'succeeded')", rel); got != "ok" {
		t.Fatalf("finish: %s", got)
	}
	if got := x("SELECT install.finish_release($1, 'failed')", rel); got != "PF035/release_finished" {
		t.Errorf("finished twice: %s", got)
	}
	if got := x(`SELECT install.record_report($1, '{"release":"v1.2.0"}', 'Release v1.2.0')`, rel); got != "ok" {
		t.Errorf("report: %s", got)
	}
	if got := x(`SELECT install.record_report($1, '{"release":"v1.2.0"}', 'again')`, rel); got != "23505" {
		t.Errorf("a second report: %s", got)
	}
	if got := x(`SELECT install.record_report($1, '{"note":"Bearer abcdefghijklmnopqrstuvwx"}', 'r')`, rel); got != "PF035/secret" {
		t.Errorf("a secret-looking report: %s", got)
	}
	start := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	pf := "0b7e2d1c-9a8b-4c6d-8e5f-1a2b3c4d5e6f"
	if got := q(`SELECT install.record_preflight($1, 'v1.2.0', 'install', $2, $3, 'passed', '{"checks":[]}', repeat('d', 64))::text`, pf, start, start.Add(time.Minute)); got != "true" {
		t.Fatalf("preflight: %s", got)
	}
	if got := q(`SELECT install.record_preflight($1, 'v1.2.0', 'install', $2, $3, 'passed', '{"checks":[]}', repeat('d', 64))::text`, pf, start, start.Add(time.Minute)); got != "false" {
		t.Errorf("the same run again: %s", got)
	}
	if got := q(`SELECT install.record_preflight($1, 'v1.2.0', 'install', $2, $3, 'refused', '{"checks":[1]}', repeat('e', 64))::text`, pf, start, start.Add(time.Minute)); got != "PF035/recorded" {
		t.Errorf("the same run, another report: %s", got)
	}
	var status string
	pc := rolePool(t, e, "app_posture")
	if err := pc.QueryRow(ctx, "SELECT install.status()::text").Scan(&status); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"state": "open"`, `"mode": "self-hosted"`, `"key": "storage.encryption"`, `"attested": true`, `"outcome": "succeeded"`,
		`"report": {"release": "v1.2.0"}`, `"result": "passed"`} {
		if !strings.Contains(status, want) {
			t.Errorf("status lacks %s: %s", want, status)
		}
	}

	// The install log, replayed with the original ids and times, twice.
	logged := `[{"id":"fairctl-0001","time":"2026-11-26T08:55:00.000000Z","type":"install.decision_recorded","severity":"high","actor":"operator:Ops Olga",
		"target":"install_decision:mode","attributes":{"key":"mode","attested":"false"}}]`
	for i := 0; i < 2; i++ {
		if got := q("SELECT install.submit_events($1)::text", logged); got != "1" {
			t.Fatalf("replay %d: %s", i, got)
		}
	}
	if got := e.adminQuery(`SELECT count(*) || ':' || min(body->>'time') FROM audit.intake WHERE event_id = 'fairctl-0001'`); got != "1:2026-11-26T08:55:00.000000Z" {
		t.Errorf("replayed: %s", got)
	}
	for name, ev := range map[string]string{
		"not the installer's": `[{"id":"x1","time":"2026-11-26T08:00:00Z","type":"posture.seeded","severity":"high","actor":"operator:Ops","target":"t"}]`,
		"no time":             `[{"id":"x2","type":"install.decision_recorded","severity":"high","actor":"operator:Ops","target":"t"}]`,
		"not an operator":     `[{"id":"x3","time":"2026-11-26T08:00:00Z","type":"install.decision_recorded","severity":"high","actor":"user:1","target":"t"}]`,
		"not an array":        `{}`,
	} {
		if got := q("SELECT install.submit_events($1)::text", ev); got != "PF035/events" {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// F-014 T-05 (F-014-AC-34; D-OQ13): services answer by the installation's
// state, read as their own database role: closed and restoring refuse
// everything but health with 503 installation_closed; upgrading refuses
// mutations only (503 upgrading); reads continue.
func TestInstallState(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := installer(t, e)
	move := func(to string) {
		t.Helper()
		if _, err := c.Exec(ctx, "SELECT install.set_state($1, 'test', 'Ops Olga')", to); err != nil {
			t.Fatalf("to %s: %v", to, err)
		}
	}
	for _, role := range []string{"app_rw", "app_posture", "app_gateway", "app_audit", "app_notify", "app_integrate"} {
		srv := server.New(server.Options{Addr: "127.0.0.1:0", Plaintext: true})
		srv.Mux().HandleFunc("/api/v1/thing", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		srv.UseInstallState(install.StateReader(rolePool(t, e, role)), 0) // read every time
		call := func(method, path string) (int, string) {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
			return rec.Code, rec.Body.String()
		}
		if code, body := call("POST", "/api/v1/thing"); code != 204 {
			t.Fatalf("%s: before an installation: %d %s", role, code, body)
		}
		if role == "app_rw" {
			if _, err := c.Exec(ctx, "SELECT install.record_installation($1, 'acme', 'self-hosted', 'Ops Olga')", testInstallation); err != nil {
				t.Fatal(err)
			}
			move("open")
		}
		for _, s := range []struct {
			state, method string
			code          int
			error         string
		}{
			{"open", "POST", 204, ""},
			{"upgrading", "GET", 204, ""},
			{"upgrading", "POST", 503, "upgrading"},
			{"upgrading", "PUT", 503, "upgrading"},
			{"open", "PUT", 204, ""},
			{"closed", "GET", 503, "installation_closed"},
			{"restoring", "GET", 503, "installation_closed"},
			{"restoring", "POST", 503, "installation_closed"},
			{"open", "GET", 204, ""},
		} {
			move(s.state)
			code, body := call(s.method, "/api/v1/thing")
			if code != s.code || (s.error != "" && !strings.Contains(body, `"error":"`+s.error+`"`)) {
				t.Errorf("%s: %s %s: %d %s", role, s.state, s.method, code, body)
			}
			if code == 503 {
				if code, _ := call("GET", "/healthz"); code != 200 {
					t.Errorf("%s: %s: /healthz %d", role, s.state, code)
				}
			}
		}
	}
}

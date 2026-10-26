package tests

// F-001 T-08 (AC-17, AC-21, AC-60): access-change outbox, materialized
// scope, events and drift reconciliation.

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// drain runs the worker's drain function as app_rw and returns rows drained.
func (e *env) drain() string {
	e.t.Helper()
	out, err := e.as("app_rw", "SELECT drained || '/' || changed FROM authz.drain_outbox()")
	if err != nil {
		e.t.Fatalf("drain: %v %s", err, out)
	}
	return out
}

type storedScope struct {
	Version   int64               `json:"v"`
	Read      map[string][]string `json:"r"`
	Write     map[string][]string `json:"w"`
	Aggregate map[string][]string `json:"a"`
}

// scopeOf returns the stored scope of a user (nil when there is no row), with
// BU ids replaced by codes.
func (e *env) scopeOf(user string) *storedScope {
	e.t.Helper()
	out := e.mustOwner(fmt.Sprintf(`SELECT json_build_object('v', scope_version, 'r', read_bus, 'w', write_bus, 'a', rollup_aggregate_bus)
		FROM authz.user_scope WHERE user_id = %s`, uid(user)))
	if out == "" {
		return nil
	}
	for _, line := range strings.Split(e.mustOwner("SELECT id || '=' || code FROM iam.bu"), "\n") {
		id, code, _ := strings.Cut(line, "=")
		out = strings.ReplaceAll(out, id, code)
	}
	var s storedScope
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		e.t.Fatal(err)
	}
	return &s
}

// The AC-17 audit record of a move is written in the move's transaction: if
// the outbox cannot take the row, the move does not commit.
func TestScopeMoveCannotCommitWithoutOutboxRow(t *testing.T) {
	e := assignmentFixture(t)
	e.drain()
	e.mustOwner("UPDATE iam.bu SET parent_id = " + buID("B") + ", updated_by = " + uid("platform") + " WHERE code = 'A1'")
	out := e.mustOwner(`SELECT ref->>'moved' || '|' || (ref->>'old_parent' = (SELECT id FROM iam.bu WHERE code = 'A')::text) || '|' ||
		(ref->>'new_parent' = (SELECT id FROM iam.bu WHERE code = 'B')::text) || '|' || (ref->>'actor' = ` + uid("platform") + `::text)
		FROM iam.outbox WHERE kind = 'bu'`)
	if out != "true|true|true|true" {
		t.Fatalf("move outbox row = %q", out)
	}

	e.mustOwner("ALTER TABLE iam.outbox ADD CONSTRAINT refuse_all CHECK (false) NOT VALID")
	e.ownerFails("UPDATE iam.bu SET parent_id = "+buID("A")+" WHERE code = 'A1'", "refuse_all")
	if out := e.mustOwner("SELECT p.code FROM iam.bu b JOIN iam.bu p ON p.id = b.parent_id WHERE b.code = 'A1'"); out != "B" {
		t.Fatalf("move committed without its outbox row: A1 parent = %s", out)
	}
	e.mustOwner("ALTER TABLE iam.outbox DROP CONSTRAINT refuse_all")

	e.drain()
	if out := e.mustOwner(`SELECT payload->>'type' FROM iam.event_outbox WHERE topic = 'audit'`); out != "bu.moved" {
		t.Fatalf("audit events = %q, want bu.moved", out)
	}
}

func TestScopeMaterialization(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	if got := e.drain(); !strings.HasSuffix(got, "/1") && !strings.Contains(got, "/") {
		t.Fatalf("drain = %s", got)
	}
	s := e.scopeOf("erin")
	if s == nil {
		t.Fatal("no scope row after drain")
	}
	if got := s.Read["register"]; !slices.Equal(sortedCopy(got), []string{"A", "A1"}) {
		t.Fatalf("register read = %v, want [A A1] (not R, R1: restricted)", got)
	}
	if len(s.Write) != 0 || len(s.Aggregate) != 0 {
		t.Fatalf("viewer has write %v / aggregate %v", s.Write, s.Aggregate)
	}
	v1 := s.Version

	// Draining again without changes keeps the version.
	e.drain()
	if s := e.scopeOf("erin"); s.Version != v1 {
		t.Fatalf("version changed without a scope change: %d -> %d", v1, s.Version)
	}

	e.mustOwner(grant("platform", "user:erin", "Risk Owner", "A1"))
	e.drain()
	s = e.scopeOf("erin")
	if s.Version <= v1 || !slices.Equal(s.Write["register"], []string{"A1"}) {
		t.Fatalf("after Risk Owner at A1: v%d write %v", s.Version, s.Write)
	}

	// Roll-up modes on the restricted BU (AC-62 data, design §3).
	e.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code = 'R'")
	e.drain()
	if s := e.scopeOf("erin"); !slices.Equal(sortedCopy(s.Aggregate["register"]), []string{"R", "R1"}) || slices.Contains(s.Read["register"], "R") {
		t.Fatalf("aggregate mode: read %v aggregate %v", s.Read["register"], s.Aggregate["register"])
	}
	e.mustOwner("UPDATE iam.bu SET rollup_mode = 'full' WHERE code = 'R'")
	e.drain()
	if s := e.scopeOf("erin"); !slices.Equal(sortedCopy(s.Read["register"]), []string{"A", "A1", "R", "R1"}) || len(s.Aggregate) != 0 {
		t.Fatalf("full mode: read %v aggregate %v", s.Read["register"], s.Aggregate)
	}
	if s := e.scopeOf("erin"); slices.Contains(s.Write["register"], "R") {
		t.Fatal("full mode must never widen write scope")
	}

	// Disabling the user removes the row and announces it.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE id = " + uid("erin"))
	e.drain()
	if e.scopeOf("erin") != nil {
		t.Fatal("disabled user still has a scope row")
	}
	if out := e.mustOwner(`SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.scope.changed'
		AND payload->>'user_id' = ` + uid("erin") + `::text AND (payload->>'revoked')::boolean`); out != "1" {
		t.Fatalf("revoked scope events = %s", out)
	}
}

func TestScopeFollowsGroupsRolesAndExpiry(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Viewers')")
	e.mustOwner(grant("platform", "group:Viewers", "Directory Reader", "B"))
	e.mustOwner("INSERT INTO iam.grp_member VALUES (" + grpID("Viewers") + ", " + uid("erin") + ")")
	e.drain()
	if s := e.scopeOf("erin"); s == nil || !slices.Equal(s.Read["bu"], []string{"B"}) {
		t.Fatalf("group grant not in scope: %+v", s)
	}

	// A new role version reaches every holder.
	e.mustOwner(`INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 2, ARRAY['bu.view', 'user.view', 'role.view'], 'add role.view' FROM iam.role WHERE name = 'Directory Reader'`)
	e.drain()
	if s := e.scopeOf("erin"); !slices.Equal(s.Read["role"], []string{"B"}) {
		t.Fatalf("role re-version not in scope: %v", s.Read)
	}

	e.mustOwner("DELETE FROM iam.grp_member WHERE user_id = " + uid("erin"))
	e.drain()
	if s := e.scopeOf("erin"); len(s.Read) != 0 {
		t.Fatalf("left group but kept scope: %v", s.Read)
	}

	// Expiry has no write to trigger on; the drain picks it up.
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, expires_at)
		VALUES ('user', %s, %s, %s, %s, now() + interval '1 second')`, uid("erin"), roleID("Directory Reader"), buID("A"), uid("platform")))
	e.drain()
	if s := e.scopeOf("erin"); len(s.Read["bu"]) == 0 {
		t.Fatal("expiring grant missing before expiry")
	}
	e.mustOwner("SELECT pg_sleep(1.2)")
	e.drain()
	if s := e.scopeOf("erin"); len(s.Read) != 0 {
		t.Fatalf("expired grant still in scope: %v", s.Read)
	}
}

// Drift alert: a scope row changed behind the worker's back is repaired by
// reconciliation and reported as a high-severity audit event.
func TestScopeReconcileDetectsDrift(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	e.drain()
	if out, err := e.as("app_rw", "SELECT count(*) FROM authz.reconcile_scopes()"); err != nil || out != "0" {
		t.Fatalf("clean reconcile = %s %v", out, err)
	}
	want := e.scopeOf("erin")

	e.mustOwner("UPDATE authz.user_scope SET read_bus = '{\"register\": [\"00000000-0000-0000-0000-000000000000\"]}' WHERE user_id = " + uid("erin"))
	erin := e.mustOwner("SELECT " + uid("erin"))
	out, err := e.as("app_rw", "SELECT string_agg(r::text, ',') FROM authz.reconcile_scopes() r")
	if err != nil || out != erin {
		t.Fatalf("reconcile after tampering = %q %v", out, err)
	}
	got := e.scopeOf("erin")
	if !mapsEqual(got.Read, want.Read) || got.Version <= want.Version {
		t.Fatalf("not repaired: %+v", got)
	}
	if out := e.mustOwner(`SELECT payload->>'severity' FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = 'authz.scope.drift'`); out != "high" {
		t.Fatalf("drift alert = %q", out)
	}
}

func TestScopeEventsAndAccess(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	e.drain()
	out, err := e.as("app_rw", "SELECT string_agg(id::text, ',') FROM authz.pending_events()")
	if err != nil || out == "" {
		t.Fatalf("pending events: %q %v", out, err)
	}
	if n, err := e.as("app_rw", "SELECT authz.mark_events_published('{"+out+"}')"); err != nil || n == "0" {
		t.Fatalf("mark published = %q %v", n, err)
	}
	if n, _ := e.as("app_rw", "SELECT count(*) FROM authz.pending_events()"); n != "0" {
		t.Fatalf("events still pending: %s", n)
	}
	// The worker functions are all app_rw gets: no direct table access.
	for _, tbl := range []string{"authz.user_scope", "iam.outbox", "iam.event_outbox"} {
		e.mustFail("app_rw", "SELECT * FROM "+tbl, "permission denied")
	}
	e.mustFail("app_rw", "SELECT * FROM authz.refresh_scopes(ARRAY[gen_random_uuid()])", "permission denied")
}

// Incremental maintenance must agree with a full recompute: after random
// access changes, each followed by a drain, reconciliation finds no drift.
func TestScopeIncrementalMatchesFullRecompute(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('G1'), ('G2')")
	users := []string{"erin", "mallory", "analyst", "buadmin2", "buadmin3"}
	roles := []string{"Executive Viewer", "Risk Analyst", "Risk Owner", "Directory Reader", "Auditor"}
	bus := []string{"ENTERPRISE", "A", "A1", "B", "R", "R1"}
	modes := []string{"excluded", "aggregate", "full"}

	for seed := uint64(1); seed <= 4; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x5C)) // #nosec G404 -- seeded for reproducible property tests
		pick := func(xs []string) string { return xs[r.IntN(len(xs))] }
		var script strings.Builder
		for range 60 {
			var sql string
			switch r.IntN(7) {
			case 0, 1:
				sql = grant("platform", "user:"+pick(users), pick(roles), pick(bus))
			case 2:
				sql = grant("platform", "group:"+pick([]string{"G1", "G2"}), pick(roles), pick(bus))
			case 3:
				sql = fmt.Sprintf(`UPDATE iam.assignment SET revoked_at = now(), revoked_by = %s
					WHERE id = (SELECT id FROM iam.assignment WHERE revoked_at IS NULL AND principal_id <> %s ORDER BY random() LIMIT 1)`, uid("platform"), uid("platform"))
			case 4:
				sql = fmt.Sprintf("INSERT INTO iam.grp_member VALUES (%s, %s) ON CONFLICT DO NOTHING", grpID(pick([]string{"G1", "G2"})), uid(pick(users)))
			case 5:
				sql = fmt.Sprintf("DELETE FROM iam.grp_member WHERE user_id = %s", uid(pick(users)))
			default:
				switch r.IntN(3) {
				case 0:
					sql = fmt.Sprintf("UPDATE iam.bu SET restricted = NOT restricted WHERE code = '%s'", pick(bus[1:]))
				case 1:
					sql = fmt.Sprintf("UPDATE iam.bu SET rollup_mode = '%s' WHERE code = '%s'", pick(modes), pick(bus[1:]))
				default:
					sql = fmt.Sprintf("UPDATE iam.bu SET parent_id = %s WHERE code = '%s'", buID(pick(bus)), pick([]string{"A1", "B", "R1"}))
				}
			}
			fmt.Fprintf(&script, "DO $$ BEGIN %s; EXCEPTION WHEN others THEN NULL; END $$;\n", sql)
			if r.IntN(3) == 0 {
				script.WriteString("SELECT authz.drain_outbox();\n")
			}
		}
		script.WriteString("SELECT authz.drain_outbox();\n")
		if out, err := e.owner(script.String()); err != nil {
			t.Fatalf("seed %d script: %v %s", seed, err, out)
		}
		if out := e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()"); out != "0" {
			t.Fatalf("seed %d: %s users drifted between incremental and full recompute", seed, out)
		}
	}
}

func sortedCopy(xs []string) []string {
	ys := slices.Clone(xs)
	slices.Sort(ys)
	return ys
}

func mapsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(sortedCopy(v), sortedCopy(b[k])) {
			return false
		}
	}
	return true
}

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-003 T-15: the STRIDE suite for F-003 (design §8), written as attacks.
// TestSTRIDECatalog maps every §8 threat to these tests and the earlier
// ones that attack the same mitigation.
//
// The fixture: ENTERPRISE -> {A -> {A1, R (restricted) -> R1}, B}; risk
// analysts platform2 at ENTERPRISE, analyst at A, buadmin at A1, mallory at
// B, buadmin3 at R, buadmin2 at R1; erin views A.

func strideF003Fixture(t *testing.T) *riskAPIEnv {
	t.Helper()
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	ra.bu["R1"] = ra.adminQuery("SELECT id FROM iam.bu WHERE code = 'R1'")
	for user, bu := range map[string]string{"platform2": "ENTERPRISE", "buadmin": "A1", "buadmin3": "R", "buadmin2": "R1"} {
		ra.mustOwner(grant("platform", "user:"+user, "Risk Analyst", bu))
	}
	ra.drain()
	return ra
}

// named creates a valid library entry or control of kind called name.
func (ra *riskAPIEnv) named(t *testing.T, user, kind, bu, name string) string {
	t.Helper()
	doc := modeltest.Bases[kind]()
	doc["name"] = name
	return ra.create(t, user, kind, bu, doc)
}

// scenarioPinning is a valid scenario document pinning version 1 of the
// given asset, threat community and control.
func (ra *riskAPIEnv) scenarioPinning(name, asset, tc, ctl string) map[string]any {
	d := modeltest.Scenario()
	d["name"] = name
	d["owner"] = ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	d["asset"] = map[string]any{"kind": "asset", "id": asset, "version": 1}
	d["threat_community"] = map[string]any{"id": tc, "version": 1}
	d["control_sets"] = []any{map[string]any{"name": "Current", "current": true, "controls": []any{
		map[string]any{"id": ctl, "version": 1, "status": "in_place"}}}}
	return d
}

// insertScenario writes a scenario head and version 1 directly as app_rw
// under user's context, in one transaction.
func (ra *riskAPIEnv) insertScenario(t *testing.T, user, bu string, doc map[string]any) error {
	t.Helper()
	b, d := canonicalDoc(t, "scenario", doc)
	return ra.tx(user, func(tx pgx.Tx) error {
		ctx := context.Background()
		var id string
		if err := tx.QueryRow(ctx, "INSERT INTO risk.scenario (bu_id) VALUES ($1) RETURNING id::text", bu).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES ($1, 1, $2, $3, 'direct')", id, b, d)
		return err
	})
}

// Spoofing: an analyst saves under another identity. Authorship comes from
// the signed DB context only: the columns are not writable, a missing or
// unknown-key context writes nothing, the API body cannot name an author,
// and a JWT cannot be paired with another user's DB context.
func TestSTRIDEF003Author(t *testing.T) {
	ra := strideF003Fixture(t)
	ctx := context.Background()
	analyst := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	tc := ra.named(t, "analyst", "threat_community", ra.bu["A"], "Cyber criminals")
	b, d := canonicalDoc(t, "threat_community", modeltest.Set(modeltest.ThreatCommunity(), "/name", "Organised crime"))

	for name, c := range map[string]struct {
		sql  string
		args []any
	}{
		"a version's author": {"INSERT INTO risk.library_version (entry_id, version, document, digest, change_note, author) VALUES ($1, 2, $2, $3, 'x', " + uid("mallory") + ")", []any{tc, b, d}},
		"a head's creator":   {"INSERT INTO risk.library_entry (bu_id, kind, created_by) VALUES ($1, 'asset', " + uid("mallory") + ")", []any{ra.bu["A"]}},
		"a version's time":   {"INSERT INTO risk.library_version (entry_id, version, document, digest, change_note, created_at) VALUES ($1, 2, $2, $3, 'x', '2020-01-01')", []any{tc, b, d}},
	} {
		err := ra.tx("analyst", func(tx pgx.Tx) error { _, err := tx.Exec(ctx, c.sql, c.args...); return err })
		if !strings.HasPrefix(pgCode(err), "42501") {
			t.Errorf("%s written: %s", name, pgCode(err))
		}
	}
	// No context, or one signed with a key the database does not hold.
	if err := ra.addVersion("", "library_version", tc, 2, b, d); !strings.HasPrefix(pgCode(err), "PF016") {
		t.Errorf("without a context: %s", pgCode(err))
	}
	p := ra.principal("analyst")
	forged, err := authz.MintDBContext(authz.ContextKey{ID: "k9", Secret: []byte("k9-secret-0123456789abcdef-012345")}, p.UserID, p.ScopeVersion, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, ra.appPool(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", forged); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES ($1, 2, $2, $3, 'x')", tc, b, d)
		return err
	})
	if !strings.HasPrefix(pgCode(err), "PF016") {
		t.Errorf("an unknown key's context: %s", pgCode(err))
	}
	// mallory's own context does not reach analyst's entry.
	if err := ra.addVersion("mallory", "library_version", tc, 2, b, d); err == nil {
		t.Error("mallory saved a version of A's entry")
	}

	// The API: no author in the body; the JWT and the DB context belong to
	// the same user.
	tcDoc := modeltest.ThreatCommunity()
	body := map[string]any{"bu_id": ra.bu["A"], "kind": "threat_community", "document": tcDoc, "change_note": "New", "author": uidValue(ra, "mallory")}
	if got := ra.call(t, "POST", "analyst", "/api/v1/library", body); got.code != 400 {
		t.Errorf("an author in the body: %d %s", got.code, got.raw)
	}
	delete(body, "author")
	if code := ra.callAs(t, "analyst", "mallory", "POST", "/api/v1/library", body); code != 401 {
		t.Errorf("analyst's token with mallory's DB context: %d", code)
	}
	got := ra.call(t, "POST", "analyst", "/api/v1/library", body)
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if got := ra.call(t, "GET", "analyst", "/api/v1/library/"+id, nil); got.code != 200 || got.body["version"].(map[string]any)["author"] != analyst {
		t.Fatalf("author: %d %s", got.code, got.raw)
	}
	if ev := ra.adminQuery(`SELECT body ->> 'actor' FROM audit.intake WHERE body ->> 'type' = 'library.created' AND body ->> 'target' = 'library:` + id + `'`); ev != analyst {
		t.Fatalf("library.created actor %q", ev)
	}
}

func uidValue(ra *riskAPIEnv, name string) string {
	return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + name + "@example.test'")
}

// callAs sends a request with jwtUser's internal token and dbUser's DB
// context, and returns the status.
func (ra *riskAPIEnv) callAs(t *testing.T, jwtUser, dbUser, method, path string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, ra.url+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	jp, dp := ra.principal(jwtUser), ra.principal(dbUser)
	tok, err := authz.MintJWT(ra.keys, authz.Claims{Subject: jp.UserID, ScopeVersion: jp.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(jp.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ra.n++
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("risk-mixed-key-%04d", ra.n))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, dp.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Tampering: a version is edited in the database. No role changes or
// deletes versions or pins; a version whose digest does not match is
// refused; an edit that bypasses the triggers is caught by the digest the
// row and the trail recorded, and the bundle refuses the document.
func TestSTRIDEF003VersionTamper(t *testing.T) {
	ra := strideF003Fixture(t)
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": ra.scenarioDoc(t), "change_note": "First"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id, digest := got.body["id"].(string), got.body["digest"].(string)
	trail := func() string {
		return ra.adminQuery(`SELECT body -> 'attributes' ->> 'digest' FROM audit.intake WHERE body ->> 'type' = 'scenario.created' AND body ->> 'target' = 'scenario:` + id + `'`)
	}
	if trail() != digest {
		t.Fatalf("the trail's digest %q, the version's %q", trail(), digest)
	}
	where := " WHERE scenario_id = '" + id + "'"
	for _, q := range []string{"UPDATE risk.scenario_version SET change_note = 'x'", "DELETE FROM risk.scenario_version",
		"UPDATE risk.scenario_pin SET to_version = 9", "DELETE FROM risk.scenario_pin"} {
		if out, err := ra.asCtx(ra.mint("analyst", ctxKey1), q+where); err == nil || !strings.Contains(out, "permission denied") {
			t.Errorf("app_rw: %s: %v %s", q, err, out)
		}
		// Not even a superuser, with the triggers in place.
		if err := ra.psqlAs(nil, ra.db, q+where); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("superuser: %s: %v", q, err)
		}
	}
	if err := ra.psqlAs(nil, ra.db, "DELETE FROM risk.scenario WHERE id = '"+id+"'"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("a head deleted: %v", err)
	}
	b, _ := canonicalDoc(t, "scenario", modeltest.Set(ra.scenarioDoc(t), "/name", "Renamed"))
	if err := ra.addVersion("analyst", "scenario_version", id, 2, b, digest); !strings.Contains(pgCode(err), "digest does not match") {
		t.Errorf("a version with another document's digest: %s", pgCode(err))
	}

	// An edit with the triggers switched off (a superuser, outside the
	// application): the stored digest and the trail no longer match the
	// document, and the service will not build a bundle from it.
	ra.admin(ra.db, `SET session_replication_role = replica;
		UPDATE risk.scenario_version SET document = convert_to(replace(convert_from(document, 'UTF8'), 'Ransomware on the claims platform', 'Nothing to see'), 'UTF8')`+where)
	if got := ra.adminQuery("SELECT (encode(sha256(document), 'hex') = digest) || '|' || digest FROM risk.scenario_version" + where); got != "false|"+digest || trail() != digest {
		t.Fatalf("after tampering: %s, trail %s", got, trail())
	}
	if got := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+id+"/versions/1/bundle", nil); got.code == 200 || strings.Contains(got.raw, "Nothing to see") {
		t.Fatalf("bundle of a tampered version: %d %s", got.code, got.raw)
	}
}

// Tampering: a pin points at an entry the analyst cannot see. The trigger
// checks every pin at write, whether through the API or straight into the
// database: a sibling's entry, a restricted BU's, the wrong kind, a
// version that does not exist.
func TestSTRIDEF003PinVisibility(t *testing.T) {
	ra := strideF003Fixture(t)
	a := ra.named(t, "analyst", "asset", ra.bu["A"], "A asset")
	tc := ra.named(t, "analyst", "threat_community", ra.bu["A"], "A threat")
	ctl := ra.named(t, "analyst", "control", ra.bu["A"], "A control")
	tcR := ra.named(t, "buadmin3", "threat_community", ra.bu["R"], "R threat")
	aB := ra.named(t, "mallory", "asset", ra.bu["B"], "B asset")
	tcB := ra.named(t, "mallory", "threat_community", ra.bu["B"], "B threat")
	ctlB := ra.named(t, "mallory", "control", ra.bu["B"], "B control")
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A"], "document": ra.scenarioPinning("Fine", a, tc, ctl), "change_note": "x"}); got.code != 201 {
		t.Fatalf("visible pins: %d %s", got.code, got.raw)
	}
	wrongVersion := ra.scenarioPinning("Version 2", a, tc, ctl)
	wrongVersion["asset"] = map[string]any{"kind": "asset", "id": a, "version": 2}
	for _, c := range []struct {
		name, user, bu, pointer string
		doc                     map[string]any
	}{
		{"a sibling's asset", "mallory", ra.bu["B"], "/asset", ra.scenarioPinning("Leak", a, tcB, ctlB)},
		{"a sibling's control", "mallory", ra.bu["B"], "/control_sets/0/controls/0", ra.scenarioPinning("Leak", aB, tcB, ctl)},
		{"a restricted BU's threat community", "analyst", ra.bu["A"], "/threat_community", ra.scenarioPinning("Leak", a, tcR, ctl)},
		{"a threat community as the asset", "analyst", ra.bu["A"], "/asset", ra.scenarioPinning("Kind", tc, tc, ctl)},
		{"a version that does not exist", "analyst", ra.bu["A"], "/asset", wrongVersion},
	} {
		got := ra.call(t, "POST", c.user, "/api/v1/scenarios", map[string]any{"bu_id": c.bu, "document": c.doc, "change_note": "x"})
		if got.code != 422 || !strings.Contains(got.raw, c.pointer) {
			t.Errorf("API, %s: %d %s", c.name, got.code, got.raw)
		}
		if err := ra.insertScenario(t, c.user, c.bu, c.doc); !strings.HasPrefix(pgCode(err), "PF016") || !strings.Contains(pgCode(err), "not visible") {
			t.Errorf("database, %s: %s", c.name, pgCode(err))
		}
	}
	if n := ra.adminQuery("SELECT count(*) || '/' || (SELECT count(*) FROM risk.scenario_pin) FROM risk.scenario"); n != "1/3" {
		t.Fatalf("scenarios/pins after the refusals: %s", n)
	}
}

// Repudiation: every change to risk data is in the trail, in its
// transaction, with the actor, the BU and the change note or reason; a
// refused change leaves no event; and a change whose event cannot be
// recorded does not happen (audit fails closed).
func TestRiskAuditEvents(t *testing.T) {
	ra := strideF003Fixture(t)
	ctx := context.Background()
	analyst := uidValue(ra, "analyst")
	type step struct{ typ, target, bu, note string }
	var want []step
	note := func(typ, target, bu, n string) { want = append(want, step{typ, target, bu, n}) }

	for _, k := range []struct {
		path, kind, event string
		doc               map[string]any
	}{
		{"/api/v1/scenarios", "", "scenario", ra.scenarioDoc(t)},
		{"/api/v1/library", "asset", "library", modeltest.Asset()},
		{"/api/v1/controls", "", "control", modeltest.Control()},
	} {
		body := map[string]any{"bu_id": ra.bu["A1"], "document": k.doc, "change_note": "Created " + k.event}
		if k.kind != "" {
			body["kind"] = k.kind
		}
		got := ra.call(t, "POST", "analyst", k.path, body)
		if got.code != 201 {
			t.Fatalf("%s create: %d %s", k.event, got.code, got.raw)
		}
		id := got.body["id"].(string)
		target := k.event + ":" + id
		note(k.event+".created", target, ra.bu["A1"], "Created "+k.event)
		// A refused save (a stale version) is not recorded.
		if got := ra.call(t, "PUT", "analyst", k.path+"/"+id, map[string]any{"document": k.doc, "expected_version": 5, "change_note": "Stale"}); got.code != 409 {
			t.Fatalf("%s stale save: %d %s", k.event, got.code, got.raw)
		}
		doc := modeltest.Set(k.doc, "/name", "Renamed "+k.event)
		if got := ra.call(t, "PUT", "analyst", k.path+"/"+id, map[string]any{"document": doc, "expected_version": 1, "change_note": "Renamed"}); got.code != 200 {
			t.Fatalf("%s save: %d %s", k.event, got.code, got.raw)
		}
		note(k.event+".version_saved", target, ra.bu["A1"], "Renamed")
		if k.event == "scenario" {
			if got := ra.call(t, "POST", "analyst", k.path+"/"+id+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "Moved up"}); got.code != 200 {
				t.Fatalf("move: %d %s", got.code, got.raw)
			}
			note("scenario.moved", target, ra.bu["A"], "Moved up")
		}
		bu := ra.bu["A1"]
		if k.event == "scenario" {
			bu = ra.bu["A"]
		}
		for _, action := range []string{"archive", "restore"} {
			if got := ra.call(t, "POST", "analyst", k.path+"/"+id+"/"+action, map[string]any{"reason": "Tidy " + action}); got.code != 200 {
				t.Fatalf("%s %s: %d %s", k.event, action, got.code, got.raw)
			}
			note(k.event+"."+map[string]string{"archive": "archived", "restore": "restored"}[action], target, bu, "Tidy "+action)
		}
	}
	for _, w := range want {
		got := ra.adminQuery(fmt.Sprintf(`SELECT string_agg((body ->> 'actor') || '|' || (body ->> 'bu_id') || '|' ||
			coalesce(body -> 'attributes' ->> 'change_note', body -> 'attributes' ->> 'reason', '-'), ',')
			FROM audit.intake WHERE body ->> 'type' = '%s' AND body ->> 'target' = '%s'`, w.typ, w.target))
		if got != analyst+"|"+w.bu+"|"+w.note {
			t.Errorf("%s %s: %q", w.typ, w.target, got)
		}
	}
	if n := ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' ~ '^(scenario|library|control)\.'`); n != fmt.Sprint(len(want)) {
		t.Errorf("%s risk_data events, want %d", n, len(want))
	}

	// The trail is full: the API refuses the change and writes nothing.
	pool := ra.auditPool()
	emitter := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})
	if r, err := (auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: 1}).Step(ctx); err != nil || r.Level != "full" {
		t.Fatalf("capacity: %+v %v", r, err)
	}
	before := ra.adminQuery("SELECT count(*) FROM risk.control")
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A1"], "document": modeltest.Control(), "change_note": "While full"}); got.code != 503 {
		t.Fatalf("create while the trail is full: %d %s", got.code, got.raw)
	}
	if after := ra.adminQuery("SELECT count(*) FROM risk.control"); after != before {
		t.Fatalf("a control was created without its event: %s -> %s", before, after)
	}
	if _, err := (auditsvc.CapacityMonitor{DB: pool, Audit: emitter, Quota: 1 << 50}).Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A1"], "document": modeltest.Control(), "change_note": "After"}); got.code != 201 {
		t.Fatalf("create after the trail has room: %d %s", got.code, got.raw)
	}
}

// Information disclosure: inherited read reaches only up the caller's own
// ancestors, and stops at a restricted BU, through the API and the
// database alike; scenarios are never inherited.
func TestSTRIDEF003InheritedRead(t *testing.T) {
	ra := strideF003Fixture(t)
	for user, bu := range map[string]string{"platform2": "ENTERPRISE", "analyst": "A", "buadmin": "A1", "mallory": "B", "buadmin3": "R", "buadmin2": "R1"} {
		ra.named(t, user, "asset", ra.bu[bu], bu+" asset")
	}
	root := ra.adminQuery("SELECT id FROM risk.library_entry WHERE bu_id = '" + ra.bu["ENTERPRISE"] + "' AND kind = 'asset'")
	if got := ra.call(t, "POST", "platform2", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["ENTERPRISE"], "change_note": "x",
		"document": ra.scenarioPinning("Root scenario", root, ra.named(t, "platform2", "threat_community", ra.bu["ENTERPRISE"], "Root threat"),
			ra.named(t, "platform2", "control", ra.bu["ENTERPRISE"], "Root control"))}); got.code != 201 {
		t.Fatalf("root scenario: %d %s", got.code, got.raw)
	}
	for _, c := range []struct{ user, own, inherited string }{
		{"buadmin", "A1 asset", "A asset,ENTERPRISE asset"},
		{"analyst", "A asset,A1 asset", "ENTERPRISE asset"},
		{"mallory", "B asset", "ENTERPRISE asset"},
		{"buadmin3", "R asset,R1 asset", ""},
		{"buadmin2", "R1 asset", "R asset"},
		{"platform2", "A asset,A1 asset,B asset,ENTERPRISE asset", ""},
	} {
		got := ra.call(t, "GET", c.user, "/api/v1/library?kind=asset&limit=200", nil)
		if got.code != 200 {
			t.Fatalf("%s: %d %s", c.user, got.code, got.raw)
		}
		var own, inh []string
		for _, x := range got.body["entries"].([]any) {
			m := x.(map[string]any)
			if m["inherited"] == true {
				inh = append(inh, m["name"].(string))
			} else {
				own = append(own, m["name"].(string))
			}
		}
		if g := sortedJoin(own); g != c.own {
			t.Errorf("%s's own entries %q, want %q", c.user, g, c.own)
		}
		if g := sortedJoin(inh); g != c.inherited {
			t.Errorf("%s's inherited entries %q, want %q", c.user, g, c.inherited)
		}
		// The database shows the same, whatever the service asks.
		out, err := ra.asCtx(ra.mint(c.user, ctxKey1), "SELECT string_agg(e.bu_id::text, ',') FROM risk.library_entry e WHERE e.bu_id IN ('"+ra.bu["B"]+"', '"+ra.bu["R"]+"', '"+ra.bu["R1"]+"', '"+ra.bu["A"]+"')")
		if err != nil {
			t.Fatal(err)
		}
		for bu, may := range map[string]bool{"B": c.user == "mallory" || c.user == "platform2", "R": strings.HasPrefix(c.user, "buadmin") && c.user != "buadmin",
			"A": c.user == "analyst" || c.user == "buadmin" || c.user == "platform2"} {
			if strings.Contains(out, ra.bu[bu]) != may {
				t.Errorf("%s reading %s's entry in the database: %v", c.user, bu, !may)
			}
		}
	}
	// By id: a sibling's and a restricted BU's entries are not found.
	for user, bu := range map[string]string{"mallory": "A", "analyst": "R", "buadmin2": "A"} {
		id := ra.adminQuery("SELECT id FROM risk.library_entry WHERE bu_id = '" + ra.bu[bu] + "'")
		if got := ra.call(t, "GET", user, "/api/v1/library/"+id, nil); got.code != 404 {
			t.Errorf("%s reads %s's entry: %d", user, bu, got.code)
		}
	}
	// Scenarios are not shared down.
	if got := ra.call(t, "GET", "analyst", "/api/v1/scenarios", nil); got.code != 200 || strings.Contains(got.raw, "Root scenario") {
		t.Fatalf("analyst lists the root's scenario: %d %s", got.code, got.raw)
	}
}

func sortedJoin(s []string) string {
	out := slices.Clone(s)
	slices.Sort(out)
	return strings.Join(out, ",")
}

// Information disclosure: a move leaks a restricted scenario. Moving out
// of a restricted subtree is refused for a user with edit on both sides,
// through the API and the definer function; moves inside it are allowed.
func TestSTRIDEF003RestrictedMove(t *testing.T) {
	ra := strideF003Fixture(t)
	ra.mustOwner(grant("platform", "user:buadmin3", "Risk Analyst", "A"))
	ra.drain()
	doc := ra.scenarioPinning("Restricted scenario", ra.named(t, "buadmin3", "asset", ra.bu["R"], "R asset"),
		ra.named(t, "buadmin3", "threat_community", ra.bu["R"], "R threat"), ra.named(t, "buadmin3", "control", ra.bu["R"], "R control"))
	got := ra.call(t, "POST", "buadmin3", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["R1"], "document": doc, "change_note": "x"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	for _, to := range []string{"A", "A1", "ENTERPRISE"} {
		if to == "ENTERPRISE" {
			ra.mustOwner(grant("platform", "user:buadmin3", "Risk Analyst", "ENTERPRISE"))
			ra.drain()
		}
		if got := ra.call(t, "POST", "buadmin3", "/api/v1/scenarios/"+id+"/move", map[string]any{"to_bu_id": ra.bu[to], "reason": "Out"}); got.code != 409 || got.body["error"] != "restricted_move" {
			t.Errorf("to %s: %d %s", to, got.code, got.raw)
		}
		out, err := ra.asCtx(ra.mint("buadmin3", ctxKey1), "SELECT risk.move_scenario('"+id+"', '"+ra.bu[to]+"')")
		if err == nil || !strings.Contains(out, "restricted") {
			t.Errorf("risk.move_scenario to %s: %v %s", to, err, out)
		}
	}
	if bu := ra.adminQuery("SELECT bu_id || '|' || (SELECT count(DISTINCT bu_id) FROM risk.scenario_pin WHERE scenario_id = '" + id + "') FROM risk.scenario WHERE id = '" + id + "'"); bu != ra.bu["R1"]+"|1" {
		t.Fatalf("after the refused moves: %s", bu)
	}
	if got := ra.call(t, "POST", "buadmin3", "/api/v1/scenarios/"+id+"/move", map[string]any{"to_bu_id": ra.bu["R"], "reason": "Inside"}); got.code != 200 {
		t.Fatalf("inside the subtree: %d %s", got.code, got.raw)
	}
	// Nobody outside R sees it, before or after.
	for _, user := range []string{"analyst", "platform2", "mallory"} {
		if got := ra.call(t, "GET", user, "/api/v1/scenarios/"+id, nil); got.code != 404 {
			t.Errorf("%s reads the restricted scenario: %d", user, got.code)
		}
	}
}

// Information disclosure: an export leaks unseen data. The file is built
// under the requester's context: a subtree export leaves out siblings and
// restricted BUs, unseen ids and BUs are not found.
func TestSTRIDEF003ExportScope(t *testing.T) {
	ra := strideF003Fixture(t)
	for user, bu := range map[string]string{"platform2": "ENTERPRISE", "analyst": "A", "mallory": "B", "buadmin3": "R", "buadmin2": "R1"} {
		a := ra.named(t, user, "asset", ra.bu[bu], bu+" asset")
		tc := ra.named(t, user, "threat_community", ra.bu[bu], bu+" threat")
		ctl := ra.named(t, user, "control", ra.bu[bu], bu+" control")
		if got := ra.call(t, "POST", user, "/api/v1/scenarios", map[string]any{"bu_id": ra.bu[bu], "change_note": "x",
			"document": ra.scenarioPinning(bu+" scenario", a, tc, ctl)}); got.code != 201 {
			t.Fatalf("%s scenario: %d %s", bu, got.code, got.raw)
		}
	}
	names := func(raw string) map[string]bool {
		out := map[string]bool{}
		for _, bu := range []string{"ENTERPRISE", "A", "B", "R", "R1"} {
			for _, what := range []string{"asset", "threat", "control", "scenario"} {
				if strings.Contains(raw, `"`+bu+" "+what+`"`) {
					out[bu] = true
				}
			}
		}
		return out
	}
	for _, c := range []struct {
		user, bu string
		want     []string
	}{
		{"analyst", "A", []string{"A"}},
		{"platform2", "ENTERPRISE", []string{"ENTERPRISE", "A", "B"}},
		{"buadmin3", "R", []string{"R", "R1"}},
		{"buadmin2", "R1", []string{"R1"}},
	} {
		got := ra.call(t, "GET", c.user, "/api/v1/risk/export?bu="+ra.bu[c.bu]+"&archived=true", nil)
		if got.code != 200 {
			t.Fatalf("%s exports %s: %d %s", c.user, c.bu, got.code, got.raw)
		}
		seen := names(got.raw)
		for _, bu := range []string{"ENTERPRISE", "A", "B", "R", "R1"} {
			want := false
			for _, w := range c.want {
				want = want || w == bu
			}
			if seen[bu] != want {
				t.Errorf("%s's export of %s: %s's data present %v", c.user, c.bu, bu, seen[bu])
			}
		}
	}
	// Unseen BUs and ids.
	for user, bu := range map[string]string{"analyst": "B", "mallory": "A", "platform2": "R"} {
		if got := ra.call(t, "GET", user, "/api/v1/risk/export?bu="+ra.bu[bu], nil); got.code != 404 && (got.code != 200 || len(names(got.raw)) > 0) {
			t.Errorf("%s exports %s: %d %s", user, bu, got.code, got.raw)
		}
	}
	for user, bu := range map[string]string{"analyst": "B", "mallory": "A", "platform2": "R", "buadmin2": "R"} {
		id := ra.adminQuery("SELECT id FROM risk.scenario WHERE bu_id = '" + ra.bu[bu] + "'")
		if got := ra.call(t, "GET", user, "/api/v1/risk/export?scenarios="+id, nil); got.code != 404 {
			t.Errorf("%s exports %s's scenario by id: %d %s", user, bu, got.code, got.raw)
		}
	}
}

// rawDoc is a document's canonical bytes and digest without validation: an
// attack that skips the service.
func rawDoc(t *testing.T, doc map[string]any) ([]byte, string) {
	t.Helper()
	raw, _ := json.Marshal(doc)
	b, err := canon.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b, canon.Digest(b)
}

// Information disclosure: secrets pasted into free text. The API and the
// database refuse documents, change notes and imports holding a value that
// looks like a secret, naming where.
func TestRiskSecretsRefused(t *testing.T) {
	ra := strideF003Fixture(t)
	const pem = "-----BEGIN RSA PRIVATE KEY----- MIIEow"
	const bearer = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
	for _, c := range []struct {
		kind, pointer, value string
	}{
		{"asset", "/description", pem},
		{"threat_community", "/name", bearer},
		{"control", "/effects/0/estimate/rationale", "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"},
		{"control", "/references/0/identifier", "__Host-sid=abc"},
	} {
		doc := modeltest.Set(modeltest.Bases[c.kind](), c.pointer, c.value)
		path, body := "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": c.kind, "document": doc, "change_note": "x"}
		if c.kind == "control" {
			path = "/api/v1/controls"
			delete(body, "kind")
		}
		if got := ra.call(t, "POST", "analyst", path, body); got.code != 422 || !strings.Contains(got.raw, `"`+c.pointer+`"`) || !strings.Contains(got.raw, "secret") {
			t.Errorf("API, %s %s: %d %s", c.kind, c.pointer, got.code, got.raw)
		}
		table, versions := "library_entry", "library_version"
		if c.kind == "control" {
			table, versions = "control", "control_version"
		}
		id, err := ra.newHead("analyst", table, ra.bu["A"], c.kind)
		if err != nil {
			t.Fatal(err)
		}
		b, d := rawDoc(t, doc)
		if err := ra.addVersion("analyst", versions, id, 1, b, d); !strings.HasPrefix(pgCode(err), "PF016") || !strings.Contains(pgCode(err), c.pointer+": looks like a secret") {
			t.Errorf("database, %s %s: %s", c.kind, c.pointer, pgCode(err))
		}
	}
	// Scenario estimates, and change notes on save.
	doc := modeltest.Set(ra.scenarioDoc(t), "/lef/tef/contact_frequency/rationale", pem)
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A"], "document": doc, "change_note": "x"}); got.code != 422 ||
		!strings.Contains(got.raw, "/lef/tef/contact_frequency/rationale") {
		t.Errorf("a scenario rationale: %d %s", got.code, got.raw)
	}
	got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": modeltest.Asset(), "change_note": "x"})
	if got.code != 201 {
		t.Fatalf("asset: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+id, map[string]any{"document": modeltest.Asset(), "expected_version": 1, "change_note": bearer}); got.code != 400 {
		t.Errorf("a secret change note: %d %s", got.code, got.raw)
	}
	// An import whose file holds one is refused whole.
	exp := ra.call(t, "GET", "analyst", "/api/v1/risk/export?library="+id, nil)
	if exp.code != 200 {
		t.Fatalf("export: %d %s", exp.code, exp.raw)
	}
	file := strings.Replace(exp.raw, "Policyholder claims.", pem, 1)
	var f any
	if err := json.Unmarshal([]byte(file), &f); err != nil {
		t.Fatal(err)
	}
	before := ra.adminQuery("SELECT count(*) FROM risk.library_entry")
	if got := ra.call(t, "POST", "analyst", "/api/v1/risk/imports", map[string]any{"bu_id": ra.bu["A1"], "file": f}); got.code != 422 || !strings.Contains(got.raw, "secret") {
		t.Errorf("import with a secret: %d %s", got.code, got.raw)
	}
	if after := ra.adminQuery("SELECT count(*) FROM risk.library_entry"); after != before {
		t.Errorf("entries %s -> %s after a refused import", before, after)
	}
}

// Denial of service: huge documents or imports. Text and list limits in
// the API and the database, the document size limit (1 MiB) and the import
// size limit (4 MiB, the mutation body limit) in the API.
func TestRiskLimits(t *testing.T) {
	ra := strideF003Fixture(t)
	long := func(n int) string { return strings.Repeat("x", n) }
	sources := make([]any, 21)
	for i := range sources {
		sources[i] = map[string]any{"type": "document", "ref": fmt.Sprint("source ", i)}
	}
	controls := make([]any, 201)
	ctl := ra.named(t, "analyst", "control", ra.bu["A"], "Control")
	for i := range controls {
		controls[i] = map[string]any{"id": ctl, "version": 1, "status": "in_place"}
	}
	for _, c := range []struct {
		kind, pointer string
		value         any
	}{
		{"asset", "/name", long(201)},
		{"asset", "/description", long(10001)},
		{"threat_community", "/threat_capability/sources", sources},
		{"control", "/references/0/identifier", long(1001)},
		{"scenario", "/control_sets/0/controls", controls},
	} {
		var base map[string]any
		if c.kind == "scenario" {
			base = ra.scenarioDoc(t)
		} else {
			base = modeltest.Bases[c.kind]()
		}
		doc := modeltest.Set(base, c.pointer, c.value)
		path := map[string]string{"asset": "/api/v1/library", "threat_community": "/api/v1/library", "control": "/api/v1/controls", "scenario": "/api/v1/scenarios"}[c.kind]
		body := map[string]any{"bu_id": ra.bu["A"], "document": doc, "change_note": "x"}
		if strings.HasSuffix(path, "/library") {
			body["kind"] = c.kind
		}
		if got := ra.call(t, "POST", "analyst", path, body); got.code != 422 || !strings.Contains(got.raw, c.pointer) {
			t.Errorf("API, %s %s: %d %s", c.kind, c.pointer, got.code, got.raw[:min(len(got.raw), 300)])
		}
		tables := map[string][2]string{"scenario": {"scenario", "scenario_version"}, "control": {"control", "control_version"}}[c.kind]
		table, versions := tables[0], tables[1]
		if table == "" {
			table, versions = "library_entry", "library_version"
		}
		id, err := ra.newHead("analyst", table, ra.bu["A"], c.kind)
		if err != nil {
			t.Fatal(err)
		}
		b, d := rawDoc(t, doc)
		if err := ra.addVersion("analyst", versions, id, 1, b, d); !strings.HasPrefix(pgCode(err), "PF016") || !strings.Contains(pgCode(err), c.pointer) {
			t.Errorf("database, %s %s: %s", c.kind, c.pointer, pgCode(err)[:min(len(pgCode(err)), 300)])
		}
	}
	// A body over the document limit (1 MiB and its envelope) is not read
	// past the limit.
	huge := modeltest.Set(modeltest.Asset(), "/description", long(1<<20+100<<10))
	if got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": huge, "change_note": "x"}); got.code != 400 {
		t.Errorf("a document over 1 MiB: %d", got.code)
	}
	// An import over 4 MiB is refused before it is read.
	file := map[string]any{"format": "fair.risk.v1", "padding": long(5 << 20)}
	if got := ra.call(t, "POST", "analyst", "/api/v1/risk/imports?dry_run=true", map[string]any{"bu_id": ra.bu["A"], "file": file}); got.code != 413 {
		t.Errorf("an import over 4 MiB: %d", got.code)
	}
	if n := ra.adminQuery("SELECT (SELECT count(*) FROM risk.scenario_version) || '/' || (SELECT count(*) FROM risk.library_version v WHERE octet_length(v.document) > 10000)"); n != "0/0" {
		t.Errorf("scenario versions / long library versions after the refusals: %s", n)
	}
}

// Elevation of privilege: a reader without edit changes the library.
// Inherited read is SELECT only: no new version, archive or new head in an
// ancestor's BU, through the API or the database; the heads' columns are
// not app_rw's to update.
func TestSTRIDEF003InheritedWrite(t *testing.T) {
	ra := strideF003Fixture(t)
	ctx := context.Background()
	root := ra.named(t, "platform2", "asset", ra.bu["ENTERPRISE"], "Root asset")
	rEntry := ra.named(t, "buadmin3", "threat_community", ra.bu["R"], "R threat")
	b, d := canonicalDoc(t, "asset", modeltest.Set(modeltest.Asset(), "/name", "Taken over"))
	bt, dt := canonicalDoc(t, "threat_community", modeltest.Set(modeltest.ThreatCommunity(), "/name", "Taken over"))
	for _, c := range []struct {
		user, id, bu, kind string
		b                  []byte
		d                  string
	}{
		{"analyst", root, "ENTERPRISE", "asset", b, d},
		{"buadmin", root, "ENTERPRISE", "asset", b, d},
		{"buadmin2", rEntry, "R", "threat_community", bt, dt},
	} {
		// It is readable...
		if got := ra.call(t, "GET", c.user, "/api/v1/library/"+c.id, nil); got.code != 200 || got.body["entry"].(map[string]any)["inherited"] != true {
			t.Fatalf("%s reads the inherited entry: %d %s", c.user, got.code, got.raw)
		}
		// ...and nothing else.
		var doc map[string]any
		_ = json.Unmarshal(c.b, &doc)
		if got := ra.call(t, "PUT", c.user, "/api/v1/library/"+c.id, map[string]any{"document": doc, "expected_version": 1, "change_note": "x"}); got.code != 403 {
			t.Errorf("%s saves the inherited entry: %d %s", c.user, got.code, got.raw)
		}
		if got := ra.call(t, "POST", c.user, "/api/v1/library/"+c.id+"/archive", map[string]any{"reason": "x"}); got.code != 403 {
			t.Errorf("%s archives the inherited entry: %d %s", c.user, got.code, got.raw)
		}
		if got := ra.call(t, "POST", c.user, "/api/v1/library", map[string]any{"bu_id": ra.bu[c.bu], "kind": c.kind, "document": doc, "change_note": "x"}); got.code != 404 && got.code != 403 {
			t.Errorf("%s creates in %s: %d %s", c.user, c.bu, got.code, got.raw)
		}
		if err := ra.addVersion(c.user, "library_version", c.id, 2, c.b, c.d); err == nil {
			t.Errorf("%s added a version in the database", c.user)
		}
		if _, err := ra.newHead(c.user, "library_entry", ra.bu[c.bu], c.kind); !strings.Contains(pgCode(err), "row-level security") {
			t.Errorf("%s created a head in %s: %s", c.user, c.bu, pgCode(err))
		}
		err := ra.tx(c.user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT risk.set_archived('library', $1, true)", c.id)
			return err
		})
		if err == nil {
			t.Errorf("%s archived through risk.set_archived", c.user)
		}
		if out, err := ra.asCtx(ra.mint(c.user, ctxKey1), "UPDATE risk.library_entry SET archived_at = now(), bu_id = '"+ra.bu["A1"]+"' WHERE id = '"+c.id+"'"); err == nil || !strings.Contains(out, "permission denied") {
			t.Errorf("%s updates the head: %v %s", c.user, err, out)
		}
	}
	if got := ra.adminQuery("SELECT string_agg(current_version || ':' || (archived_at IS NULL), ',' ORDER BY seq) FROM risk.library_entry"); got != "1:true,1:true" {
		t.Fatalf("after the attempts: %s", got)
	}
}

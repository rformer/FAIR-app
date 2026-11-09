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

	"github.com/rformer/fair-app/internal/risk/canon"
	riskmodel "github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/rlstest"
)

// F-003 T-03 (F-003-AC-05, AC-06, AC-15, AC-18, AC-23; design §4): the risk
// schema. Versions are append-only and checked in the database exactly as
// the service checks them; pins must be visible; every table is BU-owned.

// canonicalDoc validates a document with the service's validator and
// returns its canonical bytes and digest.
func canonicalDoc(t *testing.T, kind string, doc map[string]any) ([]byte, string) {
	t.Helper()
	raw, _ := json.Marshal(doc)
	d, problems := riskmodel.Validate(kind, raw)
	if problems != nil {
		t.Fatalf("%s fixture: %v", kind, problems)
	}
	return d.Canonical, d.Digest
}

func templateJSON(t *testing.T, kind string, doc map[string]any) string {
	b, _ := canonicalDoc(t, kind, doc)
	return strings.ReplaceAll(string(b), "'", "''")
}

// The RLS fixtures make whole valid rows through helper functions (as the
// caller, so RLS and the triggers apply): a head with a valid version 1,
// for scenarios with the asset, threat community and control they pin, in
// the same BU.
func init() {
	head := func(table, fn string) rlstest.Fixture {
		// Heads change only through the service's functions (archive,
		// move; T-09) and the version trigger.
		return rlstest.Fixture{Table: table, PK: "id", Missing: "00000000-0000-0000-0000-000000000000", Touch: "archived_at = archived_at",
			Refused: []string{"update", "delete", "move"}, Insert: func(bu string) string { return fmt.Sprintf("SELECT (%s)::text", fmt.Sprintf(fn, bu)) }}
	}
	child := func(table, pk, fn, suffix string) rlstest.Fixture {
		return rlstest.Fixture{Table: table, PK: pk, Missing: "none", Touch: "bu_id = bu_id",
			Refused: []string{"update", "delete", "move"}, Insert: func(bu string) string { return fmt.Sprintf("SELECT (%s)::text || '%s'", fmt.Sprintf(fn, bu), suffix) }}
	}
	for _, fx := range []rlstest.Fixture{
		head("risk.scenario", "rlsfx.scenario('%s')"),
		child("risk.scenario_version", "(scenario_id::text || '/' || version)", "rlsfx.scenario('%s')", "/1"),
		child("risk.scenario_pin", "(scenario_id::text || pointer)", "rlsfx.scenario('%s')", "/threat_community"),
		head("risk.library_entry", "rlsfx.entry('threat_community', '%s')"),
		child("risk.library_version", "(entry_id::text || '/' || version)", "rlsfx.entry('threat_community', '%s')", "/1"),
		child("risk.library_pin", "(entry_id::text || pointer)", "rlsfx.grp('%s')", "/members/0"),
		head("risk.control", "rlsfx.control('%s')"),
		child("risk.control_version", "(control_id::text || '/' || version)", "rlsfx.control('%s')", "/1"),
	} {
		rlsFixtures[fx.Table] = fx
	}
	rlsFixtureSetups = append(rlsFixtureSetups, riskFixtureFunctions)
}

func riskFixtureFunctions(e *env) {
	t := e.t
	tmpl := map[string]string{
		"scenario": templateJSON(t, "scenario", modeltest.Scenario()), "asset": templateJSON(t, "asset", modeltest.Asset()),
		"asset_group": templateJSON(t, "asset_group", modeltest.AssetGroup()), "threat_community": templateJSON(t, "threat_community", modeltest.ThreatCommunity()),
		"control": templateJSON(t, "control", modeltest.Control()),
	}
	var rows []string
	for k, v := range tmpl {
		rows = append(rows, fmt.Sprintf("('%s', '%s')", k, v))
	}
	e.admin(e.db, `CREATE SCHEMA rlsfx;
CREATE TABLE rlsfx.tmpl (kind text PRIMARY KEY, doc jsonb NOT NULL);
INSERT INTO rlsfx.tmpl VALUES `+strings.Join(rows, ", ")+`;
CREATE FUNCTION rlsfx.version(tbl text, head uuid, doc jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE b bytea := convert_to(risk.canonical(doc), 'UTF8');
BEGIN
  EXECUTE format('INSERT INTO risk.%I (%I, version, document, digest, change_note) VALUES ($1, 1, $2, $3, ''fixture'')',
    tbl, CASE tbl WHEN 'scenario_version' THEN 'scenario_id' WHEN 'library_version' THEN 'entry_id' ELSE 'control_id' END)
    USING head, b, encode(sha256(b), 'hex');
END $$;
CREATE FUNCTION rlsfx.entry(k text, bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE id uuid;
BEGIN
  INSERT INTO risk.library_entry (bu_id, kind) VALUES (bu, k) RETURNING library_entry.id INTO id;
  PERFORM rlsfx.version('library_version', id, (SELECT doc FROM rlsfx.tmpl WHERE kind = k));
  RETURN id;
END $$;
CREATE FUNCTION rlsfx.control(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE id uuid;
BEGIN
  INSERT INTO risk.control (bu_id) VALUES (bu) RETURNING control.id INTO id;
  PERFORM rlsfx.version('control_version', id, (SELECT doc FROM rlsfx.tmpl WHERE kind = 'control'));
  RETURN id;
END $$;
CREATE FUNCTION rlsfx.grp(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE a uuid := rlsfx.entry('asset', bu); id uuid;
BEGIN
  INSERT INTO risk.library_entry (bu_id, kind) VALUES (bu, 'asset_group') RETURNING library_entry.id INTO id;
  PERFORM rlsfx.version('library_version', id, jsonb_set((SELECT doc FROM rlsfx.tmpl WHERE kind = 'asset_group'), '{members}',
    jsonb_build_array(jsonb_build_object('id', a, 'version', 1))));
  RETURN id;
END $$;
CREATE FUNCTION rlsfx.scenario(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE a uuid := rlsfx.entry('asset', bu); tc uuid := rlsfx.entry('threat_community', bu); c uuid := rlsfx.control(bu); id uuid; d jsonb;
BEGIN
  d := (SELECT doc FROM rlsfx.tmpl WHERE kind = 'scenario')
    || jsonb_build_object('asset', jsonb_build_object('kind', 'asset', 'id', a, 'version', 1),
                          'threat_community', jsonb_build_object('id', tc, 'version', 1),
                          'control_sets', jsonb_build_array(jsonb_build_object('name', 'Current', 'current', true,
                            'controls', jsonb_build_array(jsonb_build_object('id', c, 'version', 1, 'status', 'in_place')))));
  INSERT INTO risk.scenario (bu_id) VALUES (bu) RETURNING scenario.id INTO id;
  PERFORM rlsfx.version('scenario_version', id, d);
  RETURN id;
END $$;
GRANT USAGE ON SCHEMA rlsfx TO app_rw;
GRANT SELECT ON rlsfx.tmpl TO app_rw;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rlsfx TO app_rw;
GRANT EXECUTE ON FUNCTION risk.canonical(jsonb) TO app_rw;`)
}

// TestRiskValidationParity: the database's check reaches the service's
// verdict on every corpus case, with a problem at the same pointer.
func TestRiskValidationParity(t *testing.T) {
	e := setup(t)
	conn := e.adminConn()
	check := func(kind string, doc []byte) []string {
		var problems []string
		if err := conn.QueryRow(context.Background(), "SELECT risk.check_document($1, $2)", kind, doc).Scan(&problems); err != nil {
			t.Fatal(err)
		}
		return problems
	}
	for _, c := range modeltest.Corpus() {
		doc := c.Doc
		if c.Valid {
			d, p := riskmodel.Validate(c.Kind, c.Doc)
			if p != nil {
				t.Fatalf("%s: %v", c.Name, p)
			}
			doc = d.Canonical
		} else if b, err := canon.Canonicalize(c.Doc); err == nil {
			doc = b // as the service would store it, were it valid
		}
		problems := check(c.Kind, doc)
		switch {
		case c.Valid && len(problems) > 0:
			t.Errorf("%s: the database refuses a valid document: %v", c.Name, problems)
		case !c.Valid && len(problems) == 0:
			t.Errorf("%s: the database accepts an invalid document", c.Name)
		case !c.Valid && !hasPointer(problems, c.Pointer):
			t.Errorf("%s: no database problem at %q: %v", c.Name, c.Pointer, problems)
		}
	}
	// What only the database sees: bytes that are not canonical.
	valid, _ := canonicalDoc(t, "asset", modeltest.Asset())
	var indented map[string]any
	_ = json.Unmarshal(valid, &indented)
	pretty, _ := json.MarshalIndent(indented, "", " ")
	for name, doc := range map[string][]byte{
		"indented":             pretty,
		"number for a decimal": []byte(strings.Replace(string(valid), `"max":"8000000"`, `"max":8000000`, 1)),
		"float":                []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1.0`, 1)),
		"not UTF-8":            append([]byte(nil), 0xff),
		"empty":                {},
	} {
		if p := check("asset", doc); len(p) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if p := check("asset", valid); len(p) != 0 {
		t.Fatalf("valid asset: %v", p)
	}
}

func hasPointer(problems []string, ptr string) bool {
	for _, p := range problems {
		if strings.HasPrefix(p, ptr+": ") {
			return true
		}
	}
	return false
}

// riskFixture: docFixture's BUs; analyst is a Risk Analyst at A, erin an
// Executive Viewer at A (docFixture), mallory a Risk Analyst at B.
type riskEnv struct {
	*env
	bu map[string]string
}

func riskFixture(t *testing.T) riskEnv {
	e := docFixture(t)
	e.mustOwner(grant("platform", "user:analyst", "Risk Analyst", "A"))
	e.mustOwner(grant("platform", "user:mallory", "Risk Analyst", "B"))
	e.drain()
	bu := map[string]string{}
	for _, c := range []string{"ENTERPRISE", "A", "A1", "B", "R"} {
		bu[c] = e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + c + "'")
	}
	return riskEnv{e, bu}
}

// tx runs fn as app_rw under user's context and commits.
func (r riskEnv) tx(user string, fn func(tx pgx.Tx) error) error {
	ctx := context.Background()
	tx, err := r.appPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if user != "" {
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", r.mint(user, ctxKey1)); err != nil {
			return err
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// newHead creates a head and returns its id.
func (r riskEnv) newHead(user, table, bu, kind string) (string, error) {
	var id string
	err := r.tx(user, func(tx pgx.Tx) error {
		q, args := "INSERT INTO risk."+table+" (bu_id) VALUES ($1) RETURNING id::text", []any{bu}
		if table == "library_entry" {
			q, args = "INSERT INTO risk.library_entry (bu_id, kind) VALUES ($1, $2) RETURNING id::text", []any{bu, kind}
		}
		return tx.QueryRow(context.Background(), q, args...).Scan(&id)
	})
	return id, err
}

var headColumn = map[string]string{"scenario_version": "scenario_id", "library_version": "entry_id", "control_version": "control_id"}

func (r riskEnv) addVersion(user, table, head string, version int, doc []byte, digest string) error {
	return r.tx(user, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), fmt.Sprintf("INSERT INTO risk.%s (%s, version, document, digest, change_note) VALUES ($1, $2, $3, $4, 'test')",
			table, headColumn[table]), head, version, doc, digest)
		return err
	})
}

// create makes a head with a valid version 1 of doc.
func (r riskEnv) create(t *testing.T, user, kind, bu string, doc map[string]any) string {
	t.Helper()
	table, versions := "library_entry", "library_version"
	switch kind {
	case "scenario":
		table, versions = "scenario", "scenario_version"
	case "control":
		table, versions = "control", "control_version"
	}
	id, err := r.newHead(user, table, bu, kind)
	if err != nil {
		t.Fatalf("%s head: %v", kind, err)
	}
	b, d := canonicalDoc(t, kind, doc)
	if err := r.addVersion(user, versions, id, 1, b, d); err != nil {
		t.Fatalf("%s version: %v", kind, err)
	}
	return id
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code + " " + pe.Message + " " + pe.Detail
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func TestRiskVersions(t *testing.T) {
	r := riskFixture(t)
	tc := r.create(t, "analyst", "threat_community", r.bu["A"], modeltest.ThreatCommunity())
	if got := r.adminQuery("SELECT e.current_version || '/' || (e.created_by = " + uid("analyst") + ") || '/' || (v.author = " + uid("analyst") + ") || '/' || (v.bu_id = e.bu_id) FROM risk.library_entry e JOIN risk.library_version v ON v.entry_id = e.id WHERE e.id = '" + tc + "'"); got != "1/true/true/true" {
		t.Fatalf("head and version: %s", got)
	}
	doc := modeltest.ThreatCommunity()
	doc["name"] = "Organised crime"
	b, d := canonicalDoc(t, "threat_community", doc)
	// Stale and skipped versions (AC-15: optimistic concurrency).
	for _, v := range []int{1, 3} {
		if err := r.addVersion("analyst", "library_version", tc, v, b, d); !strings.HasPrefix(pgCode(err), "PF017") {
			t.Errorf("version %d: %s", v, pgCode(err))
		}
	}
	// A wrong digest, an invalid and a non-canonical document (AC-05, AC-06).
	if err := r.addVersion("analyst", "library_version", tc, 2, b, strings.Repeat("0", 64)); !strings.HasPrefix(pgCode(err), "PF016") {
		t.Errorf("wrong digest: %s", pgCode(err))
	}
	bad := strings.Replace(string(b), `"min":"30"`, `"min":"95"`, 1)
	if err := r.addVersion("analyst", "library_version", tc, 2, []byte(bad), canon.Digest([]byte(bad))); !strings.Contains(pgCode(err), "/threat_capability: must be ordered") {
		t.Errorf("unordered estimate: %s", pgCode(err))
	}
	pretty := strings.Replace(string(b), `,"kind"`, `, "kind"`, 1)
	if err := r.addVersion("analyst", "library_version", tc, 2, []byte(pretty), canon.Digest([]byte(pretty))); !strings.Contains(pgCode(err), "not in canonical form") {
		t.Errorf("non-canonical: %s", pgCode(err))
	}
	// A document of another kind.
	cb, cd := canonicalDoc(t, "control", modeltest.Control())
	if err := r.addVersion("analyst", "library_version", tc, 2, cb, cd); !strings.Contains(pgCode(err), "/kind") {
		t.Errorf("wrong kind: %s", pgCode(err))
	}
	if err := r.addVersion("analyst", "library_version", tc, 2, b, d); err != nil {
		t.Fatalf("version 2: %v", err)
	}
	// Read-only and out-of-scope users cannot add versions; nor can a
	// missing context.
	// (A head the caller cannot write is no head to it: PF017.)
	for user, want := range map[string]string{"erin": "PF017", "mallory": "PF017", "": "PF016"} {
		if err := r.addVersion(user, "library_version", tc, 3, b, d); !strings.Contains(pgCode(err), want) {
			t.Errorf("%q adds a version: %s", user, pgCode(err))
		}
	}
	// Archived heads refuse versions until restored.
	if err := r.tx("analyst", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT risk.set_archived('library', $1, true)", tc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.addVersion("analyst", "library_version", tc, 3, b, d); !strings.Contains(pgCode(err), "archived") {
		t.Errorf("archived: %s", pgCode(err))
	}
}

func TestRiskAppendOnly(t *testing.T) {
	r := riskFixture(t)
	tc := r.create(t, "analyst", "threat_community", r.bu["A"], modeltest.ThreatCommunity())
	// The application role: no updates or deletes of versions, no writes to
	// heads but archived_at, no attribution of its own.
	for _, q := range []string{
		"UPDATE risk.library_version SET change_note = 'x'",
		"DELETE FROM risk.library_version",
		"UPDATE risk.library_entry SET current_version = 5",
		"UPDATE risk.library_entry SET bu_id = bu_id",
		"UPDATE risk.library_entry SET kind = 'asset'",
		"DELETE FROM risk.library_entry",
		"INSERT INTO risk.library_entry (bu_id, kind, created_by) VALUES ('" + r.bu["A"] + "', 'asset', " + uid("erin") + ")",
		"INSERT INTO risk.library_pin (entry_id, version, bu_id, pointer, to_kind, to_id, to_version) VALUES ('" + tc + "', 1, '" + r.bu["A"] + "', '/x', 'asset', '" + tc + "', 1)",
		"INSERT INTO risk.instance (currency, set_by) VALUES ('USD', 'x')",
		// The author is the context's user, never the caller's choice.
		"INSERT INTO risk.library_version (entry_id, version, document, digest, change_note, author) SELECT entry_id, 2, document, digest, 'x', " + uid("erin") + " FROM risk.library_version",
	} {
		if err := r.tx("analyst", func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), q); return err }); !strings.Contains(pgCode(err), "permission denied") {
			t.Errorf("%s: %s", q, pgCode(err))
		}
	}
	// Even the owner cannot change history (PF018).
	for _, q := range []string{
		"UPDATE risk.library_version SET change_note = 'x'",
		"DELETE FROM risk.library_version",
		"TRUNCATE risk.library_version CASCADE",
		"DELETE FROM risk.library_entry",
		"UPDATE risk.library_entry SET current_version = current_version + 2",
		"UPDATE risk.library_entry SET kind = 'asset'",
		"UPDATE risk.library_entry SET created_by = " + uid("erin"),
	} {
		// As the superuser, past RLS, so the triggers see the rows.
		if _, err := r.adminConn().Exec(context.Background(), q); !strings.HasPrefix(pgCode(err), "PF018") {
			t.Errorf("%s: %s", q, pgCode(err))
		}
	}
	if got := r.adminQuery("SELECT count(*) FROM risk.library_version"); got != "1" {
		t.Fatalf("versions: %s", got)
	}
}

func TestRiskPins(t *testing.T) {
	r := riskFixture(t)
	r.mustOwner(grant("platform", "user:buadmin", "Risk Analyst", "ENTERPRISE"))
	r.drain()
	// An asset at the root (buadmin's), library at A; analyst's scenario at
	// A1 pins them: the root's asset by inherited read.
	asset := r.create(t, "buadmin", "asset", r.bu["ENTERPRISE"], modeltest.Asset())
	tc := r.create(t, "analyst", "threat_community", r.bu["A"], modeltest.ThreatCommunity())
	ctl := r.create(t, "analyst", "control", r.bu["A"], modeltest.Control())
	scenario := func(assetID, assetKind, tcID string, ctlVersion int) map[string]any {
		d := modeltest.Scenario()
		modeltest.Set(d, "/asset", map[string]any{"kind": assetKind, "id": assetID, "version": 1})
		modeltest.Set(d, "/threat_community", map[string]any{"id": tcID, "version": 1})
		modeltest.Set(d, "/control_sets", []any{map[string]any{"name": "Current", "current": true, "controls": []any{
			map[string]any{"id": ctl, "version": ctlVersion, "status": "in_place"}}}})
		return d
	}
	s := r.create(t, "analyst", "scenario", r.bu["A1"], scenario(asset, "asset", tc, 1))
	if got := r.adminQuery("SELECT string_agg(pointer || '>' || to_kind || '@' || to_version, ',' ORDER BY pointer) FROM risk.scenario_pin WHERE scenario_id = '" + s + "'"); got != "/asset>asset@1,/control_sets/0/controls/0>control@1,/threat_community>threat_community@1" {
		t.Fatalf("pins: %s", got)
	}
	// Pins that do not resolve: a missing version, a wrong kind, an entry
	// the writer cannot see (B's, written by mallory).
	hidden := r.create(t, "mallory", "threat_community", r.bu["B"], modeltest.ThreatCommunity())
	for name, d := range map[string]map[string]any{
		"missing version": scenario(asset, "asset", tc, 2),
		"wrong kind":      scenario(tc, "asset", tc, 1),
		"not visible":     scenario(asset, "asset", hidden, 1),
		"group not asset": scenario(asset, "asset_group", tc, 1),
	} {
		id, err := r.newHead("analyst", "scenario", r.bu["A1"], "")
		if err != nil {
			t.Fatal(err)
		}
		b, dg := canonicalDoc(t, "scenario", d)
		if err := r.addVersion("analyst", "scenario_version", id, 1, b, dg); !strings.HasPrefix(pgCode(err), "PF016") {
			t.Errorf("%s: %s", name, pgCode(err))
		}
	}
	// Asset group members are library pins.
	g := modeltest.AssetGroup()
	modeltest.Set(g, "/members", []any{map[string]any{"id": asset, "version": 1}})
	grp := r.create(t, "analyst", "asset_group", r.bu["A"], g)
	if got := r.adminQuery("SELECT pointer || '>' || to_id FROM risk.library_pin WHERE entry_id = '" + grp + "'"); got != "/members/0>"+asset {
		t.Fatalf("group pins: %s", got)
	}
	// Erin (a viewer at A) reads the scenario's pins and, by inherited
	// read, the root's asset. Mallory (at B) inherits the root's asset too,
	// but sees nothing of A's.
	if got, err := r.asCtx(r.mint("erin", ctxKey1), "SELECT count(*) FROM risk.scenario_pin WHERE scenario_id = '"+s+"'; SELECT count(*) FROM risk.library_entry WHERE id = '"+asset+"'"); err != nil || got != "3\n1" {
		t.Errorf("erin: %q %v", got, err)
	}
	if got, err := r.asCtx(r.mint("mallory", ctxKey1), "SELECT count(*) FROM risk.scenario_pin; SELECT count(*) FROM risk.library_entry WHERE id IN ('"+asset+"', '"+tc+"')"); err != nil || got != "0\n1" {
		t.Errorf("mallory: %q %v", got, err)
	}

	// Each pin holds a copy of the pinned version (design §4.4).
	if got := r.adminQuery(`SELECT count(*) FILTER (WHERE p.to_digest = v.digest AND p.to_document = v.document) || '/' || count(*)
		FROM risk.scenario_pin p JOIN (SELECT entry_id AS id, version, digest, document FROM risk.library_version
		  UNION ALL SELECT control_id, version, digest, document FROM risk.control_version) v ON v.id = p.to_id AND v.version = p.to_version
		WHERE p.scenario_id = '` + s + `'`); got != "3/3" {
		t.Fatalf("pin copies: %s", got)
	}
	// A reader of scenarios only (no library.view) at A1 sees what the
	// scenario uses, through its pins, and nothing of the library.
	r.mustOwner(`WITH ro AS (INSERT INTO iam.role (name) VALUES ('Scenario Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['scenario.view'], 'test' FROM ro`)
	r.mustOwner(grant("platform", "user:buadmin2", "Scenario Reader", "A1"))
	r.drain()
	if got, err := r.asCtx(r.mint("buadmin2", ctxKey1), "SELECT count(*) FROM risk.scenario_pin WHERE scenario_id = '"+s+"' AND length(to_document) > 0; SELECT count(*) FROM risk.library_version; SELECT count(*) FROM risk.control_version"); err != nil || got != "3\n0\n0" {
		t.Errorf("scenario reader: %q %v", got, err)
	}
}

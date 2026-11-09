package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-003 T-11 (AC-24, AC-25): fair.risk.v1 export and import.
func TestRiskExportImport(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t) // asset, threat community and control at A
	tcID := doc["threat_community"].(map[string]any)["id"].(string)
	// An asset group of the asset, at A, as the scenario's asset.
	got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset_group",
		"document":    modeltest.Set(modeltest.AssetGroup(), "/members", []any{map[string]any{"id": doc["asset"].(map[string]any)["id"], "version": 1}}),
		"change_note": "Group"})
	if got.code != 201 {
		t.Fatalf("group: %d %s", got.code, got.raw)
	}
	modeltest.Set(doc, "/asset", map[string]any{"kind": "asset_group", "id": got.body["id"], "version": 1})
	got = ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	// v2 changes the name; v3 adopts the threat community's version 2.
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+sid, map[string]any{"document": modeltest.Set(doc, "/name", "Renamed"), "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("v2: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+tcID, map[string]any{"document": modeltest.Set(modeltest.ThreatCommunity(), "/name", "TC v2"), "expected_version": 1, "change_note": "x"}); got.code != 200 {
		t.Fatalf("tc v2: %d", got.code)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/adopt", map[string]any{"expected_version": 2, "change_note": "v3"}); got.code != 200 {
		t.Fatalf("v3: %d %s", got.code, got.raw)
	}

	schema := func() *jsonschema.Schema {
		b, err := os.ReadFile("../../docs/formats/fair-risk-v1.schema.json")
		if err != nil {
			t.Fatal(err)
		}
		d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		c := jsonschema.NewCompiler()
		if err := c.AddResource("urn:fair:risk:transfer:1", d); err != nil {
			t.Fatal(err)
		}
		s, err := c.Compile("urn:fair:risk:transfer:1")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()
	export := func(user, q string) (map[string]any, string) {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/risk/export?"+q, nil)
		if got.code != 200 {
			t.Fatalf("export %s as %s: %d %s", q, user, got.code, got.raw)
		}
		// The body is canonical, its digest in the header, and it follows
		// the published schema.
		if c, err := canon.Canonicalize([]byte(got.raw)); err != nil || string(c) != got.raw {
			t.Fatalf("not canonical: %v", err)
		}
		if h := got.hdr.Get("X-Fair-Digest"); h != "sha256="+canon.Digest([]byte(got.raw)) {
			t.Fatalf("digest header %q", h)
		}
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(got.raw))
		if err := schema.Validate(inst); err != nil {
			t.Fatalf("the file does not follow its schema: %v", err)
		}
		return got.body, got.raw
	}
	count := func(f map[string]any, k string) int { return len(f[k].([]any)) }

	// The scenario alone: its three versions, and every version it pins,
	// from its pin rows (the group, its member, both threat community
	// versions, the control).
	one, oneRaw := export("analyst", "scenarios="+sid)
	if count(one, "scenarios") != 1 || count(one, "library") != 0 || count(one, "controls") != 0 || count(one, "pinned") != 5 ||
		len(one["scenarios"].([]any)[0].(map[string]any)["versions"].([]any)) != 3 || one["currency"] != "USD" {
		t.Fatalf("scenario export: %s", oneRaw)
	}
	// A subtree: everything at A and below, so nothing is only pinned.
	sub, _ := export("analyst", "bu="+ra.bu["A"])
	if count(sub, "scenarios") != 1 || count(sub, "library") != 3 || count(sub, "controls") != 1 || count(sub, "pinned") != 0 {
		t.Fatalf("subtree export: %v", sub)
	}
	// Only what the requester sees.
	if got := ra.call(t, "GET", "mallory", "/api/v1/risk/export?scenarios="+sid, nil); got.code != 404 {
		t.Fatalf("an unseen scenario: %d", got.code)
	}
	if empty, _ := export("mallory", "bu="+ra.bu["A"]); count(empty, "scenarios")+count(empty, "library")+count(empty, "controls") != 0 {
		t.Fatalf("mallory's export of A: %v", empty)
	}
	for _, q := range []string{"", "scenarios=nope", "bu=x"} {
		if got := ra.call(t, "GET", "analyst", "/api/v1/risk/export?"+q, nil); got.code != 400 {
			t.Errorf("export %q: %d", q, got.code)
		}
	}
	if ev := ra.adminQuery(`SELECT string_agg((body -> 'attributes' ->> 'scenarios') || '/' || (body -> 'attributes' ->> 'pinned'), ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' = 'risk.exported' AND body ->> 'actor' = (SELECT id::text FROM iam.app_user WHERE email = 'analyst@example.test')`); ev != "1/5,1/0" {
		t.Fatalf("export events: %s", ev)
	}

	imp := func(user, bu string, file map[string]any, dry bool) apiResp {
		t.Helper()
		q := ""
		if dry {
			q = "?dry_run=true"
		}
		return ra.call(t, "POST", user, "/api/v1/risk/imports"+q, map[string]any{"bu_id": bu, "file": file})
	}
	inB := func() string {
		return ra.adminQuery("SELECT (SELECT count(*) FROM risk.scenario WHERE bu_id = '" + ra.bu["B"] + "') || '/' || (SELECT count(*) FROM risk.library_entry WHERE bu_id = '" + ra.bu["B"] + "') || '/' || (SELECT count(*) FROM risk.control WHERE bu_id = '" + ra.bu["B"] + "')")
	}

	// Into B by mallory: the subtree file, a dry run first.
	got = imp("mallory", ra.bu["B"], sub, true)
	if got.code != 200 || got.body["dry_run"] != true || len(got.body["created"].([]any)) != 5 {
		t.Fatalf("dry run: %d %s", got.code, got.raw)
	}
	if n := inB(); n != "0/0/0" {
		t.Fatalf("a dry run wrote: %s", n)
	}
	got = imp("mallory", ra.bu["B"], sub, false)
	if got.code != 201 {
		t.Fatalf("import: %d %s", got.code, got.raw)
	}
	if n := inB(); n != "1/3/1" {
		t.Fatalf("after the import: %s", n)
	}
	// The scenario's history was replayed, its pins re-pointed into B.
	newSID := ra.adminQuery("SELECT id FROM risk.scenario WHERE bu_id = '" + ra.bu["B"] + "'")
	if got := ra.adminQuery("SELECT current_version || '/' || name FROM risk.scenario WHERE id = '" + newSID + "'"); got != "3/Renamed" {
		t.Fatalf("imported scenario: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FILTER (WHERE to_bu_id = '" + ra.bu["B"] + "') || '/' || count(*) FROM risk.scenario_pin WHERE scenario_id = '" + newSID + "' AND version = 3"); got != "4/4" {
		t.Fatalf("imported pins: %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(change_note, ',' ORDER BY version) FROM risk.scenario_version WHERE scenario_id = '" + newSID + "'"); got != "v1,v2,v3" {
		t.Fatalf("change notes: %s", got)
	}

	// The scenario-only file into B: its pinned versions become entries at
	// version 1 (mallory cannot see A's).
	got = imp("mallory", ra.bu["B"], one, false)
	if got.code != 201 {
		t.Fatalf("import with pinned: %d %s", got.code, got.raw)
	}
	reused := 0
	for _, c := range got.body["created"].([]any) {
		if c.(map[string]any)["reused"] == true {
			reused++
		}
	}
	if len(got.body["created"].([]any)) != 6 || reused != 0 {
		t.Fatalf("created: %s", got.raw)
	}
	// ...and back into A by the analyst, who has those versions: reused.
	got = imp("analyst", ra.bu["A"], one, true)
	reused = 0
	for _, c := range got.body["created"].([]any) {
		if c.(map[string]any)["reused"] == true {
			reused++
		}
	}
	if got.code != 200 || reused != 5 {
		t.Fatalf("reuse: %d %s", got.code, got.raw)
	}

	// Refusals: every problem listed, nothing written.
	before := inB()
	tampered := clone(t, one)
	pinned := tampered["pinned"].([]any)
	pinned[0].(map[string]any)["digest"] = strings.Repeat("0", 64)
	sv := tampered["scenarios"].([]any)[0].(map[string]any)["versions"].([]any)
	sv[1].(map[string]any)["document"].(map[string]any)["name"] = ""
	got = imp("mallory", ra.bu["B"], tampered, false)
	if got.code != 422 || !strings.Contains(got.raw, "does not match its digest") || !strings.Contains(got.raw, `"pointer":"/name"`) {
		t.Fatalf("tampered: %d %s", got.code, got.raw)
	}
	if n := inB(); n != before {
		t.Fatalf("a refused import wrote: %s -> %s", before, n)
	}
	// A pin neither in the file nor visible to the importer.
	short := clone(t, one)
	short["pinned"] = short["pinned"].([]any)[1:]
	if got := imp("mallory", ra.bu["B"], short, false); got.code != 422 || !strings.Contains(got.raw, "neither in the file nor visible") {
		t.Fatalf("missing pin: %d %s", got.code, got.raw)
	}
	// Another currency.
	eur := clone(t, one)
	eur["currency"] = "EUR"
	if got := imp("mallory", ra.bu["B"], eur, false); got.code != 422 || !strings.Contains(got.raw, `"pointer":"/currency"`) {
		t.Fatalf("currency: %d %s", got.code, got.raw)
	}
	// Not the format; no permission.
	bad := clone(t, one)
	bad["format"] = "other"
	if got := imp("mallory", ra.bu["B"], bad, false); got.code != 422 {
		t.Fatalf("format: %d", got.code)
	}
	if got := imp("erin", ra.bu["A"], one, false); got.code != 403 {
		t.Fatalf("viewer imports: %d", got.code)
	}
	if n := inB(); n != before {
		t.Fatalf("refusals wrote: %s -> %s", before, n)
	}
	if ev := ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'risk.imported'`); ev != "2" {
		t.Fatalf("import events: %s", ev)
	}
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(m)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

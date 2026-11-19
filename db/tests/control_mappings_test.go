package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/authz"
)

func mapping(framework, version, req, strength string) map[string]any {
	return map[string]any{"framework": framework, "version": version, "requirement": req, "strength": strength}
}

// F-013 T-06 (F-013-AC-07 to AC-09, AC-19, AC-20; design §3.4): mappings in
// a control's versioned document, checked by the database against the
// imported frameworks, projected under row-level security, recorded when
// they change; suggestions from plain references and newer versions.
func TestControlMappings(t *testing.T) {
	fe := frameworkAPI(t)
	ra := fe.risk
	doc := modeltest.Control()
	doc["mappings"] = []any{mapping("nist-800-53", "5.2.0", "ac-2", "full"), mapping("nist-800-53", "5.2.0", "ac-2.1", "supports")}
	got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "document": doc, "change_note": "Mapped"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	rows := func(where string) string {
		t.Helper()
		return ra.adminQuery(`SELECT coalesce(string_agg(r.identifier || ':' || m.strength || ':' || m.control_version || ':' || m.current, ',' ORDER BY m.control_version, r.identifier), '-')
			FROM framework.control_mapping m JOIN framework.requirement r ON r.id = m.requirement_id WHERE m.control_id = '` + id + `'` + where)
	}
	if got := rows(""); got != "ac-2:full:1:true,ac-2.1:supports:1:true" {
		t.Errorf("projection %s", got)
	}

	// Problems: a requirement that does not exist, one withdrawn, a bad
	// strength; the document is refused, by pointer.
	for name, c := range map[string]struct {
		m       map[string]any
		pointer string
	}{
		"an unknown requirement": {mapping("nist-800-53", "5.2.0", "zz-1", "full"), "/mappings/0/requirement"},
		"a withdrawn one":        {mapping("nist-800-53", "5.2.0", "ac-13", "full"), "/mappings/0/requirement"},
		"an unknown version":     {mapping("nist-800-53", "9.9", "ac-2", "full"), "/mappings/0/requirement"},
		"a bad strength":         {mapping("nist-800-53", "5.2.0", "ac-2", "most"), "/mappings/0/strength"},
	} {
		d := modeltest.Control()
		d["mappings"] = []any{c.m}
		got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+id, map[string]any{"document": d, "expected_version": 1, "change_note": "x"})
		if got.code != 422 || !strings.Contains(got.raw, c.pointer) {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// A new version: ac-2.1 removed, ac-3 added, and in place; the previous
	// rows stay (as of a date) but are not current.
	doc2 := modeltest.Control()
	doc2["mappings"] = []any{mapping("nist-800-53", "5.2.0", "ac-2", "full"), mapping("nist-800-53", "5.2.0", "ac-3", "partial")}
	doc2["implementation"] = map[string]any{"status": "in_place", "assessed_on": "2026-11-15"}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+id, map[string]any{"document": doc2, "expected_version": 1, "change_note": "Remapped"}); got.code != 200 {
		t.Fatalf("save: %d %s", got.code, got.raw)
	}
	if got := rows(" AND m.current"); got != "ac-2:full:2:true,ac-3:partial:2:true" {
		t.Errorf("current projection %s", got)
	}
	if got := rows(" AND NOT m.current"); got != "ac-2:full:1:false,ac-2.1:supports:1:false" {
		t.Errorf("previous projection %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(DISTINCT implementation, ',') FROM framework.control_mapping WHERE control_id = '" + id + "' AND current"); got != "in_place" {
		t.Errorf("implementation %s", got)
	}
	// AC-19: what changed, with the author and BU.
	ev := ra.adminQuery(`SELECT body -> 'attributes' ->> 'added' || ' | ' || (body -> 'attributes' ->> 'removed') FROM audit.intake
		WHERE body ->> 'type' = 'control.mappings_changed' AND body -> 'attributes' ->> 'version' = '2' AND body ->> 'actor' = (` + uid("analyst") + `)::text
		AND body ->> 'bu_id' = '` + ra.bu["A"] + `'`)
	if ev != "nist-800-53 5.2.0 ac-3 partial | nist-800-53 5.2.0 ac-2.1 supports" {
		t.Errorf("mappings_changed: %q", ev)
	}
	// A save that keeps the mappings records no change of them.
	doc2["description"] = "Reworded"
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+id, map[string]any{"document": doc2, "expected_version": 2, "change_note": "Reworded"}); got.code != 200 {
		t.Fatalf("save 3: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'control.mappings_changed' AND body ->> 'target' = 'control:" + id + "'"); n != "2" {
		t.Errorf("%s mappings_changed events, want 2", n)
	}

	// Row-level security: B's analyst does not see A's mapping rows.
	count := func(user string) string {
		var n string
		if err := authz.WithDBContext(context.Background(), ra.appPool(), ra.principal(user).DBToken, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*)::text FROM framework.control_mapping WHERE control_id = $1", id).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if a, m := count("analyst"), count("mallory"); a == "0" || m != "0" {
		t.Errorf("visible rows: analyst %s, mallory %s", a, m)
	}

	// Archiving the control carries to its rows.
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls/"+id+"/archive", map[string]any{"reason": "Replaced"}); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM framework.control_mapping WHERE control_id = '" + id + "' AND archived_at IS NULL"); n != "0" {
		t.Errorf("%s rows not archived", n)
	}

	// AC-08: plain references become suggested mappings (the fixture cites
	// "NIST SP 800-53r5" "SI-4"); AC-09: mappings to 5.1.1 have equivalents
	// in 5.2.0.
	old := modeltest.Control()
	old["references"] = []any{map[string]any{"framework": "NIST SP 800-53r5", "identifier": "SI-4"}, map[string]any{"framework": "NIST SP 800-53", "identifier": "AC-02(01)"},
		map[string]any{"framework": "ISO 27001", "identifier": "A.8.7"}}
	old["mappings"] = []any{mapping("nist-800-53", "5.1.1+u4", "ac-2", "full")}
	got = ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "document": old, "change_note": "Old"})
	if got.code != 201 {
		t.Fatalf("create old: %d %s", got.code, got.raw)
	}
	oid := got.body["id"].(string)
	sug := fe.call(t, "GET", "analyst", "/api/v1/controls/"+oid+"/suggested-mappings", nil)
	if sug.code != 200 || !strings.Contains(sug.raw, `"requirement":"si-4"`) || !strings.Contains(sug.raw, `"requirement":"ac-2.1"`) || strings.Contains(sug.raw, "A.8.7") {
		t.Errorf("suggestions: %d %s", sug.code, sug.raw)
	}
	upd := fe.call(t, "GET", "analyst", "/api/v1/controls/"+oid+"/mapping-updates", nil)
	if upd.code != 200 || !strings.Contains(upd.raw, `"to_version":"5.2.0"`) || !strings.Contains(upd.raw, `"requirement":"ac-2"`) {
		t.Errorf("updates: %d %s", upd.code, upd.raw)
	}
	for user, code := range map[string]int{"erin": 403, "mallory": 404} {
		if got := fe.call(t, "GET", user, "/api/v1/controls/"+oid+"/suggested-mappings", nil); got.code != code {
			t.Errorf("%s: %d", user, got.code)
		}
	}
}

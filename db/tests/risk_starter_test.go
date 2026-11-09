package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/risk/starter"
)

// F-003 T-10 (AC-11): the starter library is synced at migrate, read-only,
// and copied into a BU as an ordinary entry.
func TestRiskStarter(t *testing.T) {
	ra := newRiskAPI(t)
	lib, err := starter.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT count(*) || '/' || bool_and(illustrative) || '/' || min(release) FROM risk.starter_entry"); got != "12/true/"+lib.Release {
		t.Fatalf("synced: %s", got)
	}
	// Idempotent: a second migrate changes nothing.
	res, err := ra.migrate("")
	if err != nil || len(res.Starter.Added)+len(res.Starter.Changed)+len(res.Starter.Removed) != 0 {
		t.Fatalf("second sync: %+v %v", res.Starter, err)
	}
	// A release without an entry removes it; the next restores it.
	payload, _ := starter.SyncPayload()
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	p["entries"] = p["entries"].([]any)[1:]
	short, _ := json.Marshal(p)
	var out string
	if err := ra.adminConn().QueryRow(context.Background(), "SELECT risk.sync_starter($1::jsonb)::text", string(short)).Scan(&out); err != nil ||
		!strings.Contains(out, `"removed": ["threat_community.cyber_criminals"]`) {
		t.Fatalf("removal: %s %v", out, err)
	}
	if res, err := ra.migrate(""); err != nil || strings.Join(res.Starter.Added, ",") != "threat_community.cyber_criminals" {
		t.Fatalf("restore: %+v %v", res.Starter, err)
	}
	// Nobody edits it; only migrate syncs it.
	for _, q := range []string{"UPDATE risk.starter_entry SET guidance = 'x'", "DELETE FROM risk.starter_entry",
		"INSERT INTO risk.starter_entry (key, release, kind, illustrative, guidance, document, digest) VALUES ('a.b', 'x', 'asset', true, 'x', '\\x00', repeat('0', 64))",
		"SELECT risk.sync_starter('{}')"} {
		ra.mustFail("app_rw", q, "permission denied")
	}

	// Read through the API with library.view somewhere.
	if got := ra.call(t, "GET", "buadmin2", "/api/v1/library/starter", nil); got.code != 404 {
		t.Fatalf("no permission: %d", got.code)
	}
	got := ra.call(t, "GET", "erin", "/api/v1/library/starter", nil)
	if got.code != 200 || len(got.body["entries"].([]any)) != 12 {
		t.Fatalf("list: %d %s", got.code, got.raw)
	}
	for _, e := range got.body["entries"].([]any) {
		m := e.(map[string]any)
		if m["illustrative"] != true || m["guidance"] == "" || m["name"] == "" {
			t.Fatalf("entry: %v", m)
		}
	}

	// Copy: library.edit at the BU; amounts wait for the currency.
	copyEntry := func(user, key, bu string) apiResp {
		t.Helper()
		return ra.call(t, "POST", user, "/api/v1/library/starter/"+key+"/copy", map[string]any{"bu_id": bu})
	}
	if got := copyEntry("erin", "threat_community.cyber_criminals", ra.bu["A"]); got.code != 403 {
		t.Fatalf("viewer copies: %d", got.code)
	}
	if got := copyEntry("mallory", "threat_community.cyber_criminals", ra.bu["A"]); got.code != 404 {
		t.Fatalf("outsider copies: %d", got.code)
	}
	for _, key := range []string{"threat_community.nothing", "Not A Key"} {
		if got := copyEntry("analyst", key, ra.bu["A"]); got.code != 404 {
			t.Errorf("copy %q: %d", key, got.code)
		}
	}
	if got := copyEntry("analyst", "loss_guidance.response", ra.bu["A"]); got.code != 409 || got.body["error"] != "currency_not_set" {
		t.Fatalf("amounts before the currency: %d %s", got.code, got.raw)
	}
	got = copyEntry("analyst", "threat_community.cyber_criminals", ra.bu["A"])
	if got.code != 201 || got.body["origin"] != "threat_community.cyber_criminals@"+lib.Release || got.body["kind"] != "threat_community" {
		t.Fatalf("copy: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	ra.setCurrency(t, "USD")
	if got := copyEntry("analyst", "loss_guidance.response", ra.bu["A"]); got.code != 201 {
		t.Fatalf("copy with amounts: %d %s", got.code, got.raw)
	}
	// The copy is an ordinary entry: the starter document as version 1,
	// editable; the starter entry is unchanged.
	if o := ra.adminQuery("SELECT origin FROM risk.library_entry WHERE id = '" + id + "'"); o != "threat_community.cyber_criminals@"+lib.Release {
		t.Fatalf("origin: %s", o)
	}
	if same := ra.adminQuery("SELECT v.digest = s.digest FROM risk.library_version v, risk.starter_entry s WHERE v.entry_id = '" + id + "' AND v.version = 1 AND s.key = 'threat_community.cyber_criminals'"); same != "t" {
		t.Fatalf("the copy's version 1 is not the starter document: %s", same)
	}
	adapted := modeltest.Set(modeltest.ThreatCommunity(), "/name", "Cyber criminals (our view)")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+id, map[string]any{"document": adapted, "expected_version": 1, "change_note": "Calibrated"}); got.code != 200 {
		t.Fatalf("edit the copy: %d %s", got.code, got.raw)
	}
	if ev := ra.adminQuery(`SELECT string_agg((body -> 'attributes' ->> 'kind') || '@' || (body -> 'attributes' ->> 'origin'), ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' = 'library.starter_copied'`); ev != "threat_community@threat_community.cyber_criminals@"+lib.Release+",loss_profile@loss_guidance.response@"+lib.Release {
		t.Fatalf("events: %s", ev)
	}
}

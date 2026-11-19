package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/framework/content"
)

// F-013 T-04 (F-013-AC-04; design §2, §11): a fresh install has the
// shipped frameworks, from the release alone; syncing again changes
// nothing; a shipped version whose source changed is refused, never
// rewritten.
func TestShippedFrameworks(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	got := e.install.Frameworks
	if strings.Join(got.Versions, ",") != "nist-800-53 5.2.0,nist-800-53 5.1.1+u4,nist-800-171 Rev 3 (1.1.0)" || len(got.Baselines) != 8 || len(got.Crosswalks) != 1 {
		t.Fatalf("install synced %+v", got)
	}
	for q, want := range map[string]string{
		"SELECT count(*) FROM framework.version WHERE source = 'shipped' AND state = 'active'":                                                          "3",
		"SELECT count(*) FROM framework.requirement r JOIN framework.version v ON v.id = r.version_id WHERE v.label = '5.2.0'":                          "1196",
		"SELECT r.label FROM framework.requirement r JOIN framework.version v ON v.id = r.version_id WHERE v.label = '5.2.0' AND identifier = 'ac-2.1'": "AC-2(1)",
		"SELECT count(*) FROM framework.baseline WHERE source = 'shipped'":                                                                              "8",
		"SELECT count(*) FROM framework.relationship":                                                                                                   "157",
		"SELECT count(DISTINCT relationship) FROM framework.relationship":                                                                               "1",
		`SELECT b.key FROM framework.baseline b JOIN framework.version v ON v.id = b.version_id WHERE v.label = '5.1.1+u4' ORDER BY b.key LIMIT 1`:      "fedramp-high",
	} {
		if v := e.adminQuery(q); v != want {
			t.Errorf("%s: %s, want %s", q, v, want)
		}
	}
	// The moderate baseline's selection is a subset of its version.
	if v := e.adminQuery(`SELECT count(*) FROM framework.baseline b, unnest(b.selected) s(id)
		WHERE b.key = 'nist-moderate' AND NOT EXISTS (SELECT 1 FROM framework.requirement r WHERE r.version_id = b.version_id AND r.identifier = s.id)`); v != "0" {
		t.Errorf("moderate selects %s unknown requirements", v)
	}

	payload, err := content.SyncPayload()
	if err != nil {
		t.Fatal(err)
	}
	conn := e.adminConn()
	defer func() { _ = conn.Close(ctx) }()
	sync := func(p []byte) (map[string][]string, error) {
		var raw []byte
		if err := conn.QueryRow(ctx, "SELECT framework.sync_shipped($1::jsonb)", string(p)).Scan(&raw); err != nil {
			return nil, err
		}
		var out map[string][]string
		return out, json.Unmarshal(raw, &out)
	}
	if out, err := sync(payload); err != nil || len(out["versions"])+len(out["baselines"])+len(out["crosswalks"]) != 0 {
		t.Fatalf("re-sync: %v %v", out, err)
	}
	if v := e.adminQuery("SELECT count(*) FROM framework.version"); v != "3" {
		t.Errorf("%s versions after a re-sync", v)
	}
	// A release whose 5.2.0 came from another file is refused.
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	p["versions"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("e", 64)
	changed, _ := json.Marshal(p)
	if _, err := sync(changed); pgState(err) != "PF033/shipped_changed" {
		t.Errorf("a changed shipped version: %v", err)
	}
}

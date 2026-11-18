package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// F-011 T-09 (F-011-AC-10, AC-12 to AC-14; design §3.4 as amended
// 2026-11-18): a run's records become proposals holding the source values:
// new records create, changed ones update their link's target, a newer one
// supersedes the pending one, unchanged or rejected values propose
// nothing; complete batches propose archiving what the source dropped;
// loss events are not proposed.
func TestProposals(t *testing.T) {
	im := importAPI(t)
	add := func(name, kind string) string {
		t.Helper()
		var id string
		if err := im.ie.as("platform", func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT integration.add($1, $2, $3, 'push', '{}', NULL, NULL, false)::text", im.bu["A"], name, kind).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assets, controls, events := add("CMDB", "assets"), add("GRC", "control_status"), add("Incidents", "loss_events")
	push := func(id, body string) map[string]any {
		t.Helper()
		got := im.send(t, "pusher", "/api/v1/imports/"+id+"/batches", "application/json", body)
		if got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		return got.body
	}
	pending := func(id string) string {
		return im.adminQuery("SELECT coalesce(string_agg(external_id || ':' || action || ':' || descriptive_only, ',' ORDER BY external_id, seq), '') FROM integration.proposal WHERE integration_id = '" + id + "' AND state = 'pending'")
	}

	// New records: create proposals holding the record, at its BU.
	got := push(assets, batchOf(asset("a-1", "A1", "Claims platform"), asset("a-2", "A", "Warehouse")))
	if c := got["counts"].(map[string]any); c["proposed"] != 2.0 {
		t.Errorf("counts %v", c)
	}
	if p := pending(assets); p != "a-1:create:false,a-2:create:false" {
		t.Errorf("pending: %s", p)
	}
	if got := im.adminQuery("SELECT b.code || ':' || (p.document ->> 'name') FROM integration.proposal p JOIN iam.bu b ON b.id = p.bu_id WHERE p.external_id = 'a-1'"); got != "A1:Claims platform" {
		t.Errorf("a-1's proposal: %s", got)
	}

	// Accepted (as T-10 will do): a link and an applied row.
	accept := func(ext string) {
		t.Helper()
		pid := im.adminQuery("SELECT id FROM integration.proposal WHERE integration_id = '" + assets + "' AND external_id = '" + ext + "' AND state = 'pending'")
		digest := im.adminQuery("SELECT digest FROM integration.proposal WHERE id = '" + pid + "'")
		target := im.adminQuery("SELECT gen_random_uuid()")
		im.mustOwner(fmt.Sprintf(`UPDATE integration.proposal SET state = 'accepted', decided_by = %s, decided_at = now() WHERE id = '%s'`, uid("platform"), pid))
		im.mustOwner(fmt.Sprintf(`INSERT INTO integration.applied (proposal_id, target_type, target_id, version, accepted_by) VALUES ('%s', 'asset', '%s', 1, %s)`, pid, target, uid("platform")))
		im.mustOwner(fmt.Sprintf(`INSERT INTO integration.link (integration_id, external_id, target_type, target_id, last_digest) VALUES ('%s', '%s', 'asset', '%s', '%s')`, assets, ext, target, digest))
	}
	accept("a-1")
	accept("a-2")
	if p := pending(assets); p != "" {
		t.Fatalf("pending after accepting: %s", p)
	}

	// Unchanged: nothing. A name change only: descriptive. A value change:
	// not. A newer change supersedes the pending one.
	got = push(assets, batchOf(asset("a-1", "A1", "Claims platform"), asset("a-2", "A", "Data warehouse")))
	if c := got["counts"].(map[string]any); c["unchanged"] != 1.0 || c["proposed"] != 1.0 {
		t.Errorf("counts %v", c)
	}
	if p := pending(assets); p != "a-2:update:true" {
		t.Errorf("a descriptive change: %s", p)
	}
	valued := `{"kind": "asset", "external_id": "a-2", "bu": "A", "name": "Data warehouse", "asset_type": "application", "value": {"min": "1", "ml": "2", "max": "3"}}`
	push(assets, batchOf(valued))
	if p := pending(assets); p != "a-2:update:false" {
		t.Errorf("a value change: %s", p)
	}
	if n := im.adminQuery("SELECT count(*) FROM integration.proposal WHERE external_id = 'a-2' AND state = 'superseded'"); n != "1" {
		t.Errorf("%s superseded", n)
	}
	// Rejected values are not proposed again until they change.
	pid := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'a-2' AND state = 'pending'")
	im.mustOwner(fmt.Sprintf(`UPDATE integration.proposal SET state = 'rejected', decided_by = %s, decided_at = now(), reason = 'wrong value' WHERE id = '%s'`, uid("platform"), pid))
	im.mustOwner("UPDATE integration.link SET rejected_digest = (SELECT digest FROM integration.proposal WHERE id = '" + pid + "') WHERE external_id = 'a-2'")
	if got := push(assets, batchOf(valued)); got["counts"].(map[string]any)["proposed"] != 0.0 {
		t.Errorf("a rejected value proposed again: %v", got["counts"])
	}

	// A complete batch without a-2 proposes archiving it, at the BU it was
	// accepted at, once.
	complete := `{"format": "fair.integration.v1", "complete": true, "records": [` + asset("a-1", "A1", "Claims platform") + `]}`
	if got := push(assets, complete); got["counts"].(map[string]any)["proposed"] != 1.0 {
		t.Errorf("complete batch: %v", got["counts"])
	}
	if got := im.adminQuery("SELECT p.action || ':' || b.code || ':' || (p.target_id IS NOT NULL) || ':' || (p.document IS NULL) FROM integration.proposal p JOIN iam.bu b ON b.id = p.bu_id WHERE p.external_id = 'a-2' AND p.state = 'pending'"); got != "archive:A:true:true" {
		t.Errorf("the archive proposal: %s", got)
	}
	if got := push(assets, complete); got["counts"].(map[string]any)["proposed"] != 0.0 {
		t.Errorf("a second archive proposal: %v", got["counts"])
	}

	// A record's kind matches its link's.
	group := `{"kind": "asset_group", "external_id": "a-1", "bu": "A", "name": "Group", "members": ["a-2"]}`
	if got := push(assets, batchOf(group)); len(got["refused"].([]any)) != 1 {
		t.Errorf("a group under an asset's external ID: %v", got["refused"])
	}

	// Control status: the control the first time, then the link.
	ctl := im.adminQuery("SELECT gen_random_uuid()")
	status := func(ext, control, st string) string {
		c := ""
		if control != "" {
			c = fmt.Sprintf(`"control": %q, `, control)
		}
		return fmt.Sprintf(`{"kind": "control_status", "external_id": %q, %s"status": %q, "assessed_on": "2026-11-01"}`, ext, c, st)
	}
	got = push(controls, batchOf(status("c-1", "", "in_place"), status("c-2", ctl, "not_in_place")))
	if r := got["refused"].([]any); len(r) != 1 || !strings.Contains(fmt.Sprint(r[0]), "/control") {
		t.Errorf("control status without a control: %v", r)
	}
	if got := im.adminQuery("SELECT action || ':' || target_type || ':' || target_id FROM integration.proposal WHERE integration_id = '" + controls + "'"); got != "update:control:"+ctl {
		t.Errorf("a control status proposal: %s", got)
	}

	// Loss events are data: no proposals.
	ev := `{"kind": "loss_event", "external_id": "e-1", "bu": "A", "occurred_on": "2026-01-02", "event_type": "fraud"}`
	if got := push(events, batchOf(ev)); got["counts"].(map[string]any)["proposed"] != 0.0 {
		t.Errorf("a loss event proposed: %v", got["counts"])
	}
	// A dry run proposes nothing.
	before := im.adminQuery("SELECT count(*) FROM integration.proposal")
	if got := im.send(t, "pusher", "/api/v1/imports/"+assets+"/batches?dry_run=true", "application/json", batchOf(asset("a-9", "A", "New"))); got.code != 200 || got.body["counts"].(map[string]any)["proposed"] != 1.0 {
		t.Errorf("dry run: %d %s", got.code, got.raw)
	}
	if after := im.adminQuery("SELECT count(*) FROM integration.proposal"); after != before {
		t.Errorf("a dry run stored proposals: %s -> %s", before, after)
	}
}

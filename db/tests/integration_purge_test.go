package tests

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/integration"
)

// F-011 T-17b (design §3.2, §5): staged records go after
// integration.records_retention_days; runs, their counts and refusals,
// proposals, links and provenance stay; each purge is recorded.
func TestIntegrationRecordsPurged(t *testing.T) {
	im := importAPI(t)
	ctx := context.Background()
	var id string
	if err := im.ie.as("platform", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT integration.add($1, 'CMDB', 'assets', 'push', '{}', NULL, NULL, false)::text", im.bu["A"]).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	push := func(records ...string) string {
		t.Helper()
		got := im.send(t, "pusher", "/api/v1/imports/"+id+"/batches", "application/json", batchOf(records...))
		if got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		return got.body["run"].(map[string]any)["id"].(string)
	}
	old := push(asset("p-1", "A", "One"), asset("p-2", "A", "Two"))
	recent := push(asset("p-3", "A", "Three"))
	// The first run finished 31 days ago (moved as the owner, past the
	// state rule that keeps finished runs as they are).
	im.adminQuery("SET session_replication_role = replica; UPDATE integration.run SET started_at = started_at - interval '31 days', finished_at = finished_at - interval '31 days' WHERE id = '" + old + "'")

	purger := integration.Purger{DB: im.ie.pool, Retention: func() (int, error) { return 30, nil }, Batch: 1}
	got, err := purger.Step(ctx)
	if err != nil || got.Runs != 1 || got.Records != 2 || !got.More {
		t.Fatalf("first step: %+v %v", got, err)
	}
	if got, err := purger.Step(ctx); err != nil || got.Runs != 0 || got.More {
		t.Fatalf("second step: %+v %v", got, err)
	}
	for run, want := range map[string]string{old: "0", recent: "1"} {
		if n := im.adminQuery("SELECT count(*) FROM integration.record WHERE run_id = '" + run + "'"); n != want {
			t.Errorf("run %s keeps %s records, want %s", run, n, want)
		}
	}
	// The run, its counts and its proposals remain.
	if got := im.adminQuery("SELECT (counts ->> 'received') || ' ' || (SELECT count(*) FROM integration.proposal p WHERE p.run_id = r.id) FROM integration.run r WHERE id = '" + old + "'"); got != "2 2" {
		t.Errorf("the purged run: %s", got)
	}
	if got := im.call(t, "GET", "pusher", "/api/v1/imports/runs/"+old, nil); got.code != 200 {
		t.Errorf("the purged run reads: %d", got.code)
	}
	if got := im.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'integration.records_purged' AND body -> 'attributes' ->> 'run' = '` + old + `'
		AND body -> 'attributes' ->> 'records' = '2' AND body ->> 'bu_id' = '` + im.bu["A"] + `'`); got != "1" {
		t.Errorf("%s purge events", got)
	}
	// Only the integrate service purges, within the setting's bounds.
	if _, err := im.appPool().Exec(ctx, "SELECT integration.purge_records(30, 10)"); pgState(err) != "42501" {
		t.Errorf("app_rw purges: %v", err)
	}
	if _, err := im.ie.pool.Exec(ctx, "SELECT integration.purge_records(0, 10)"); pgState(err) != "PF031/invalid_value" {
		t.Errorf("zero days: %v", err)
	}
}

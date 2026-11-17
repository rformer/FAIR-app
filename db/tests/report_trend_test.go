package tests

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/reports"
)

// F-010 T-15 (F-010-AC-06, AC-07; OQ6; design §3.2 as amended): snapshots
// taken at the interval, never changed, purged past the retention; each
// viewer's trend sums only the units they read (aggregate-only ones as
// totals), and a roll-up row shows only to viewers who see all it covers.
func TestReportTrend(t *testing.T) {
	a := acceptanceFixture(t)
	ra, rg := a.ra, a.rg
	ctx := context.Background()
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code IN ('R', 'R1')")
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rown@example.test', 'Rown')")
	ra.mustOwner(grant("platform", "user:rown", "Risk Owner", "R"))
	ra.drain()
	rown := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rown@example.test'")
	mk := func(user, bu, title, owner string) {
		t.Helper()
		got := rg.call(t, "POST", user, "/api/v1/register/risks", map[string]any{"bu_id": bu, "change_note": "x",
			"document": map[string]any{"schema_version": 1, "title": title, "owner": owner, "state": "open", "scenarios": []any{}}})
		if got.code != 201 {
			t.Fatalf("create %s: %d %s", title, got.code, got.raw)
		}
	}
	mk("rown", ra.bu["R"], "Restricted risk", rown)
	mk("rown", ra.bu["R1"], "Restricted risk 2", rown)
	mk("chief", ra.bu["B"], "Vendor outage", a.chief)
	_ = a.accepted(t, "Claims leak", "owen")
	tick := func() map[string]any {
		t.Helper()
		var raw []byte
		if err := ra.tx("owen", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT report.snapshot_tick(7, 1095)").Scan(&raw)
		}); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	trend := func(user, bu string) []reports.TrendPoint {
		t.Helper()
		var out []reports.TrendPoint
		readAs(t, ra, user, func(tx pgx.Tx) error {
			var err error
			out, err = reports.ReadTrend(ctx, tx, ra.bu[bu], time.Now().AddDate(-5, 0, 0), time.Now().Add(time.Hour))
			return err
		})
		return out
	}

	// A snapshot, then none within the interval.
	if got := tick(); got["taken"] == nil || got["purged"] != 0.0 {
		t.Fatalf("first tick: %v", got)
	}
	if got := tick(); got["taken"] != nil {
		t.Errorf("a second snapshot within the interval: %v", got)
	}
	// Each viewer's sum (AC-07): chief reads A, A1, B and R by its totals;
	// owen A and A1, and R's totals; mallory B alone.
	for _, c := range []struct {
		user, bu string
		open     int
	}{{"chief", "ENTERPRISE", 5}, {"owen", "A", 4}, {"mallory", "ENTERPRISE", 1}, {"mallory", "A", 0}} {
		pts := trend(c.user, c.bu)
		if len(pts) != 1 || pts[0].Counts.Open != c.open {
			t.Errorf("%s at %s: %+v, want %d open", c.user, c.bu, pts, c.open)
		}
	}
	// Chief's equals the dashboard: its open risks plus the restricted totals.
	re := reportAPI(t, ra, reports.Kinds())
	d := re.call(t, "GET", "chief", "/api/v1/reports/dashboard?bu="+ra.bu["ENTERPRISE"], nil)
	if int(d.body["coverage"].(map[string]any)["open"].(float64))+int(d.body["restricted"].(map[string]any)["open_risks"].(float64)) != trend("chief", "ENTERPRISE")[0].Counts.Open {
		t.Errorf("the trend and the dashboard differ: %s", d.raw)
	}
	// Snapshots never change (PF029).
	if got := ra.adminState("UPDATE report.snapshot_bu SET open_risks = 99"); got != "PF029" {
		t.Errorf("a snapshot row changed: %s", got)
	}

	// A roll-up of A1 since the last snapshot joins the next one, shown to
	// viewers who read every risk it covers.
	if got := rg.call(t, "POST", "chief", "/api/v1/register/rollups", map[string]any{"bu_id": ra.bu["A1"]}); got.code != 202 {
		t.Fatalf("roll-up: %d %s", got.code, got.raw)
	}
	if q := ra.adminQuery("SELECT coalesce(string_agg(id::text, ',' ORDER BY seq), '') FROM analysis.aggregate WHERE purpose = 'rollup' AND state = 'queued'"); q != "" {
		for _, id := range strings.Split(q, ",") {
			if err := a.ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil {
				t.Fatalf("aggregate %s: %v", id, err)
			}
		}
	}
	back := func(days int) {
		ra.admin(ra.db, "SET session_replication_role = replica; UPDATE report.snapshot SET taken_at = taken_at - make_interval(days => "+strconv.Itoa(days)+")")
	}
	back(8)
	if got := tick(); got["taken"] == nil {
		t.Fatalf("a snapshot after the interval: %v", got)
	}
	for user, want := range map[string]bool{"chief": true, "owen": true} {
		pts := trend(user, "A1")
		if len(pts) != 2 || pts[0].Rollup != nil || (pts[1].Rollup != nil) != want {
			t.Errorf("%s's A1 trend: %+v", user, pts)
		}
	}
	if pts := trend("mallory", "A1"); len(pts) != 2 || pts[1].Rollup != nil || pts[1].Counts.Open != 0 {
		t.Errorf("mallory's A1 trend: %+v", pts)
	}

	// The API: report.view at the BU; bad periods refused.
	if got := re.call(t, "GET", "chief", "/api/v1/reports/dashboard/trend?bu="+ra.bu["ENTERPRISE"], nil); got.code != 200 || len(got.body["snapshots"].([]any)) != 2 {
		t.Errorf("trend: %d %s", got.code, got.raw)
	}
	for _, c := range []struct {
		user, q string
		code    int
	}{{"est", "bu=" + ra.bu["A"], 404}, {"chief", "bu=" + ra.bu["A"] + "&from=soon", 400}, {"chief", "bu=" + ra.bu["A"] + "&from=2026-02-01&to=2026-01-01", 400},
		{"chief", "bu=" + ra.bu["A"] + "&from=2020-01-01&to=2020-12-31", 200}} {
		if got := re.call(t, "GET", c.user, "/api/v1/reports/dashboard/trend?"+c.q, nil); got.code != c.code {
			t.Errorf("%s %s: %d %s", c.user, c.q, got.code, got.raw)
		}
	}

	// Purged whole past the retention.
	back(1100)
	if got := tick(); got["purged"] != 2.0 || got["taken"] == nil {
		t.Errorf("purge: %v", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM report.snapshot_bu b WHERE NOT EXISTS (SELECT 1 FROM report.snapshot s WHERE s.id = b.snapshot_id)"); got != "0" {
		t.Errorf("orphan rows: %s", got)
	}
	if _, err := ra.as("app_rw", "SELECT report.snapshot_tick(0, 1095)"); err == nil {
		t.Error("an interval of 0 days")
	}
}

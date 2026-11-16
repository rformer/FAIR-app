package tests

import (
	"fmt"
	"strings"
	"testing"
)

// F-010 T-03 (F-010-AC-06, AC-15, AC-19; design §5 as amended): the report
// schema is report_definer's alone, and its state rules hold for every role.
func TestReportSchema(t *testing.T) {
	e := setup(t)
	// No application role reaches the tables; report_definer does.
	for _, role := range []string{"app_rw", "app_notify", "app_posture", "app_audit", "app_gateway"} {
		for _, tbl := range []string{"run", "file", "schedule", "snapshot", "snapshot_bu", "snapshot_rollup", "notice_outbox"} {
			if got := e.adminState("SET ROLE " + role + "; PERFORM count(*) FROM report." + tbl); got != "42501" {
				t.Errorf("%s reads report.%s: %s", role, tbl, got)
			}
		}
	}
	if got := e.adminState("SET ROLE report_definer; PERFORM count(*) FROM report.run"); got != "ok" {
		t.Errorf("report_definer reads runs: %s", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.bu_owned_tables WHERE table_name::text LIKE 'report.%'"); got != "0" {
		t.Errorf("%s report tables registered as BU-owned", got)
	}

	// The state rules (as the owner here, so only the triggers refuse).
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rae@example.test', 'Rae')")
	user := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rae@example.test'")
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	run := func() string {
		return e.adminQuery(fmt.Sprintf(`INSERT INTO report.run (requested_by, bu_id, kind, formats) VALUES ('%s', '%s', 'register', '{pdf,csv}') RETURNING id`, user, root))
	}
	r1 := run()
	nonce := "0123456789abcdef0123456789abcdef"
	for _, c := range []struct{ name, sql, want string }{
		{"a request changed", "UPDATE report.run SET kind = 'risk' WHERE id = '" + r1 + "'", "PF029"},
		{"queued to succeeded", "UPDATE report.run SET state = 'succeeded', finished_at = now() WHERE id = '" + r1 + "'", "PF029"},
		{"running without a nonce", "UPDATE report.run SET state = 'running' WHERE id = '" + r1 + "'", "23514"},
		{"running", "UPDATE report.run SET state = 'running', context_nonce = '" + nonce + "', started_at = now() WHERE id = '" + r1 + "'", "ok"},
		{"retried", "UPDATE report.run SET state = 'queued', context_nonce = NULL, attempts = 1 WHERE id = '" + r1 + "'", "ok"},
		{"running again", "UPDATE report.run SET state = 'running', context_nonce = '" + nonce + "' WHERE id = '" + r1 + "'", "ok"},
		{"failed without a cause", "UPDATE report.run SET state = 'failed', context_nonce = NULL, finished_at = now() WHERE id = '" + r1 + "'", "23514"},
		{"succeeded", "UPDATE report.run SET state = 'succeeded', context_nonce = NULL, finished_at = now(), progress = 100 WHERE id = '" + r1 + "'", "ok"},
		{"a finished run", "UPDATE report.run SET progress = 50 WHERE id = '" + r1 + "'", "PF029"},
		{"an unknown format", fmt.Sprintf("INSERT INTO report.run (requested_by, bu_id, kind, formats) VALUES ('%s', '%s', 'register', '{docx}')", user, root), "23514"},
		{"a file", "INSERT INTO report.file (run_id, format, object_key, size, sha256) VALUES ('" + r1 + "', 'pdf', 'reports/i/" + r1 + "/report.pdf', 10, repeat('a', 64))", "ok"},
		{"over 100 MiB", "INSERT INTO report.file (run_id, format, object_key, size, sha256) VALUES ('" + r1 + "', 'csv', 'k', 104857601, repeat('a', 64))", "23514"},
		{"a file's digest", "UPDATE report.file SET sha256 = repeat('b', 64) WHERE run_id = '" + r1 + "'", "PF029"},
		{"purged", "UPDATE report.file SET purged_at = now() WHERE run_id = '" + r1 + "'", "ok"},
		{"purged twice", "UPDATE report.file SET purged_at = now() WHERE run_id = '" + r1 + "'", "PF029"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	// Snapshots never change.
	snap := e.adminQuery("INSERT INTO report.snapshot DEFAULT VALUES RETURNING id")
	e.adminQuery(fmt.Sprintf(`INSERT INTO report.snapshot_bu (snapshot_id, bu_id, open_risks, current_risks, stale_risks, unquantified, mean_sum, acceptances, open_actions, overdue_actions)
		VALUES (%s, '%s', 3, 1, 1, 1, 100, '{}', 2, 1) RETURNING bu_id`, snap, root))
	if got := e.adminState("UPDATE report.snapshot_bu SET open_risks = 4"); got != "PF029" {
		t.Errorf("a snapshot changed: %s", got)
	}
	if got := e.adminState(fmt.Sprintf(`INSERT INTO report.snapshot_bu (snapshot_id, bu_id, open_risks, current_risks, stale_risks, unquantified, mean_sum, acceptances, open_actions, overdue_actions)
		VALUES (%s, '%s', 3, 1, 1, 0, 100, '{}', 0, 0)`, snap, user)); got != "23503" && got != "23514" {
		t.Errorf("counts that do not add up: %s", got)
	}
	// The purge deletes a snapshot whole.
	if got := e.adminState("SET ROLE report_definer; DELETE FROM report.snapshot WHERE id = " + snap); got != "ok" {
		t.Errorf("purge: %s", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM report.snapshot_bu"); got != "0" {
		t.Errorf("%s snapshot rows left", got)
	}

	// Schedules: at most 20 live per owner; a deleted one is kept and fixed.
	sched := func() string {
		return fmt.Sprintf(`INSERT INTO report.schedule (owner, bu_id, kind, formats, cadence, weekday, hour, next_at)
			VALUES ('%s', '%s', 'register', '{pdf}', 'weekly', 1, 7, now()) RETURNING id`, user, root)
	}
	first := e.adminQuery(sched())
	for range 19 {
		e.adminQuery(sched())
	}
	plain := func() string { return strings.TrimSuffix(sched(), " RETURNING id") }
	if got := e.adminState(plain()); got != "PF030" {
		t.Errorf("a 21st schedule: %s", got)
	}
	if got := e.adminState("UPDATE report.schedule SET deleted_at = now() WHERE id = '" + first + "'"); got != "ok" {
		t.Errorf("delete: %s", got)
	}
	if got := e.adminState(plain()); got != "ok" {
		t.Errorf("after deleting one: %s", got)
	}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('sol@example.test', 'Sol')")
	other := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'sol@example.test'")
	for _, c := range []struct{ name, sql, want string }{
		{"a deleted schedule", "UPDATE report.schedule SET hour = 8 WHERE id = '" + first + "'", "PF029"},
		{"weekly without a day", fmt.Sprintf(`INSERT INTO report.schedule (owner, bu_id, kind, formats, cadence, hour, next_at) VALUES ('%s', '%s', 'register', '{pdf}', 'weekly', 7, now())`, other, root), "23514"},
		{"suspended without a reason", "UPDATE report.schedule SET state = 'suspended' WHERE id <> '" + first + "'", "23514"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

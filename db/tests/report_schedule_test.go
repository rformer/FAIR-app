package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/reports"
)

// F-010 T-16 (F-010-AC-19 to AC-21; OQ5; design §3.7): schedules, their
// owner's alone; due ones become runs as their owner sees the data, one
// after an outage; an owner without report.export has the schedule
// suspended; the notices (ready, failed, suspended) reach the owner only.
func TestReportSchedules(t *testing.T) {
	ra := strideF003Fixture(t)
	seedPosture(t, ra.env)
	reportUsers(ra)
	re := reportAPI(t, ra)
	ctx := context.Background()
	pub := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'pub@example.test'")

	// next_time: the first time strictly after.
	for _, c := range [][2]string{
		{"'daily', NULL, NULL, 9, '2026-11-17 10:00Z'", "2026-11-18 09:00:00+00"},
		{"'daily', NULL, NULL, 9, '2026-11-17 08:00Z'", "2026-11-17 09:00:00+00"},
		{"'weekly', 2, NULL, 9, '2026-11-17 08:00Z'", "2026-11-17 09:00:00+00"}, // a Tuesday
		{"'weekly', 2, NULL, 9, '2026-11-17 09:00Z'", "2026-11-24 09:00:00+00"},
		{"'weekly', 0, NULL, 0, '2026-11-17 09:00Z'", "2026-11-22 00:00:00+00"},
		{"'monthly', NULL, 28, 9, '2026-11-28 10:00Z'", "2026-12-28 09:00:00+00"},
		{"'monthly', NULL, 1, 0, '2026-12-15 00:00Z'", "2027-01-01 00:00:00+00"},
	} {
		if got := ra.adminQuery("SET TIME ZONE 'UTC'; SELECT report.next_time(" + c[0] + ")"); got != c[1] {
			t.Errorf("next_time(%s) = %s, want %s", c[0], got, c[1])
		}
	}

	schedule := func(user, bu string, body map[string]any) apiResp {
		t.Helper()
		b := map[string]any{"kind": "register", "bu_id": bu, "formats": []string{"json"}, "cadence": "weekly", "weekday": 1, "hour": 9}
		for k, v := range body {
			b[k] = v
		}
		return re.call(t, "POST", user, "/api/v1/reports/schedules", b)
	}
	// Created by a holder of report.export at the BU, for themselves.
	got := schedule("pub", ra.bu["A1"], nil)
	if got.code != 201 || got.body["state"] != "active" || got.body["version"] != 1.0 || got.body["next_at"] == nil {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	for _, c := range []struct {
		name, user, bu string
		body           map[string]any
		code           int
	}{
		{"a viewer", "viewer", ra.bu["A"], nil, 403},
		{"outside their BUs", "pub", ra.bu["B"], nil, 404},
		{"weekly without a weekday", "pub", ra.bu["A1"], map[string]any{"weekday": nil}, 422},
		{"a monthday of 29", "pub", ra.bu["A1"], map[string]any{"cadence": "monthly", "weekday": nil, "monthday": 29}, 422},
		{"no hour", "pub", ra.bu["A1"], map[string]any{"hour": nil}, 422},
		{"an hour of 24", "pub", ra.bu["A1"], map[string]any{"hour": 24}, 422},
		{"the root without a reason", "pubroot", ra.bu["ENTERPRISE"], nil, 400},
	} {
		if got := schedule(c.user, c.bu, c.body); got.code != c.code {
			t.Errorf("%s: %d %s", c.name, got.code, got.raw)
		}
	}
	if got := schedule("pubroot", ra.bu["ENTERPRISE"], map[string]any{"reason": "Committee pack"}); got.code != 201 || got.body["reason"] != "Committee pack" {
		t.Errorf("the root with a reason: %d %s", got.code, got.raw)
	}
	if got := reportScheduleEvents(ra, sid, "report.schedule_created"); got != "1" {
		t.Errorf("report.schedule_created: %s", got)
	}
	// The owner's alone.
	for _, m := range []string{"GET", "PUT"} {
		if got := re.call(t, m, "pubroot", "/api/v1/reports/schedules/"+sid, map[string]any{"expected_version": 1, "formats": []string{"csv"}, "cadence": "daily", "hour": 7}); got.code != 404 {
			t.Errorf("pubroot %s pub's schedule: %d", m, got.code)
		}
	}
	if got := re.call(t, "GET", "pubroot", "/api/v1/reports/schedules", nil); len(got.body["schedules"].([]any)) != 1 {
		t.Errorf("pubroot lists: %s", got.raw)
	}
	// Changed with the version.
	if got := re.call(t, "PUT", "pub", "/api/v1/reports/schedules/"+sid, map[string]any{"expected_version": 9, "formats": []string{"csv"}, "cadence": "daily", "hour": 7}); got.code != 409 {
		t.Errorf("a stale version: %d %s", got.code, got.raw)
	}
	got = re.call(t, "PUT", "pub", "/api/v1/reports/schedules/"+sid, map[string]any{"expected_version": 1, "formats": []string{"json", "csv"}, "cadence": "daily", "hour": 7})
	if got.code != 200 || got.body["version"] != 2.0 || got.body["cadence"] != "daily" || fmt.Sprint(got.body["formats"]) != "[csv json]" {
		t.Fatalf("update: %d %s", got.code, got.raw)
	}
	if got := re.call(t, "PUT", "pub", "/api/v1/reports/schedules/"+sid, map[string]any{"expected_version": 2, "kind": "treatment", "formats": []string{"csv"}, "cadence": "daily", "hour": 7}); got.code != 422 {
		t.Errorf("a new kind: %d %s", got.code, got.raw)
	}
	// At most 20 live per person (PF030).
	for i := 0; i < 19; i++ {
		if got := schedule("pub", ra.bu["A1"], nil); got.code != 201 {
			t.Fatalf("schedule %d: %d %s", i+2, got.code, got.raw)
		}
	}
	if got := schedule("pub", ra.bu["A1"], nil); got.code != 409 || got.body["error"] != "too_many_schedules" {
		t.Errorf("a 21st: %d %s", got.code, got.raw)
	}
	// Keep sid and one failing schedule; delete the rest (a reason needed).
	list := re.call(t, "GET", "pub", "/api/v1/reports/schedules", nil).body["schedules"].([]any)
	if got := re.call(t, "DELETE", "pub", "/api/v1/reports/schedules/"+sid, map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("delete without a reason: %d %s", got.code, got.raw)
	}
	var failing string
	for _, x := range list {
		id := x.(map[string]any)["id"].(string)
		if id == sid {
			continue
		}
		if failing == "" {
			failing = id
			ra.admin(ra.db, "UPDATE report.schedule SET params = '{\"fail\":true}' WHERE id = '"+id+"'")
			continue
		}
		if got := re.call(t, "DELETE", "pub", "/api/v1/reports/schedules/"+id, map[string]any{"reason": "Too many"}); got.code != 204 {
			t.Fatalf("delete: %d %s", got.code, got.raw)
		}
	}
	if got := re.call(t, "GET", "pub", "/api/v1/reports/schedules", nil); len(got.body["schedules"].([]any)) != 2 {
		t.Errorf("after deleting: %s", got.raw)
	}

	// Due after an outage of ten days: one run each, then the next time.
	ra.admin(ra.db, "UPDATE report.schedule SET next_at = now() - interval '10 days' WHERE id IN ('"+sid+"', '"+failing+"')")
	rc, err := river.NewClient(riverpgxv5.New(ra.appPool()), &river.Config{Schema: reports.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	job := &reports.ScheduleJob{DB: ra.appPool(), Enqueue: reports.Enqueuer(rc)}
	if runs, susp, err := job.Step(ctx); err != nil || runs != 2 || susp != 0 {
		t.Fatalf("due: %d %d %v", runs, susp, err)
	}
	if runs, _, err := job.Step(ctx); err != nil || runs != 0 {
		t.Errorf("again at once: %d %v", runs, err)
	}
	if got := ra.adminQuery("SELECT count(*) FROM report.schedule WHERE id IN ('" + sid + "', '" + failing + "') AND next_at > now()"); got != "2" {
		t.Errorf("next times: %s", got)
	}
	runOf := func(s string) string {
		return ra.adminQuery("SELECT id FROM report.run WHERE schedule_id = '" + s + "'")
	}
	ok, bad := runOf(sid), runOf(failing)
	if n := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'report.generate' AND args ->> 'run_id' IN ('" + ok + "', '" + bad + "')"); n != "2" {
		t.Errorf("jobs: %s", n)
	}
	if got := ra.adminQuery("SELECT requested_by || ' ' || array_to_string(formats, ',') FROM report.run WHERE id = '" + ok + "'"); got != pub+" csv,json" {
		t.Errorf("the scheduled run: %s", got)
	}
	// Generated as pub sees the data; ready and failed notices to pub.
	if err := re.attempt(t, ok, 1); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= reports.Attempts; i++ {
		_ = re.attempt(t, bad, i)
	}
	if got := ra.adminQuery("SELECT string_agg(kind || ':' || user_id || ':' || run_id, ',' ORDER BY id) FROM report.notice_outbox"); got != "report.ready:"+pub+":"+ok+",report.failed:"+pub+":"+bad {
		t.Errorf("notices: %s", got)
	}

	// pub loses report.export: the next due time suspends the schedule.
	ra.mustOwner(revoke("platform", "pub", "Report Publisher", "A"))
	ra.drain()
	ra.admin(ra.db, "UPDATE report.schedule SET next_at = now() - interval '1 minute' WHERE id = '"+sid+"'")
	if runs, susp, err := job.Step(ctx); err != nil || runs != 0 || susp != 1 {
		t.Fatalf("suspend: %d %d %v", runs, susp, err)
	}
	if got := ra.adminQuery("SELECT state || ' ' || suspended_reason FROM report.schedule WHERE id = '" + sid + "'"); got != "suspended no_permission" {
		t.Errorf("suspended: %s", got)
	}
	if got := reportScheduleEvents(ra, sid, "report.schedule_suspended"); got != "1" {
		t.Errorf("report.schedule_suspended: %s", got)
	}
	if got := re.call(t, "POST", "pub", "/api/v1/reports/schedules/"+sid+"/resume", nil); got.code != 403 && got.code != 404 {
		t.Errorf("resume without report.export: %d %s", got.code, got.raw)
	}
	ra.mustOwner(grant("platform", "user:pub", "Report Publisher", "A"))
	ra.drain()
	if got := re.call(t, "POST", "pub", "/api/v1/reports/schedules/"+sid+"/resume", nil); got.code != 200 || got.body["state"] != "active" {
		t.Errorf("resume: %d %s", got.code, got.raw)
	}
	if got := re.call(t, "POST", "pub", "/api/v1/reports/schedules/"+sid+"/resume", nil); got.code != 409 {
		t.Errorf("resume an active one: %d %s", got.code, got.raw)
	}

	// The notify service takes the three to pub alone, linked back.
	pool := notifyPool(t, ra.env)
	if n, err := (notify.Cycle{Collector: notify.Collector{DB: pool, Batch: 10}, FanOut: notify.FanOut{DB: pool, Batch: 10}}).Run(ctx); err != nil || n != 3 {
		t.Fatalf("collected %d: %v", n, err)
	}
	if got := ra.adminQuery(`SELECT string_agg(n.kind || '|' || (n.envelope #>> '{item,link}') || '|' || i.user_id, ',' ORDER BY n.seq)
		FROM notify.notice n JOIN notify.inbox i ON i.notice_id = n.id WHERE n.source = 'report'`); got !=
		"report.ready|/reports/"+ok+"|"+pub+",report.failed|/reports/"+bad+"|"+pub+",report.schedule_suspended|/reports/schedules/"+sid+"|"+pub {
		t.Errorf("notices: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM report.notice_outbox WHERE delivered_at IS NULL"); got != "0" {
		t.Errorf("%s left in the outbox", got)
	}
	if strings.Contains(ra.adminQuery("SELECT coalesce(string_agg(envelope::text, ' '), '') FROM notify.notice WHERE source = 'report'"), `"fail": true`) {
		t.Error("an envelope carries report content")
	}
}

func reportScheduleEvents(ra *riskAPIEnv, schedule, typ string) string {
	return ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' = 'report_schedule:" + schedule + "'")
}

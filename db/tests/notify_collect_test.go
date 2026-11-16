package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/notify"
)

// notifyPool is a pool as app_notify (the notify service's role).
func notifyPool(t *testing.T, e *env) *pgxpool.Pool {
	t.Helper()
	cc, err := dbconn.Config("development", "app_notify", e.secrets["app_notify"], "fair-test")
	if err != nil {
		t.Fatal(err)
	}
	cc.Database = e.db
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig = cc
	p, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// F-009 T-04 (F-009-AC-01, AC-05, AC-06; design §3.1, §3.3, §3.6): every
// outbox becomes notices, once each, marked delivered in the same
// transaction; envelopes are minimal, titles only by setting and never for
// restricted business units; high and critical findings are queued.
func TestNotifyCollect(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	c := notify.Collector{DB: notifyPool(t, ra.env)}
	titles := false
	c.Titles = func() bool { return titles }
	collect := func() (int, int) {
		t.Helper()
		n, u, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return n, u
	}
	// Whatever the fixture queued, collected first.
	collect()
	base := ra.adminQuery("SELECT count(*) FROM notify.notice")

	// An acceptance request (decision_needed, for the approvers) at A1.
	risk := a.accepted(t, "Claims ransomware notices", "owen")
	acc, code := a.request(t, "owen", risk, "Within appetite", days(90), "")
	if code != "" {
		t.Fatal(code)
	}
	// A setting exception at the root and one inside the restricted R; a
	// break-glass login; findings of each severity.
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.exception_expiring', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "session.idle_timeout", "exception_id": "e1"}'),
		('setting.exception_expiring', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "session.idle_timeout", "exception_id": "e2", "bu_id": "`+ra.bu["R"]+`"}')`)
	owen := a.userID("owen")
	ra.admin(ra.db, `INSERT INTO iam.notice_outbox (kind, payload) VALUES ('breakglass.login', '{"type": "breakglass.login", "user_id": "`+owen+`"}')`)
	ra.admin(ra.db, `INSERT INTO posture.drift_finding (kind, check_id, severity, subject, remediation) VALUES
		('app', 'test_low', 'low', 's1', 'x'), ('app', 'test_high', 'high', 's2', 'x'), ('app', 'test_critical', 'critical', 's3', 'x')`)
	if got := ra.adminQuery("SELECT string_agg(check_id || ':' || severity, ',' ORDER BY id) FROM posture.finding_outbox"); got != "test_high:high,test_critical:critical" {
		t.Fatalf("finding outbox: %s", got)
	}
	// A refreshed finding is not queued again.
	ra.admin(ra.db, "UPDATE posture.drift_finding SET last_seen = now() WHERE check_id = 'test_high'")

	n, unknown := collect()
	if n != 6 || unknown != 0 {
		t.Fatalf("collected %d, unknown %d", n, unknown)
	}
	for _, ob := range []string{"posture.notice_outbox", "iam.notice_outbox", "posture.finding_outbox", "acceptance.notice_outbox", "estimate.notice_outbox"} {
		if got := ra.adminQuery("SELECT count(*) FROM " + ob + " WHERE delivered_at IS NULL"); got != "0" {
			t.Errorf("%s: %s pending", ob, got)
		}
	}
	// Once each: nothing more to collect.
	if n, _ := collect(); n != 0 {
		t.Errorf("collected again: %d", n)
	}
	if got := ra.adminQuery("SELECT count(*) - " + base + " FROM notify.notice"); got != "6" {
		t.Errorf("notices: %s", got)
	}

	env := func(where string) string {
		return ra.adminQuery("SELECT envelope - 'id' - 'at' FROM notify.notice WHERE " + where)
	}
	// Minimal by default (AC-05): kind, BU, item and link; no title.
	if got := env("source = 'acceptance' AND item_id = '" + acc + "'"); got !=
		`{"bu": {"id": "`+ra.bu["A1"]+`", "name": "A1"}, "item": {"id": "`+acc+`", "link": "/acceptances/`+acc+`", "type": "acceptance"}, "kind": "acceptance.decision_needed"}` {
		t.Errorf("acceptance envelope: %s", got)
	}
	if got := ra.adminQuery("SELECT recipients::text FROM notify.notice WHERE source = 'acceptance' AND item_id = '" + acc + "'"); got != `{"deciders": "`+acc+`"}` {
		t.Errorf("decision_needed recipients: %s", got)
	}
	root := ra.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	if got := env("source = 'iam'"); got != `{"bu": {"id": "`+root+`", "name": "Enterprise"}, "item": {"id": "`+owen+`", "link": "/audit?target=user:`+owen+`", "type": "breakglass"}, "kind": "breakglass.login"}` {
		t.Errorf("break-glass envelope: %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(kind || ':' || (recipients ->> 'permission_holders'), ',' ORDER BY seq) FROM notify.notice WHERE source = 'finding'"); got != "finding.opened:drift.acknowledge,finding.opened:drift.acknowledge" {
		t.Errorf("findings: %s", got)
	}

	// Titles by setting (AC-06), never for restricted units.
	titles = true
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.exception_reverted', '{"users": []}', '{"key": "session.idle_timeout", "exception_id": "e3"}'),
		('setting.exception_reverted', '{"users": []}', '{"key": "session.idle_timeout", "exception_id": "e4", "bu_id": "`+ra.bu["R1"]+`"}')`)
	risk2 := a.accepted(t, "Claims vendor notices", "owen")
	acc2, _ := a.request(t, "owen", risk2, "Within appetite", days(90), "")
	collect()
	if got := ra.adminQuery("SELECT envelope ->> 'title' FROM notify.notice WHERE item_id = 'e3'"); got != "session.idle_timeout" {
		t.Errorf("a title: %q", got)
	}
	if got := ra.adminQuery("SELECT coalesce(envelope ->> 'title', '-') || ':' || restricted FROM notify.notice WHERE item_id = 'e4'"); got != "-:true" {
		t.Errorf("restricted: %s", got)
	}
	if got := ra.adminQuery("SELECT envelope ->> 'title' FROM notify.notice WHERE item_id = '" + acc2 + "'"); got != "Claims vendor notices" {
		t.Errorf("the acceptance's risk title: %q", got)
	}
	if got := ra.adminQuery("SELECT coalesce(envelope ->> 'title', '-') FROM notify.notice WHERE item_id = 'e2'"); got != "-" {
		t.Errorf("collected before titles were on: %s", got)
	}

	// F-004: an estimate request, to its estimator, titled.
	ea := estimateAPI(t, ra)
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('dana@example.test', 'Dana')")
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.drain()
	dana := a.userID("dana")
	got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": a.s1, "title": "Contact frequency of ransomware crews",
		"due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339), "factors": []any{"/lef/tef/contact_frequency"}, "estimators": []any{dana},
		"context": []any{"name"}})
	if got.code != 201 {
		t.Fatalf("estimate request: %d %s", got.code, got.raw)
	}
	req := got.body["id"].(string)
	collect()
	if got := ra.adminQuery("SELECT kind || '|' || (envelope #>> '{item,link}') || '|' || (envelope ->> 'title') || '|' || recipients::text FROM notify.notice WHERE source = 'estimate' AND item_id = '" + req + "'"); got !=
		"estimate.assigned|/estimates/"+req+"|Contact frequency of ransomware crews|"+`{"users": ["`+dana+`"]}` {
		t.Errorf("estimate notice: %s", got)
	}

	// A kind the release does not know stays pending, counted.
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES ('setting.mystery', '{"users": []}', '{}')`)
	if _, u := collect(); u != 1 {
		t.Errorf("unknown: %d", u)
	}
	if got := ra.adminQuery("SELECT count(*) FROM posture.notice_outbox WHERE kind = 'setting.mystery' AND delivered_at IS NULL"); got != "1" {
		t.Errorf("the unknown row: %s", got)
	}
	// Only app_notify collects.
	if got := ra.adminState("SET ROLE app_rw; PERFORM notify.collect(false, 10)"); got != "42501" {
		t.Errorf("app_rw collects: %s", got)
	}
	if got := ra.adminState("SET ROLE app_notify; PERFORM notify.collect(false, 0)"); got != "PF028" {
		t.Errorf("a zero batch: %s", got)
	}
}

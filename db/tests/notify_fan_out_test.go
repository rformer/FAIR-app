package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/notify"
)

// F-009 T-05 (F-009-AC-01, AC-03, AC-04; design §3.1, §3.2, §3.4): notices
// reach their recipients in the app, by email and to the webhooks whose
// scope holds them; the re-checks drop, with reasons; at most 50 holders.
func TestNotifyFanOut(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	pool := notifyPool(t, ra.env)
	c, f := notify.Collector{DB: pool}, notify.FanOut{DB: pool}
	run := func() notify.FannedOut {
		t.Helper()
		var all notify.FannedOut
		for {
			if _, _, err := c.Collect(context.Background()); err != nil {
				t.Fatal(err)
			}
			r, err := f.Step(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			all.Notices, all.InApp, all.Dropped, all.Emails, all.Webhooks = all.Notices+r.Notices, all.InApp+r.InApp, all.Dropped+r.Dropped,
				all.Emails+r.Emails, all.Webhooks+r.Webhooks
			if r.Notices == 0 {
				return all
			}
		}
	}
	run() // whatever the fixture queued
	root := ra.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	// The relay, and webhooks at A, at B, at the root and inside R.
	ra.admin(ra.db, "INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'relay', '{}')")
	hook := func(name, bu string) string {
		return ra.adminQuery(fmt.Sprintf(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct)
			VALUES ('webhook', '%s', '{}', '%s', '{acceptance.decision_needed,setting.exception_expiring}', '\x00') RETURNING id`, name, bu))
	}
	hookA, hookB, hookRoot, hookR := hook("A", ra.bu["A"]), hook("B", ra.bu["B"]), hook("root", root), hook("R", ra.bu["R"])
	who := func(n string) string { return a.userID(n) }

	// decision_needed at A1: the approvers who may decide it (not owen,
	// who requested it and owns the risk).
	risk := a.accepted(t, "Claims ransomware fan-out", "owen")
	acc, code := a.request(t, "owen", risk, "Within appetite", days(90), "")
	if code != "" {
		t.Fatal(code)
	}
	run()
	notice := ra.adminQuery("SELECT id FROM notify.notice WHERE source = 'acceptance' AND item_id = '" + acc + "' AND kind = 'acceptance.decision_needed'")
	names := func(q string) string {
		return ra.adminQuery("SELECT coalesce(string_agg(split_part(u.email, '@', 1), ',' ORDER BY u.email), '') FROM iam.app_user u WHERE u.id IN (" + q + ")")
	}
	if got := names("SELECT user_id FROM notify.inbox WHERE notice_id = '" + notice + "'"); got != "appA1,appA,root1,root2" {
		t.Errorf("decision_needed in the app: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.delivery WHERE notice_id = '" + notice + "' AND user_id IS NOT NULL AND state = 'pending'"); got != "4" {
		t.Errorf("emails: %s", got)
	}
	// Webhooks: A's subtree holds A1; B's does not; the root's does.
	if got := ra.adminQuery("SELECT string_agg(channel_id::text, ',' ORDER BY channel_id) FROM notify.delivery WHERE notice_id = '" + notice + "' AND user_id IS NULL"); got != strings.Join(sortedCopy([]string{hookA, hookRoot}), ",") {
		t.Errorf("webhooks: %s", got)
	}
	_ = hookB

	// A restricted unit's notice: only a webhook inside its subtree, and
	// only its own unit's holders (none of the root's reach into R).
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.exception_expiring', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "k", "exception_id": "r1", "bu_id": "`+ra.bu["R1"]+`"}')`)
	run()
	rn := ra.adminQuery("SELECT id FROM notify.notice WHERE item_id = 'r1'")
	if got := ra.adminQuery("SELECT string_agg(channel_id::text, ',') FROM notify.delivery WHERE notice_id = '" + rn + "' AND user_id IS NULL"); got != hookR {
		t.Errorf("restricted webhooks: %s (want only R's)", got)
	}

	// Named users, re-checked: an estimator removed from the request is
	// not_visible; an inactive one is dropped; a muted optional kind gets no
	// email; a digest user's optional email waits for the digest.
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam", "lee"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
		ra.mustOwner(grant("platform", "user:"+u, "Estimator", "A"))
	}
	ra.drain()
	got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": a.s1, "title": "Contact frequency",
		"due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339), "factors": []any{"/lef/tef/contact_frequency"},
		"estimators": []any{who("dana"), who("sam"), who("lee")}, "context": []any{"name"}})
	if got.code != 201 {
		t.Fatalf("estimate request: %d %s", got.code, got.raw)
	}
	req := got.body["id"].(string)
	ra.admin(ra.db, "UPDATE estimate.request_estimator SET removed_at = now() WHERE user_id = '"+who("sam")+"'")
	ra.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'lee@example.test'")
	run()
	en := "SELECT id FROM notify.notice WHERE source = 'estimate' AND item_id = '" + req + "' AND kind = 'estimate.assigned'"
	if got := ra.adminQuery(`SELECT string_agg(split_part(u.email, '@', 1) || ':' || coalesce(r.reason, 'in_app'), ',' ORDER BY u.email NULLS LAST)
		FROM notify.recipient r JOIN iam.app_user u ON u.id = r.user_id WHERE r.notice_id IN (` + en + ")"); got != "dana:in_app,lee:inactive,sam:not_visible" {
		t.Errorf("recipients: %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(state || ':' || coalesce(reason, '-'), ',' ORDER BY state) FROM notify.delivery WHERE notice_id IN (" + en + ")"); got != "pending:-" {
		t.Errorf("estimate emails: %s", got)
	}
	// Optional kinds: muted, or held for the digest.
	ra.admin(ra.db, "INSERT INTO notify.preference (user_id, kind, email_muted) VALUES ('"+who("dana")+"', 'estimate.closed', true)")
	ra.admin(ra.db, "INSERT INTO notify.user_option (user_id, digest) VALUES ('"+who("dana")+"', true)")
	ra.admin(ra.db, `INSERT INTO estimate.notice_outbox (kind, user_id, request_id) VALUES ('closed', '`+who("dana")+`', '`+req+`'), ('finished', '`+who("dana")+`', '`+req+`'), ('reminder', '`+who("dana")+`', '`+req+`')`)
	run()
	if got := ra.adminQuery(`SELECT string_agg(n.kind || ':' || coalesce(d.digest::text, 'none'), ',' ORDER BY n.kind) FROM notify.notice n
		LEFT JOIN notify.delivery d ON d.notice_id = n.id WHERE n.source = 'estimate' AND n.kind <> 'estimate.assigned'`); got != "estimate.closed:none,estimate.finished:true,estimate.reminder:false" {
		t.Errorf("muted and digest: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id WHERE n.kind = 'estimate.closed'"); got != "1" {
		t.Errorf("a muted kind still in the app: %s", got)
	}

	// At most 50 permission holders, the others counted.
	ra.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Setting Approver') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['settings.approve'], 'test' FROM r`)
	for i := range 55 {
		u := fmt.Sprintf("sa%02d", i)
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
		ra.mustOwner(grant("platform", "user:"+u, "Setting Approver", "ENTERPRISE"))
	}
	ra.drain()
	holders := ra.adminQuery("SELECT count(*) FROM iam.permission_holders('settings.approve', '" + root + "', 100000)")
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "k", "exception_id": "cap"}')`)
	run()
	if got := ra.adminQuery("SELECT (SELECT count(*) FROM notify.inbox i WHERE i.notice_id = n.id) || ':' || n.left_out FROM notify.notice n WHERE n.item_id = 'cap'"); got != fmt.Sprintf("50:%d", atoi(holders)-50) {
		t.Errorf("capped: %s (holders %s)", got, holders)
	}
	// Each notice is fanned out once.
	if r := run(); r.Notices != 0 {
		t.Errorf("fanned out again: %+v", r)
	}
	if got := ra.adminState("SET ROLE app_rw; PERFORM notify.fan_out(10)"); got != "42501" {
		t.Errorf("app_rw fans out: %s", got)
	}
}


package tests

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rformer/fair-app/internal/notify"
)

type fakeSends struct {
	mu   sync.Mutex
	ids  []string // delivery ids sent (or attempted)
	to   []string
	subj []string
	fail func(id string) error
}

func (f *fakeSends) record(id, to, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids, f.to, f.subj = append(f.ids, id), append(f.to, to), append(f.subj, subject)
	if f.fail != nil {
		return f.fail(id)
	}
	return nil
}

type fakeMailer struct{ *fakeSends }

func (m fakeMailer) Send(_ context.Context, _ notify.SMTPConfig, to string, msg notify.Message, id string) (notify.Sent, error) {
	return notify.Sent{TLSVersion: "TLS 1.3"}, m.record(id, to, msg.Subject)
}

type fakePoster struct {
	*fakeSends
	secrets []string
}

func (p *fakePoster) Send(_ context.Context, target, secret, _, id string, _ []byte) (notify.Sent, error) {
	p.mu.Lock()
	p.secrets = append(p.secrets, secret)
	p.mu.Unlock()
	return notify.Sent{Status: 204}, p.record(id, target, "")
}

// F-009 T-10 (F-009-AC-13 to AC-16, AC-19; design §3.5, §3.8, §3.9).
func TestNotifyDelivery(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	pool := notifyPool(t, ra.env)
	ctx := context.Background()
	keys, err := notify.NewKeyring(map[string][]byte{"whk-1": []byte("a-secret-of-thirty-two-bytes-xyz")})
	if err != nil {
		t.Fatal(err)
	}
	mail, post := fakeMailer{&fakeSends{}}, &fakePoster{fakeSends: &fakeSends{}}
	w := notify.Worker{DB: pool, Mail: mail, Post: post, Keys: keys, RetryHours: func() int { return 24 },
		Composer: func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} }}
	pump := func() {
		t.Helper()
		for {
			if _, _, err := (notify.Collector{DB: pool}).Collect(ctx); err != nil {
				t.Fatal(err)
			}
			r, err := (notify.FanOut{DB: pool}).Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if r.Notices == 0 {
				return
			}
		}
	}
	pump() // the fixture's own notices, before any channel
	root := ra.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	smtp := ra.adminQuery(`INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'relay',
		'{"host": "relay.example.com", "port": 587, "tls_mode": "starttls", "from": "fair@example.com"}') RETURNING id`)
	secret, _ := notify.NewWebhookSecret()
	ct := base64.StdEncoding.EncodeToString(keys.Seal(secret))
	hook := ra.adminQuery(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct) VALUES ('webhook', 'tickets',
		'{"url": "https://hooks.example.com/fair"}', '` + root + `', '{setting.revert_failed,acceptance.decision_needed}', decode('` + ct + `', 'base64')) RETURNING id`)

	// A security notice to the settings approvers, and an acceptance request.
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "k", "exception_id": "x1"}')`)
	risk := a.accepted(t, "Claims delivery", "owen")
	acc, code := a.request(t, "owen", risk, "Within appetite", days(90), "")
	if code != "" {
		t.Fatal(code)
	}
	pump()
	pending := func(where string) string {
		return ra.adminQuery("SELECT count(*) FROM notify.delivery WHERE state = 'pending' AND " + where)
	}
	due := pending("true")

	// Two workers at once: every delivery once.
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := w.Step(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	sent := map[string]int{}
	for _, id := range append(append([]string{}, mail.ids...), post.ids...) {
		sent[id]++
	}
	for id, n := range sent {
		if n != 1 {
			t.Errorf("delivery %s sent %d times", id, n)
		}
	}
	if fmt.Sprint(len(sent)) != due || pending("true") != "0" {
		t.Fatalf("sent %d of %s due, %s still pending", len(sent), due, pending("true"))
	}
	if got := ra.adminQuery("SELECT (last_success IS NOT NULL)::text FROM notify.channel WHERE id = '" + hook + "'"); got != "true" {
		t.Errorf("the webhook's last success: %s", got)
	}
	if len(post.secrets) == 0 || post.secrets[0] != secret {
		t.Errorf("the webhook's secret did not open: %v", post.secrets)
	}

	// Retries: growing delays; past retry_hours, failed and recorded.
	post.fail = func(string) error { return errors.New("connection reset") }
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": []}', '{"key": "k", "exception_id": "x2"}')`)
	pump()
	notice2 := ra.adminQuery("SELECT id FROM notify.notice WHERE item_id = 'x2'")
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	delay := func() string {
		return ra.adminQuery("SELECT attempts || ':' || round(extract(epoch FROM next_attempt_at - now())) FROM notify.delivery WHERE notice_id = '" + notice2 + "' AND channel_id = '" + hook + "'")
	}
	if got := delay(); got != "1:30" && got != "1:29" {
		t.Errorf("first retry: %s", got)
	}
	ra.admin(ra.db, "UPDATE notify.delivery SET next_attempt_at = now() WHERE notice_id = '"+notice2+"'")
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := delay(); got != "2:60" && got != "2:59" {
		t.Errorf("second retry: %s", got)
	}
	// Past its retries (creation moved back as the owner, past the rules).
	ra.admin(ra.db, "SET session_replication_role = replica; UPDATE notify.delivery SET created_at = now() - interval '25 hours', next_attempt_at = now() WHERE notice_id = '"+notice2+"'")
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ':' || reason FROM notify.delivery WHERE notice_id = '" + notice2 + "' AND channel_id = '" + hook + "'"); got != "failed:retries_exhausted" {
		t.Errorf("exhausted: %s", got)
	}
	// A security notice that reached nobody outside the app opens the finding.
	finding := func() string {
		return ra.adminQuery("SELECT coalesce((SELECT status || ':' || severity FROM posture.drift_finding WHERE check_id = 'notification_undelivered' ORDER BY first_seen DESC LIMIT 1), 'none')")
	}
	if got := finding(); got != "open:high" {
		t.Errorf("the finding: %s", got)
	}
	failed := ra.adminQuery(`SELECT count(*) || ':' || max(body ->> 'severity') FROM audit.intake WHERE body ->> 'type' = 'notification.delivery_failed'
		AND body #>> '{attributes,notice}' = '` + notice2 + `'`)
	if failed != "1:high" {
		t.Errorf("failure events: %s", failed)
	}
	// The next security notice delivered resolves it.
	post.fail = nil
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": []}', '{"key": "k", "exception_id": "x3"}')`)
	pump()
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := finding(); got != "resolved:high" {
		t.Errorf("after a delivery: %s", got)
	}

	// Permanent answers fail at once; a refused destination is recorded too.
	post.fail = func(string) error { return notify.Permanent{Err: errors.New("410 gone")} }
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": []}', '{"key": "k", "exception_id": "x4"}')`)
	pump()
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ':' || reason || ':' || attempts FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE n.item_id = 'x4'"); got != "failed:permanent:1" {
		t.Errorf("permanent: %s", got)
	}
	post.fail = func(string) error {
		return fmt.Errorf("%w: hooks.example.com is not in notification.allowed_hosts", notify.ErrRefused)
	}
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": []}', '{"key": "k", "exception_id": "x5"}')`)
	pump()
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'notification.destination_refused' AND body ->> 'severity' = 'high'`); got != "1" {
		t.Errorf("refused events: %s", got)
	}
	post.fail = nil

	// An uncertain claim (the worker stopped mid-send) returns, the same id.
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": []}', '{"key": "k", "exception_id": "x6"}')`)
	pump()
	id6 := ra.adminQuery("SELECT d.id FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE n.item_id = 'x6'")
	ra.admin(ra.db, "SET ROLE app_notify; SELECT count(*) FROM notify.claim(10, gen_random_uuid())")
	if n, _ := w.Reclaim(ctx); n != 0 {
		t.Errorf("a fresh claim reclaimed: %d", n)
	}
	ra.admin(ra.db, "UPDATE notify.delivery SET claimed_at = now() - interval '3 minutes' WHERE id = '"+id6+"'")
	if n, _ := w.Reclaim(ctx); n != 1 {
		t.Errorf("reclaimed %d", n)
	}
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ':' || attempts FROM notify.delivery WHERE id = '" + id6 + "'"); got != "sent:2" {
		t.Errorf("after reclaiming: %s", got)
	}
	if n := strings.Count(strings.Join(post.ids, ","), id6); n != 1 {
		t.Errorf("sent %d times under its id", n)
	}

	// Re-checked before each email: a deactivated approver is dropped.
	ra.admin(ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES
		('setting.revert_failed', '{"users": [], "permission_holders": "settings.approve"}', '{"key": "k", "exception_id": "x7"}')`)
	pump()
	victim := ra.adminQuery("SELECT d.user_id FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE n.item_id = 'x7' AND d.user_id IS NOT NULL LIMIT 1")
	ra.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE id = '" + victim + "'")
	if _, err := w.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ':' || reason FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE n.item_id = 'x7' AND d.user_id = '" + victim + "'"); got != "dropped:inactive" {
		t.Errorf("a deactivated recipient: %s", got)
	}

	// Digests (AC-19): owen's optional notices wait, then go as one email.
	owen := a.userID("owen")
	ra.admin(ra.db, "INSERT INTO notify.user_option (user_id, digest, digest_hour) VALUES ('"+owen+"', true, 0)")
	if _, code := a.decide(t, "appA1", acc, "approve"); code != "" {
		t.Fatal(code)
	}
	r2 := a.accepted(t, "Claims digest", "owen")
	acc2, _ := a.request(t, "owen", r2, "Within appetite", days(90), "")
	if _, code := a.decide(t, "appA1", acc2, "approve"); code != "" {
		t.Fatal(code)
	}
	pump()
	held := pending("digest AND user_id = '" + owen + "'")
	if held != "2" {
		t.Fatalf("held for the digest: %s", held)
	}
	_, _ = w.Step(ctx) // digest deliveries are not claimed one by one
	if pending("digest AND user_id = '"+owen+"'") != "2" {
		t.Fatal("a held delivery sent alone")
	}
	before := len(mail.ids)
	if ok, err := w.Digest(ctx); !ok || err != nil {
		t.Fatalf("digest: %v %v", ok, err)
	}
	if len(mail.ids) != before+1 || !strings.Contains(mail.subj[len(mail.subj)-1], "2 notices") || mail.to[len(mail.to)-1] != "owen@example.test" {
		t.Errorf("digest email: %v %v", mail.subj[before:], mail.to[before:])
	}
	if pending("digest AND user_id = '"+owen+"'") != "0" {
		t.Error("held deliveries left after the digest")
	}
	if ok, _ := w.Digest(ctx); ok {
		t.Error("a second digest the same day")
	}

	// Retention: the log past its days; notices past 180 days with their
	// in-app notifications.
	ra.admin(ra.db, "SET session_replication_role = replica; UPDATE notify.delivery SET created_at = now() - interval '100 days' WHERE channel_id = '"+smtp+"'")
	ra.admin(ra.db, "SET session_replication_role = replica; UPDATE notify.notice SET collected_at = now() - interval '200 days' WHERE item_id = 'x1'")
	d, n, err := w.Purge(ctx, 90)
	if err != nil || d == 0 || n != 1 {
		t.Errorf("purge: %d deliveries, %d notices, %v", d, n, err)
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id WHERE n.item_id = 'x1'"); got != "0" {
		t.Errorf("in-app notifications of a purged notice: %s", got)
	}
	// Claims belong to their token.
	if got := ra.adminState("SET ROLE app_notify; PERFORM notify.settle('" + id6 + "', gen_random_uuid(), 'sent', '', 24)"); got != "PF028" {
		t.Errorf("settling someone else's claim: %s", got)
	}
	if b, err := notify.Banner(ctx, pool); err != nil || !strings.HasPrefix(b, "You are accessing an information system") || !strings.HasSuffix(b, ".") {
		t.Errorf("banner: %q %v", b, err)
	}
}

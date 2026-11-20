package tests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/notifyapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-009 T-15: the database half of the STRIDE suite for design §7, over
// acceptanceFixture (owen a Risk Owner at A, chief at the root, mallory at
// B; approvers appA1 at A1, appA at A, root1 and root2 at the root;
// "platform" a Platform Admin) with an Auditor "aud". The rows map to these
// tests and others in TestSTRIDECatalog.

type f009Env struct {
	*acceptanceEnv
	na      *riskAPIEnv // the notify API, channels included
	keys    *notify.Keyring
	mail    fakeMailer
	post    *fakePoster
	allowed []string // notification.allowed_hosts, as the guard reads it
	root    string
}

func strideF009Fixture(t *testing.T) *f009Env {
	t.Helper()
	a := acceptanceFixture(t)
	ra := a.ra
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('aud@example.test', 'Aud')")
	ra.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))
	ra.drain()
	f := &f009Env{acceptanceEnv: a, allowed: []string{"203.0.113.10"}, root: ra.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")}
	pool := notifyPool(t, ra.env)
	f.keys, _ = notify.NewKeyring(map[string][]byte{"whk-1": []byte("a-secret-of-thirty-two-bytes-xyz")})
	f.mail, f.post = fakeMailer{&fakeSends{}}, &fakePoster{fakeSends: &fakeSends{}}
	guard := notify.Guard{Allowed: func() []string { return f.allowed }, Cluster: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}}
	api := &notifyapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Keys: f.keys, Guard: guard,
		Mail: f.mail, Post: f.post, Composer: func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} }}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	na := *ra
	na.url, na.aud, na.n = srv.URL, "notify", ra.n+970000
	f.na = &na
	f.pump(t, false) // the fixture's own notices, before any channel
	return f
}

// pump collects (titles or not) and fans out everything queued.
func (f *f009Env) pump(t *testing.T, titles bool) {
	t.Helper()
	p := notifyPool(t, f.ra.env)
	if _, err := (notify.Cycle{Collector: notify.Collector{DB: p, Titles: func() bool { return titles }}, FanOut: notify.FanOut{DB: p}}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *f009Env) worker(t *testing.T, mail notify.Mailer, post notify.Poster) notify.Worker {
	return notify.Worker{DB: notifyPool(t, f.ra.env), Mail: mail, Post: post, Keys: f.keys, RetryHours: func() int { return 24 },
		Composer: func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} }}
}

func (f *f009Env) deliverAll(t *testing.T, w notify.Worker) {
	t.Helper()
	for {
		n, err := w.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func (f *f009Env) channels(t *testing.T) (smtp, hook string, secret string) {
	t.Helper()
	ra := f.ra
	smtp = ra.adminQuery(`INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'relay',
		'{"host": "203.0.113.10", "port": 465, "tls_mode": "implicit", "from": "fair@example.com"}') RETURNING id`)
	secret, _ = notify.NewWebhookSecret()
	ct := base64.StdEncoding.EncodeToString(f.keys.Seal(secret))
	hook = ra.adminQuery(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct) VALUES ('webhook', 'tickets',
		'{"url": "https://203.0.113.10/fair"}', '` + f.root + `', '{acceptance.decision_needed,setting.exception_expiring}', decode('` + ct + `', 'base64')) RETURNING id`)
	return smtp, hook, secret
}

// postureNotice queues a setting.exception_expiring notice at bu, its title
// key, to the named users.
func (f *f009Env) postureNotice(bu, key, exception string, users ...string) {
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = `"` + f.userID(u) + `"`
	}
	f.ra.admin(f.ra.db, `INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES ('setting.exception_expiring',
		'{"users": [`+strings.Join(ids, ",")+`]}', '`+mustJSON(map[string]string{"key": key, "exception_id": exception, "bu_id": bu})+`')`)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return strings.ReplaceAll(string(b), "'", "''")
}

// I: notices leak risk data to email and chat tools.
func TestSTRIDEF009Content(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	hook := func(name, bu string) string {
		return ra.adminQuery(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct) VALUES ('webhook', '` + name + `',
			'{"url": "https://203.0.113.10/` + name + `"}', '` + bu + `', '{setting.exception_expiring}', '\x00') RETURNING id`)
	}
	hRoot, hB, hR := hook("root", f.root), hook("b", ra.bu["B"]), hook("r", ra.bu["R"])
	// Titles by setting: on, an unrestricted unit's notice names its item; a
	// restricted unit's never does.
	f.postureNotice(ra.bu["A1"], "Customer ledger", "c-a1", "owen")
	f.postureNotice(ra.bu["R1"], "Investigations ledger", "c-r1", "owen")
	f.pump(t, true)
	// Off (the default, minimal): no title at all.
	f.postureNotice(ra.bu["A1"], "Payroll ledger", "c-min", "owen")
	f.pump(t, false)
	env := func(item string) (map[string]any, string) {
		t.Helper()
		var e map[string]any
		raw := ra.adminQuery("SELECT envelope::text || '|' || restricted FROM notify.notice WHERE item_id = '" + item + "'")
		js, restricted, _ := strings.Cut(raw, "|")
		if err := json.Unmarshal([]byte(js), &e); err != nil {
			t.Fatalf("%s: %s", item, raw)
		}
		return e, restricted
	}
	for item, want := range map[string]struct{ title, restricted string }{"c-a1": {"Customer ledger", "false"}, "c-r1": {"", "true"}, "c-min": {"", "false"}} {
		e, restricted := env(item)
		if got, _ := e["title"].(string); got != want.title || restricted != want.restricted {
			t.Errorf("%s: title %q restricted %s", item, got, restricted)
		}
		// The envelope is the minimal shape: no payload, scores or amounts.
		for k := range e {
			if !strings.Contains(" id kind at bu item title ", " "+k+" ") {
				t.Errorf("%s: envelope field %q", item, k)
			}
		}
		// What leaves the platform is composed from the envelope alone.
		var en notify.Envelope
		b, _ := json.Marshal(e)
		_ = json.Unmarshal(b, &en)
		c := notify.Composer{Base: "https://fair.example.com"}
		m, err := c.Email(en, "A security setting exception expires soon")
		body, err2 := c.WebhookBody(en, "d")
		if err != nil || err2 != nil {
			t.Fatal(err, err2)
		}
		for _, secret := range []string{"Investigations", "Payroll"} {
			if strings.Contains(m.Subject+m.Text+m.HTML+string(body), secret) {
				t.Errorf("%s: %q leaves the platform", item, secret)
			}
		}
	}
	// Webhooks by scope: the root's takes A1's notice, not R1's; R's takes
	// only its own unit's; B's neither.
	hooks := func(item string) string {
		return ra.adminQuery(`SELECT coalesce(string_agg(d.channel_id::text, ',' ORDER BY d.channel_id), '') FROM notify.delivery d
			JOIN notify.notice n ON n.id = d.notice_id WHERE d.user_id IS NULL AND n.item_id = '` + item + "'")
	}
	if got := hooks("c-a1"); got != hRoot {
		t.Errorf("A1's notice to %s (want the root's only)", got)
	}
	if got := hooks("c-r1"); got != hR {
		t.Errorf("R1's notice to %s (want R's only)", got)
	}
	_ = hB
}

// I: a notice reaches someone who lost access.
func TestSTRIDEF009Recheck(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	f.channels(t)
	risk := f.accepted(t, "Recheck ransomware", "owen")
	acc, code := f.request(t, "owen", risk, "Within appetite", days(90), "")
	if code != "" {
		t.Fatal(code)
	}
	f.pump(t, false)
	notice := ra.adminQuery("SELECT id FROM notify.notice WHERE item_id = '" + acc + "' AND kind = 'acceptance.decision_needed'")
	// Between fan-out and sending: appA1 is disabled, appA loses the
	// approver role, root1 keeps it; only root1 and root2 are emailed.
	ra.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'appA1@example.test'")
	ra.mustOwner(revoke("platform", "appA", "Approver", "A"))
	ra.drain()
	mail := fakeMailer{&fakeSends{}}
	f.deliverAll(t, f.worker(t, mail, &fakePoster{fakeSends: &fakeSends{}}))
	got := ra.adminQuery(`SELECT string_agg(split_part(u.email, '@', 1) || ':' || d.state || ':' || coalesce(d.reason, '-'), ',' ORDER BY u.email)
		FROM notify.delivery d JOIN iam.app_user u ON u.id = d.user_id WHERE d.notice_id = '` + notice + "'")
	if got != "appA1:dropped:inactive,appA:dropped:not_visible,root1:sent:-,root2:sent:-" {
		t.Errorf("deliveries: %s", got)
	}
	for _, to := range mail.to {
		if strings.Contains(to, "appA") {
			t.Errorf("emailed %s", to)
		}
	}
}

// I, E: a channel used to reach internal systems (SSRF).
func TestSTRIDEF009Destinations(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	// Even an allow-list of "*" does not open internal ranges.
	f.allowed = []string{"*"}
	for _, u := range []string{"https://169.254.169.254/latest/meta-data", "https://127.0.0.1/x", "https://[::1]/x", "https://10.96.0.1/x",
		"https://100.64.0.1/x", "https://0.0.0.0/x", "https://[::ffff:127.0.0.1]/x"} {
		got := f.na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", map[string]any{"name": "internal", "url": u,
			"bu_id": f.root, "kinds": []any{"risk.stale"}, "reason": "probe"})
		if got.code != 422 || got.body["error"] != "destination_refused" {
			t.Errorf("%s: %d %s", u, got.code, got.raw)
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.channel"); got != "0" {
		t.Errorf("%s channels saved", got)
	}
	// A destination allowed when configured and removed from the list later
	// is refused at delivery, before any connection, and recorded.
	f.allowed = []string{"203.0.113.10"}
	f.channels(t)
	risk := f.accepted(t, "Destination ransomware", "owen")
	if _, code := f.request(t, "owen", risk, "Within appetite", days(90), ""); code != "" {
		t.Fatal(code)
	}
	f.pump(t, false)
	f.allowed = nil
	guard := notify.Guard{Allowed: func() []string { return f.allowed }}
	f.deliverAll(t, f.worker(t, notify.SMTPSender{Guard: guard, Dir: t.TempDir()}, notify.WebhookSender{Guard: guard}))
	if got := ra.adminQuery("SELECT string_agg(DISTINCT state || ':' || coalesce(reason, '-'), ',') FROM notify.delivery"); got != "failed:refused" {
		t.Errorf("deliveries: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'notification.destination_refused'"); got == "0" {
		t.Error("no destination_refused event")
	}
}

// S, T: a forged or replayed webhook delivery.
func TestSTRIDEF009Signing(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	_, hook, secret := f.channels(t)
	other, _ := notify.NewWebhookSecret()
	ra.adminQuery(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct) VALUES ('webhook', 'audit desk',
		'{"url": "https://203.0.113.10/desk"}', '` + f.root + `', '{acceptance.decision_needed}', decode('` + base64.StdEncoding.EncodeToString(f.keys.Seal(other)) + `', 'base64')) RETURNING id`)
	risk := f.accepted(t, "Signing ransomware", "owen")
	if _, code := f.request(t, "owen", risk, "Within appetite", days(90), ""); code != "" {
		t.Fatal(code)
	}
	f.pump(t, false)
	// The first attempt fails transiently; the retry carries the same id.
	post := &fakePoster{fakeSends: &fakeSends{}}
	tries := map[string]int{}
	post.fail = func(id string) error {
		tries[id]++
		if tries[id] == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}
	w := f.worker(t, fakeMailer{&fakeSends{}}, post)
	f.deliverAll(t, w)
	ra.admin(ra.db, "SET session_replication_role = replica; UPDATE notify.delivery SET next_attempt_at = now() WHERE state = 'pending'")
	f.deliverAll(t, w)
	if len(post.ids) != 4 {
		t.Fatalf("posts %v", post.ids)
	}
	seen := map[string][]string{}
	for i, id := range post.ids {
		seen[id] = append(seen[id], post.secrets[i])
	}
	mine := ra.adminQuery("SELECT id FROM notify.delivery WHERE channel_id = '" + hook + "'")
	for id, secrets := range seen {
		if len(secrets) != 2 || secrets[0] != secrets[1] {
			t.Errorf("delivery %s: %d attempts with secrets %v", id, len(secrets), secrets)
		}
		want := other
		if id == mine {
			want = secret
		}
		if secrets[0] != want {
			t.Errorf("delivery %s signed with another webhook's secret", id)
		}
	}
	if got := ra.adminQuery("SELECT string_agg(DISTINCT state, ',') FROM notify.delivery WHERE user_id IS NULL"); got != "sent" {
		t.Errorf("webhook deliveries: %s", got)
	}
}

// I: secrets and credentials disclosed.
func TestSTRIDEF009Secrets(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	got := f.na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", map[string]any{"name": "Tickets", "url": "https://203.0.113.10/fair",
		"bu_id": f.root, "kinds": []any{"acceptance.decision_needed"}, "reason": "tickets"})
	if got.code != 201 {
		t.Fatalf("webhook: %d %s", got.code, got.raw)
	}
	secret := got.body["secret"].(string)
	id := got.body["channel"].(map[string]any)["id"].(string)
	f.pump(t, false)
	// Never again: not in the list, the log, a test's answer or the trail.
	for _, path := range []string{"/api/v1/notifications/channels", "/api/v1/notifications/deliveries"} {
		if got := f.na.call(t, "GET", "aud", path, nil); got.code != 200 || strings.Contains(got.raw, secret) || strings.Contains(got.raw, "secret_ct") {
			t.Errorf("%s: %d %s", path, got.code, got.raw)
		}
	}
	if got := f.na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+id+"/test", nil); got.code != 200 || strings.Contains(got.raw, secret) {
		t.Errorf("test: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body::text LIKE '%whsec_%'"); got != "0" {
		t.Errorf("%s events hold a secret", got)
	}
	// At rest: ciphertext, opened only with the key.
	ct, _ := base64.StdEncoding.DecodeString(ra.adminQuery("SELECT encode(secret_ct, 'base64') FROM notify.channel WHERE id = '" + id + "'"))
	if strings.Contains(string(ct), secret) {
		t.Error("stored in clear")
	}
	otherKeys, _ := notify.NewKeyring(map[string][]byte{"whk-1": []byte("another-key-of-thirty-two-bytes!")})
	if _, err := otherKeys.Open(ct); err == nil {
		t.Error("opened with another key")
	}
	// The tables are the definer's alone; services and users go through functions.
	for _, role := range []string{"app_notify", "app_rw", "app_posture", "app_audit"} {
		ra.mustFail(role, "SELECT secret_ct FROM notify.channel", "permission denied")
	}
	// Passwords are never taken: a file name only.
	if got := f.na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"reason": "x",
		"config": map[string]any{"host": "203.0.113.10", "port": 587, "tls_mode": "starttls", "from": "fair@example.com", "username": "u", "password": "hunter2"}}); got.code != 400 {
		t.Errorf("a password: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.channel WHERE config::text LIKE '%hunter2%'"); got != "0" {
		t.Error("a password stored")
	}
	// Removed: the secrets are erased.
	if got := f.na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+id+"/remove", map[string]any{"reason": "gone"}); got.code != 200 {
		t.Fatalf("remove: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (secret_ct = '\\x00'::bytea)::text FROM notify.channel WHERE id = '" + id + "'"); got != "true" {
		t.Errorf("a removed webhook's secret: %s", got)
	}
}

// T: injection through notice content.
func TestSTRIDEF009Injection(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	f.channels(t)
	f.postureNotice(ra.bu["A1"], "Ledger\r\nBcc: attacker@example.com <script>alert(1)</script>", "inj-1", "owen")
	f.pump(t, true)
	mail := fakeMailer{&fakeSends{}}
	f.deliverAll(t, f.worker(t, mail, &fakePoster{fakeSends: &fakeSends{}}))
	if len(mail.subj) != 1 {
		t.Fatalf("emails %v", mail.subj)
	}
	if strings.ContainsAny(mail.subj[0], "\r\n") {
		t.Errorf("subject %q", mail.subj[0])
	}
	// The link is the platform's own path; the envelope cannot carry another.
	if got := ra.adminQuery("SELECT envelope #>> '{item,link}' FROM notify.notice WHERE item_id = 'inj-1'"); got != "/posture" {
		t.Errorf("link %q", got)
	}
	var en notify.Envelope
	_ = json.Unmarshal([]byte(ra.adminQuery("SELECT envelope::text FROM notify.notice WHERE item_id = 'inj-1'")), &en)
	m, err := (notify.Composer{Base: "https://fair.example.com"}).Email(en, "A security setting exception expires soon")
	if err != nil || strings.Contains(m.HTML, "<script>") || strings.ContainsAny(m.Subject, "\r\n") {
		t.Errorf("composed: %v %q", err, m.Subject)
	}
	if !strings.Contains(m.HTML, "https://fair.example.com/posture") {
		t.Errorf("the link is not built from the base URL:\n%s", m.HTML)
	}
}

// E: users read others' notices or change channels.
func TestSTRIDEF009Access(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	f.postureNotice(ra.bu["A1"], "k1", "acc-owen", "owen")
	f.postureNotice(ra.bu["A1"], "k2", "acc-root1", "root1")
	f.pump(t, false)
	theirs := ra.adminQuery("SELECT i.id FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id WHERE n.item_id = 'acc-root1'")
	// Own rows only: another's id is neither listed nor marked.
	if got := f.na.call(t, "GET", "owen", "/api/v1/notifications", nil); got.code != 200 || strings.Contains(got.raw, "acc-root1") || !strings.Contains(got.raw, "acc-owen") {
		t.Errorf("owen's list: %d %s", got.code, got.raw)
	}
	if got := f.na.call(t, "POST", "owen", "/api/v1/notifications/read", map[string]any{"ids": []any{json.Number(theirs)}}); got.code != 200 || got.body["marked"] != 0.0 {
		t.Errorf("marking another's: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (read_at IS NULL)::text FROM notify.inbox WHERE id = " + theirs); got != "true" {
		t.Error("another's notification marked read")
	}
	// Without a signed context, or as another service: refused.
	ra.mustFail("app_notify", "SELECT notify.my_notifications(false, NULL, 50)", "")
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		ra.mustFail(role, "SELECT notify.my_notifications(false, NULL, 50)", "permission denied")
		ra.mustFail(role, "SELECT notify.channels()", "permission denied")
	}
	ra.mustFail("app_notify", "SELECT * FROM notify.inbox", "permission denied")
	// Channels: manage changes, view reads, others are not told they exist.
	body := map[string]any{"reason": "x", "config": map[string]any{"host": "203.0.113.10", "port": 465, "tls_mode": "implicit", "from": "fair@example.com"}}
	for user, want := range map[string]int{"owen": 404, "mallory": 404, "chief": 404, "aud": 403} {
		if got := f.na.call(t, "PUT", user, "/api/v1/notifications/channels/smtp", body); got.code != want {
			t.Errorf("%s configures the relay: %d", user, got.code)
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.channel"); got != "0" {
		t.Errorf("%s channels", got)
	}
	// The permission is privileged in the catalog.
	if got := ra.adminQuery("SELECT privileged::text FROM iam.permission WHERE key = 'notification.manage'"); got != "true" {
		t.Errorf("notification.manage privileged: %s", got)
	}
}

// R: configuration changes or failures not attributable; and audit fails closed.
func TestNotifyAuditEvents(t *testing.T) {
	f := strideF009Fixture(t)
	ra := f.ra
	cfg := map[string]any{"host": "203.0.113.10", "port": 465, "tls_mode": "implicit", "from": "fair@example.com"}
	if got := f.na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": cfg, "reason": "the relay"}); got.code != 200 {
		t.Fatalf("relay: %d %s", got.code, got.raw)
	}
	smtp := ra.adminQuery("SELECT id FROM notify.channel WHERE kind = 'smtp'")
	if got := f.na.call(t, "PUT", "owen", "/api/v1/notifications/preferences", map[string]any{"digest": true, "digest_hour": 6}); got.code != 200 {
		t.Fatalf("preferences: %d %s", got.code, got.raw)
	}
	// A failure: the relay answers permanently.
	risk := f.accepted(t, "Audit ransomware", "owen")
	if _, code := f.request(t, "owen", risk, "Within appetite", days(90), ""); code != "" {
		t.Fatal(code)
	}
	f.pump(t, false)
	mail := fakeMailer{&fakeSends{fail: func(string) error { return notify.Permanent{Err: context.Canceled} }}}
	f.deliverAll(t, f.worker(t, mail, &fakePoster{fakeSends: &fakeSends{}}))
	platform, owen := f.userID("platform"), f.userID("owen")
	for typ, actor := range map[string]string{"notification.channel_created": "user:" + platform, "notification.preferences_changed": "user:" + owen,
		"notification.delivery_failed": "system:notify"} {
		got := ra.adminQuery("SELECT coalesce(string_agg(DISTINCT body ->> 'actor', ','), '') FROM audit.intake WHERE body ->> 'type' = '" + typ + "'")
		if got == "" || !strings.Contains(got, strings.TrimPrefix(actor, "user:")) && !strings.HasPrefix(got, "system") {
			t.Errorf("%s: actors %q (want %s)", typ, got, actor)
		}
	}
	if got := ra.adminQuery("SELECT body #>> '{attributes,reason}' FROM audit.intake WHERE body ->> 'type' = 'notification.channel_created'"); got != "the relay" {
		t.Errorf("reason %q", got)
	}
	// Fail closed: with the trail full, a change is refused whole.
	ap := ra.auditPool()
	emitter := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap})
	used, err := auditsvc.CapacityMonitor{DB: ap, Audit: emitter, Quota: 1 << 50}.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := (auditsvc.CapacityMonitor{DB: ap, Audit: emitter, Quota: used.Used * 100 / 120}).Step(context.Background()); err != nil || r.Level != "full" {
		t.Fatalf("full: %+v %v", r, err)
	}
	if got := f.na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+smtp+"/disable", map[string]any{"reason": "while full"}); got.code < 500 {
		t.Errorf("a change while the trail is full: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT enabled::text FROM notify.channel WHERE id = '" + smtp + "'"); got != "true" {
		t.Error("the change was saved without its event")
	}
	if _, err := (auditsvc.CapacityMonitor{DB: ap, Audit: emitter, Quota: 1 << 50}).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
}

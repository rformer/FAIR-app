package tests

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/notifyapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-009 T-11 (F-009-AC-08 to AC-12, AC-17, AC-21; design §3.4, §6).
func TestNotifyChannels(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('aud@example.test', 'Aud')")
	ra.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))
	ra.drain()
	pool := notifyPool(t, ra.env)
	keys, _ := notify.NewKeyring(map[string][]byte{"whk-1": []byte("a-secret-of-thirty-two-bytes-xyz")})
	mail, post := fakeMailer{&fakeSends{}}, &fakePoster{fakeSends: &fakeSends{}}
	guard := notify.Guard{Allowed: func() []string { return []string{"203.0.113.10"} }}
	api := &notifyapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Keys: keys, Guard: guard,
		Mail: mail, Post: post, Composer: func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} }}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	na := *ra
	na.url, na.aud, na.n = srv.URL, "notify", ra.n+950000
	root := ra.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	smtpCfg := map[string]any{"host": "203.0.113.10", "port": 587, "tls_mode": "starttls", "from": "FAIR <fair@example.com>", "username": "fair", "password_file": "relay"}

	// Who may: manage changes; view reads; others are not told it exists.
	if got := na.call(t, "GET", "owen", "/api/v1/notifications/channels", nil); got.code != 404 {
		t.Errorf("owen lists channels: %d", got.code)
	}
	if got := na.call(t, "GET", "aud", "/api/v1/notifications/channels", nil); got.code != 200 {
		t.Errorf("an auditor lists channels: %d %s", got.code, got.raw)
	}
	if got := na.call(t, "PUT", "aud", "/api/v1/notifications/channels/smtp", map[string]any{"config": smtpCfg, "reason": "x"}); got.code != 403 {
		t.Errorf("an auditor configures the relay: %d %s", got.code, got.raw)
	}

	// The relay (AC-08): never plaintext, no password, allowed hosts only.
	for name, c := range map[string]struct {
		cfg  map[string]any
		code int
		err  string
	}{
		"plaintext":        {map[string]any{"host": "203.0.113.10", "port": 25, "tls_mode": "none", "from": "fair@example.com"}, 422, "invalid_config"},
		"a password":       {map[string]any{"host": "203.0.113.10", "port": 587, "tls_mode": "starttls", "from": "fair@example.com", "password": "x"}, 400, "invalid_request"},
		"a path":           {map[string]any{"host": "203.0.113.10", "port": 587, "tls_mode": "starttls", "from": "fair@example.com", "username": "u", "password_file": "/etc/shadow"}, 422, "invalid_config"},
		"an unlisted host": {map[string]any{"host": "198.51.100.7", "port": 587, "tls_mode": "starttls", "from": "fair@example.com"}, 422, "destination_refused"},
		"a loopback host":  {map[string]any{"host": "127.0.0.1", "port": 587, "tls_mode": "starttls", "from": "fair@example.com"}, 422, "destination_refused"},
	} {
		if got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": c.cfg, "reason": "relay"}); got.code != c.code || got.body["error"] != c.err {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": smtpCfg}); got.code != 400 {
		t.Errorf("without a reason: %d %s", got.code, got.raw)
	}
	got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": smtpCfg, "reason": "the corporate relay"})
	if got.code != 200 || got.body["version"] != 1.0 || got.body["kind"] != "smtp" {
		t.Fatalf("relay: %d %s", got.code, got.raw)
	}
	smtpID := got.body["id"].(string)
	smtpCfg["port"] = 465
	smtpCfg["tls_mode"] = "implicit"
	if got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": smtpCfg, "expected_version": 0, "reason": "x"}); got.code != 409 {
		t.Errorf("a stale version: %d %s", got.code, got.raw)
	}
	if got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/smtp", map[string]any{"config": smtpCfg, "expected_version": 1, "reason": "implicit TLS"}); got.code != 200 || got.body["version"] != 2.0 {
		t.Errorf("relay change: %d %s", got.code, got.raw)
	}

	// Webhooks (AC-09): the secret once; never returned again.
	hook := map[string]any{"name": "Tickets", "url": "https://203.0.113.10/fair", "bu_id": ra.bu["A"], "kinds": []any{"acceptance.decision_needed"}, "reason": "ticketing"}
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"http":          {map[string]any{"name": "x", "url": "http://203.0.113.10/x", "bu_id": root, "kinds": []any{"risk.stale"}, "reason": "x"}, 422},
		"credentials":   {map[string]any{"name": "x", "url": "https://u:p@203.0.113.10/x", "bu_id": root, "kinds": []any{"risk.stale"}, "reason": "x"}, 422},
		"unlisted":      {map[string]any{"name": "x", "url": "https://198.51.100.7/x", "bu_id": root, "kinds": []any{"risk.stale"}, "reason": "x"}, 422},
		"unknown kind":  {map[string]any{"name": "x", "url": "https://203.0.113.10/x", "bu_id": root, "kinds": []any{"mail.spam"}, "reason": "x"}, 400},
		"no kinds":      {map[string]any{"name": "x", "url": "https://203.0.113.10/x", "bu_id": root, "kinds": []any{}, "reason": "x"}, 400},
		"the test kind": {map[string]any{"name": "x", "url": "https://203.0.113.10/x", "bu_id": root, "kinds": []any{"notify.test"}, "reason": "x"}, 400},
	} {
		if got := na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", c.body); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	got = na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", hook, "webhook-create-key")
	if got.code != 201 || !strings.HasPrefix(got.body["secret"].(string), notify.SecretPrefix) {
		t.Fatalf("webhook: %d %s", got.code, got.raw)
	}
	secret := got.body["secret"].(string)
	hookID := got.body["channel"].(map[string]any)["id"].(string)
	if replay := na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", hook, "webhook-create-key"); replay.code != 409 || strings.Contains(replay.raw, secret) {
		t.Errorf("a replay shows the secret: %d %s", replay.code, replay.raw)
	}
	list := na.call(t, "GET", "aud", "/api/v1/notifications/channels", nil)
	if strings.Contains(list.raw, secret) || strings.Contains(list.raw, "secret_ct") || len(list.body["channels"].([]any)) != 2 {
		t.Errorf("the list: %s", list.raw)
	}
	stored := ra.adminQuery("SELECT encode(secret_ct, 'base64') FROM notify.channel WHERE id = '" + hookID + "'")
	if ct, _ := base64.StdEncoding.DecodeString(stored); strings.Contains(string(ct), secret) {
		t.Error("the secret is stored in clear")
	} else if opened, err := keys.Open(ct); err != nil || opened != secret {
		t.Errorf("the sealed secret: %v", err)
	}
	if got := na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks", hook); got.code != 409 || got.body["error"] != "name_taken" {
		t.Errorf("a second webhook of the name: %d %s", got.code, got.raw)
	}
	hook["kinds"], hook["expected_version"], hook["bu_id"] = []any{"acceptance.decision_needed", "risk.stale"}, 1, root
	if got := na.call(t, "PUT", "platform", "/api/v1/notifications/channels/webhooks/"+hookID, hook); got.code != 200 || got.body["version"] != 2.0 {
		t.Errorf("webhook change: %d %s", got.code, got.raw)
	}

	// Rotation: a new secret once; the previous one still signs.
	got = na.call(t, "POST", "platform", "/api/v1/notifications/channels/webhooks/"+hookID+"/rotate-secret", map[string]any{"reason": "yearly"})
	if got.code != 200 || got.body["secret"] == secret || got.body["channel"].(map[string]any)["rotation_until"] == nil {
		t.Fatalf("rotate: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (previous_ct = decode('" + stored + "', 'base64'))::text FROM notify.channel WHERE id = '" + hookID + "'"); got != "true" {
		t.Errorf("the previous secret kept: %s", got)
	}

	// Test messages (AC-11): email to the caller, the webhook; recorded.
	got = na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+smtpID+"/test", nil)
	if got.code != 200 || got.body["sent"] != true || len(mail.ids) != 1 || !strings.HasPrefix(mail.ids[0], "test-") {
		t.Errorf("smtp test: %d %s %v", got.code, got.raw, mail.ids)
	}
	post.fail = func(string) error { return notify.Permanent{Err: context.DeadlineExceeded} }
	got = na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+hookID+"/test", nil)
	if got.code != 200 || got.body["sent"] != false || len(post.secrets) != 1 || post.secrets[0] == secret {
		t.Errorf("webhook test (with the rotated secret): %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT count(*) FROM notify.delivery"); got != "0" {
		t.Errorf("a test message queued %s deliveries", got)
	}

	// Disable, enable, remove (AC-12).
	for _, c := range []struct {
		action string
		code   int
	}{{"disable", 200}, {"disable", 409}, {"enable", 200}, {"remove", 200}, {"enable", 404}} {
		if got := na.call(t, "POST", "platform", "/api/v1/notifications/channels/"+hookID+"/"+c.action, map[string]any{"reason": "maintenance"}); got.code != c.code {
			t.Errorf("%s: %d %s", c.action, got.code, got.raw)
		}
	}
	if got := ra.adminQuery("SELECT (secret_ct = '\\x00'::bytea AND previous_ct IS NULL)::text FROM notify.channel WHERE id = '" + hookID + "'"); got != "true" {
		t.Errorf("a removed webhook keeps its secret: %s", got)
	}

	// Every change audited, with the actor and the reason (AC-21).
	evs := ra.adminQuery(`SELECT string_agg(body ->> 'type' || ':' || coalesce(body #>> '{attributes,reason}', '-'), ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' LIKE 'notification.%' AND body ->> 'type' <> 'notification.preferences_changed'`)
	for _, want := range []string{"notification.channel_created:the corporate relay", "notification.channel_changed:implicit TLS", "notification.channel_created:ticketing",
		"notification.channel_changed:ticketing", "notification.secret_rotated:yearly", "notification.test_sent:test message", "notification.channel_disabled:maintenance",
		"notification.channel_enabled:maintenance", "notification.channel_removed:maintenance"} {
		if !strings.Contains(evs, want) {
			t.Errorf("no %s in %s", want, evs)
		}
	}
	if strings.Contains(evs, secret) {
		t.Error("a secret in the trail")
	}

	// The delivery log (AC-17), for view and manage only.
	if got := na.call(t, "GET", "aud", "/api/v1/notifications/deliveries?state=failed&limit=10", nil); got.code != 200 {
		t.Errorf("deliveries: %d %s", got.code, got.raw)
	}
	if got := na.call(t, "GET", "owen", "/api/v1/notifications/deliveries", nil); got.code != 404 {
		t.Errorf("owen reads the log: %d", got.code)
	}
	for _, q := range []string{"?state=lost", "?kind=mail.spam", "?limit=0", "?before=yesterday", "?channel=x"} {
		if got := na.call(t, "GET", "aud", "/api/v1/notifications/deliveries"+q, nil); got.code != 400 {
			t.Errorf("%s: %d", q, got.code)
		}
	}

	// T-13: the business units a webhook may take (names only), for view and manage.
	if got := na.call(t, "GET", "aud", "/api/v1/notifications/bus", nil); got.code != 200 || !strings.Contains(got.raw, `"code":"A"`) {
		t.Errorf("bus: %d %s", got.code, got.raw)
	}
	if got := na.call(t, "GET", "owen", "/api/v1/notifications/bus", nil); got.code != 404 {
		t.Errorf("owen lists the BUs: %d", got.code)
	}
}

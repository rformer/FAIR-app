package tests

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-001 T-23: just-in-time provisioning (AC-09: off by default; no roles)
// and the inactivity sweep (AC-11: 90 days by default).

// seedPosture installs the Enterprise Baseline, so the database reads the
// settings in force as in production.
func seedPosture(t *testing.T, e *env) {
	t.Helper()
	addMACKey(e, "k1")
	e.mustOwner("SELECT posture.set_deployment_mode('self-hosted')")
	if _, err := posture.Seed(context.Background(), e.posturePool(), audit.NewMemory(), "system:installer", settings.ProfileEnterpriseBaseline, ""); err != nil {
		t.Fatal(err)
	}
}

// setInstance changes an instance value directly (as a test may; the
// production path is the posture change workflow).
func setInstance(e *env, key, value string) {
	e.admin(e.db, `INSERT INTO posture.setting_value (key, bu_id, value, source, row_mac, mac_key_id)
		VALUES ('`+key+`', NULL, '`+value+`', 'profile', '\x`+strings.Repeat("00", 32)+`', 'k1')
		ON CONFLICT (key, bu_id) DO UPDATE SET value = EXCLUDED.value`)
}

func TestJITProvisioning(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	seedPosture(t, e)
	login := func(nameID string, attrs map[string][]string) (int, string) {
		t.Helper()
		r := se.response(se.startLogin(t, "/"), nameID)
		r.Attributes = attrs
		resp := se.post(t, se.build(t, r), nil)
		_ = resp.Body.Close()
		return resp.StatusCode, sessionCookie(resp)
	}
	denied := func() string {
		return e.adminQuery("SELECT coalesce(string_agg(payload->>'reason', '|' ORDER BY id), '') FROM iam.event_outbox WHERE payload->>'type' = 'authn.login.denied'")
	}
	nobody := func(email string) {
		t.Helper()
		if n := e.adminQuery("SELECT count(*) FROM iam.app_user WHERE lower(email) = lower('" + email + "')"); n != "0" {
			t.Fatalf("%s was created", email)
		}
	}

	// Off by default (every profile): an unknown subject is refused, nothing created.
	if v := e.adminQuery("SELECT iam.instance_setting('auth.jit_provisioning')"); v != "false" {
		t.Fatalf("default %s", v)
	}
	if code, c := login("new@example.test", nil); code != http.StatusUnauthorized || c != "" {
		t.Fatalf("JIT off: %d", code)
	}
	nobody("new@example.test")
	// The service believing it on does not suffice: the database checks the setting itself.
	se.mfa.jit = true
	if code, _ := login("new@example.test", nil); code != http.StatusUnauthorized || !strings.Contains(denied(), "provisioning is off") {
		t.Fatalf("service on, setting off: %d %s", code, denied())
	}
	nobody("new@example.test")
	e.mustFail("app_rw", "SELECT iam.jit_provision('"+se.idpID+"', 'x', 'x@example.test', 'X')", "provisioning is off")

	// On: the user is created with the IdP's email and name, signs in, and has no roles.
	setInstance(e, "auth.jit_provisioning", "true")
	code, cookie := login("new@example.test", map[string][]string{"http://schemas.microsoft.com/identity/claims/displayname": {"New Person"}})
	if code != http.StatusOK || cookie == "" {
		t.Fatalf("JIT on: %d %s", code, denied())
	}
	id := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'new@example.test'")
	if got := e.adminQuery("SELECT source || '|' || display_name || '|' || external_id || '|' || idp_id FROM iam.app_user WHERE id = '" + id + "'"); got != "jit|New Person|new@example.test|"+se.idpID {
		t.Fatalf("provisioned %q", got)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.assignment WHERE principal_id = '" + id + "'"); n != "0" {
		t.Fatal("a just-in-time user got a role (AC-09)")
	}
	e.drain()
	if n := e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '" + id + "'"); n != "0" {
		t.Fatal("a just-in-time user has access")
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'user.jit_provisioned' AND payload->>'target' = 'user:" + id + "'"); n != "1" {
		t.Fatal("provisioning not audited")
	}
	// The next login finds the user (no second account).
	if code, _ := login("new@example.test", nil); code != http.StatusOK {
		t.Fatalf("second login: %d", code)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.app_user WHERE source = 'jit'"); n != "1" {
		t.Fatalf("%s JIT users", n)
	}
	// The email comes from an email attribute when the NameID is not one.
	if code, _ := login("opaque-subject-42", map[string][]string{"mail": {"Mail.Attr@example.test"}}); code != http.StatusOK {
		t.Fatalf("email attribute: %d %s", code, denied())
	}
	// Refused, nothing created: an email outside the IdP's domains, an email
	// that belongs to another account (no silent linking), no email at all.
	for name, c := range map[string]struct {
		nameID string
		attrs  map[string][]string
		reason string
	}{
		"other domain": {"x@elsewhere.example", nil, "not served by this IdP"},
		"taken email":  {"another-subject", map[string][]string{"email": {"USER@example.test"}}, "belongs to another account"},
		"no email":     {"opaque-subject-43", nil, "email address are required"},
	} {
		if code, _ := login(c.nameID, c.attrs); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
		if !strings.Contains(denied(), c.reason) {
			t.Errorf("%s: reasons %s", name, denied())
		}
	}
	nobody("x@elsewhere.example")
	if n := e.adminQuery("SELECT count(*) FROM iam.app_user WHERE external_id = 'another-subject'"); n != "0" {
		t.Fatal("an account was linked by email")
	}
	// Turned off again: unknown subjects are refused again.
	setInstance(e, "auth.jit_provisioning", "false")
	if code, _ := login("later@example.test", nil); code != http.StatusUnauthorized {
		t.Fatalf("JIT turned off: %d", code)
	}
	nobody("later@example.test")
}

// OIDC: an email the IdP says is unverified is not provisioned.
func TestJITProvisioningOIDC(t *testing.T) {
	oe := oidcFixture(t)
	e := oe.e
	seedPosture(t, e)
	setInstance(e, "auth.jit_provisioning", "true")
	oe.mfa.jit = true
	resp, _ := oe.signIn(t, "fresh@corp.example", "/", map[string]any{"email": "fresh@corp.example", "email_verified": false})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unverified email: %d", resp.StatusCode)
	}
	resp, _ = oe.signIn(t, "fresh@corp.example", "/", map[string]any{"email": "fresh@corp.example", "email_verified": "true", "name": "Fresh"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified email: %d", resp.StatusCode)
	}
	if got := e.adminQuery("SELECT source || '|' || display_name FROM iam.app_user WHERE email = 'fresh@corp.example'"); got != "jit|Fresh" {
		t.Fatalf("provisioned %q", got)
	}
}

func TestInactivitySweep(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	w := scope.New(scope.Options{Pool: e.appPool(), Audit: audit.NewMemory()})
	ctx := context.Background()
	// Without the setting in force the sweep refuses to guess.
	_, err := w.SweepInactive(ctx)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "PF003" {
		t.Fatalf("sweep without settings: %v", err)
	}
	seedPosture(t, e)
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name, source, created_at, last_login_at) VALUES
		('stale@example.test', 'Stale', 'scim', now() - interval '200 days', now() - interval '100 days'),
		('never@example.test', 'Never', 'scim', now() - interval '91 days', NULL),
		('recent@example.test', 'Recent', 'scim', now() - interval '200 days', now() - interval '10 days'),
		('glass@example.test', 'Glass', 'breakglass', now() - interval '400 days', NULL),
		('newish@example.test', 'Newish', 'jit', now() - interval '89 days', NULL),
		('busy@example.test', 'Busy', 'scim', now() - interval '200 days', now() - interval '100 days'),
		('gone@example.test', 'Gone', 'scim', now() - interval '200 days', now() - interval '100 days')`)
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled', disabled_reason = 'scim' WHERE email = 'gone@example.test'")
	stale := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'stale@example.test'")
	cookie := ge.login(t, "stale") // a session from long ago, idle since
	e.mustOwner("UPDATE iam.session SET last_seen_at = now() - interval '100 days', created_at = now() - interval '100 days', absolute_expiry_at = now() + interval '1 day' WHERE user_id = '" + stale + "'")
	e.mustOwner("UPDATE iam.app_user SET last_login_at = now() - interval '100 days' WHERE id = '" + stale + "'")
	busy := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'busy@example.test'")
	e.mustOwner(`INSERT INTO iam.session (id_hmac, user_id, auth_method, absolute_expiry_at, created_at, last_seen_at)
		VALUES (authz.gen_random_bytes(32), '` + busy + `', 'oidc', now() + interval '1 day', now() - interval '1 day', now() - interval '1 hour')`)

	n, err := w.SweepInactive(ctx)
	if err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	got := e.adminQuery(`SELECT string_agg(split_part(email, '@', 1) || ':' || status || ':' || coalesce(disabled_reason, ''), ',' ORDER BY email)
		FROM iam.app_user WHERE email IN ('stale@example.test', 'never@example.test', 'recent@example.test', 'glass@example.test',
		'newish@example.test', 'busy@example.test', 'gone@example.test')`)
	want := "busy:active:,glass:active:,gone:disabled:scim,never:disabled:inactive,newish:active:,recent:active:,stale:disabled:inactive"
	if got != want {
		t.Fatalf("after the sweep\n %s\nwant\n %s", got, want)
	}
	// Disabled users lose their sessions (T-22) and the sweep is audited.
	if r := ge.do(t, "GET", "/api/v1/me", cookie, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("an inactive user's session: %d", r.code)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'user.disabled_inactive' AND payload->'attributes'->>'inactive_after' = '2160h0m0s'"); n != "2" {
		t.Fatalf("%s sweep audit events", n)
	}
	// Idempotent; a shorter period (a stricter profile) catches more.
	if n, _ := w.SweepInactive(ctx); n != 0 {
		t.Fatalf("second sweep disabled %d", n)
	}
	setInstance(e, "auth.inactive_disable_after", `"720h0m0s"`) // 30 days
	if n, _ := w.SweepInactive(ctx); n != 1 {                   // newish (89 days) yes; recent (10 days) no
		t.Fatalf("30-day sweep disabled %d", n)
	}
	if got := e.adminQuery("SELECT status FROM iam.app_user WHERE email = 'newish@example.test'"); got != "disabled" {
		t.Fatalf("newish %s", got)
	}
}

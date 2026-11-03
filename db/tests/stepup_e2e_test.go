package tests

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/postureapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-24b (AC-33; design §6.6): step-up end to end, through the real
// gateway, iam's SAML and OIDC sign-in and the Posture API. A sign-in older
// than the restricted BU's bu.reauth_max_age (15 minutes, the overlay) gets
// 401 step_up with the way back; re-authenticating at the IdP (ForceAuthn,
// prompt=login) gives a new session, revokes the old one, and the BU opens.
// A step-up the IdP did not honour is refused.

// stepUpPosture seeds the posture state and mounts the Posture API, with
// the step-up check, as the gateway's posture upstream; it adds the
// restricted BU R, where user holds an explicit grant, and returns R's id.
func stepUpPosture(t *testing.T, ge *gwEnv) string {
	t.Helper()
	ctx := context.Background()
	e := ge.e
	addMACKey(e, "k1")
	e.mustOwner("SELECT posture.set_deployment_mode('self-hosted')")
	if _, err := posture.Seed(ctx, e.posturePool(), audit.NewMemory(), "system:installer", settings.ProfileEnterpriseBaseline, ""); err != nil {
		t.Fatal(err)
	}
	app := e.appPool()
	c := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: app}, Service: "posture"})
	if err := c.Register(settings.F001Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, settings.DBRegistrar{DB: app}, "F-001", "1"); err != nil {
		t.Fatal(err)
	}
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'ENTERPRISE'")
	e.mustOwner(grant("admin", "user:user", "Executive Viewer", "R"))
	e.mustOwner(grant("admin", "user:user", "Auditor", "R"))
	e.mustOwner(grant("admin", "user:user", "Auditor", "ENTERPRISE"))
	e.drain()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pool := e.posturePool()
	api := &postureapi.API{DB: pool, Audit: audit.NewMemory(),
		Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool), ReauthMaxAge: c.ReauthMaxAge})}
	srv := httptest.NewServer(api.Handler(ge.keys, nil))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	ge.g.Upstreams["posture"] = u
	ge.resetHandler(t)
	return e.adminQuery("SELECT id FROM iam.bu WHERE code = 'R'")
}

// ack acknowledges the system-use banner for a session (every new session
// shows it first, the one a step-up creates too).
func (ge *gwEnv) ack(cookie string) {
	ge.e.mustOwner("UPDATE iam.session SET banner_ack_at = now(), banner_version = 1 WHERE id_hmac = '\\x" + hmacSID(ge.g.Sessions.Pepper, cookie) + "'")
}

// authnRequest decodes the AuthnRequest of an IdP redirect: its ID and XML.
func authnRequest(t *testing.T, loc string) (id, xml string) {
	t.Helper()
	u, _ := url.Parse(loc)
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	x, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(` ID="([^"]+)"`).FindSubmatch(x)
	if m == nil {
		t.Fatalf("AuthnRequest %s", x)
	}
	return string(m[1]), string(x)
}

func TestStepUpEndToEndSAML(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	r := stepUpPosture(t, se.gwEnv)
	settingsAtR := "/api/v1/posture/settings?bu=" + r

	// Sign in: the session records the IdP's AuthnInstant (30 s before the
	// response, as the test IdP writes it).
	resp := se.post(t, se.build(t, se.response(se.startLogin(t, "/"), "user@example.test")), nil)
	_ = resp.Body.Close()
	first := sessionCookie(resp)
	se.ack(first)
	// AuthnInstant has second precision: 30 to 32 seconds before the session.
	if got := se.sessionRow(t, first, "(extract(epoch FROM created_at - auth_time) BETWEEN 29 AND 32)::text"); got != "true" {
		t.Fatalf("auth_time is not the IdP's AuthnInstant (about 30 s before the session): %s",
			se.sessionRow(t, first, "extract(epoch FROM created_at - auth_time)::text"))
	}
	if g := se.do(t, "GET", settingsAtR, first, nil, nil); g.code != 200 {
		t.Fatalf("a fresh sign-in at the restricted BU: %d %s", g.code, g.raw)
	}

	// The IdP authentication was 20 minutes ago (the session itself is new:
	// what counts is auth_time): step-up, with the way back.
	e.mustOwner("UPDATE iam.session SET auth_time = auth_time - interval '20 minutes' " +
		"WHERE user_id = (SELECT id FROM iam.app_user WHERE email = 'user@example.test')")
	g := se.do(t, "GET", settingsAtR, first, nil, nil)
	wantURL := "/api/v1/auth/saml/" + se.idpID + "/login?max_age=900&step_up=1"
	if g.code != 401 || g.body["error"] != "step_up_required" || g.body["login_url"] != wantURL || g.body["max_age"] != float64(900) ||
		g.hdr.Get("WWW-Authenticate") != "step_up max_age=900" {
		t.Fatalf("a stale sign-in at the restricted BU: %d %v %s", g.code, g.hdr, g.raw)
	}
	// Elsewhere the same session still works (12h outside restricted BUs).
	if g := se.do(t, "GET", "/api/v1/posture/settings", first, nil, nil); g.code != 200 {
		t.Fatalf("the instance settings with a 20-minute-old sign-in: %d", g.code)
	}

	// step starts a step-up sign-in from the browser (cookie sent), and
	// answers with the IdP's response for nameID, built by change.
	step := func(cookie, nameID string, hdr map[string]string, change func(*etree.Element)) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", se.url+wantURL+"&return=%2Fposture", nil)
		if cookie != "" {
			req.Header.Set("Cookie", "__Host-sid="+cookie)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		start, err := se.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = start.Body.Close()
		id, xml := authnRequest(t, start.Header.Get("Location"))
		if !strings.Contains(xml, `ForceAuthn="true"`) {
			t.Fatalf("a step-up AuthnRequest without ForceAuthn: %s", xml)
		}
		r := se.response(id, nameID)
		if change != nil {
			r.BeforeSign = change
		}
		return se.post(t, se.build(t, r), nil)
	}
	instant := func(at time.Time) func(*etree.Element) {
		return func(a *etree.Element) {
			s := a.FindElement("//AuthnStatement")
			if at.IsZero() {
				s.RemoveAttr("AuthnInstant")
				return
			}
			s.CreateAttr("AuthnInstant", at.UTC().Format(time.RFC3339))
		}
	}
	stepFailures := func() string {
		return e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'authn.step_up_failed'")
	}

	// The IdP ignored ForceAuthn (the old authentication), or reported no
	// time: refused, audited; the old session is untouched.
	for name, at := range map[string]time.Time{"old authentication": time.Now().Add(-10 * time.Minute), "no AuthnInstant": {}} {
		before := stepFailures()
		resp := step(first, "user@example.test", nil, instant(at))
		_ = resp.Body.Close()
		if resp.StatusCode != 401 || sessionCookie(resp) != "" || stepFailures() == before {
			t.Errorf("%s: %d, %s step-up failures; denials: %s", name, resp.StatusCode, stepFailures(),
				e.adminQuery("SELECT coalesce(string_agg(payload->>'type' || ': ' || coalesce(payload->>'reason', ''), ' | ' ORDER BY id), '') FROM iam.event_outbox WHERE payload->>'type' LIKE 'authn.%'"))
		}
	}
	if g := se.do(t, "GET", "/api/v1/posture/settings", first, nil, nil); g.code != 200 {
		t.Fatalf("the old session after refused step-ups: %d", g.code)
	}

	// Re-authenticated: a new session with the fresh time; the old one is
	// revoked (step_up), and the restricted BU opens.
	resp = step(first, "user@example.test", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	second := sessionCookie(resp)
	if resp.StatusCode != 200 || second == "" || second == first || !strings.Contains(string(body), "url=/posture") {
		t.Fatalf("step-up sign-in: %d %s", resp.StatusCode, body)
	}
	se.ack(second)
	if got := se.sessionRow(t, first, "revoked_reason"); got != "step_up" {
		t.Fatalf("the replaced session: %q", got)
	}
	if g := se.do(t, "GET", settingsAtR, second, nil, nil); g.code != 200 {
		t.Fatalf("after the step-up: %d %s", g.code, g.raw)
	}
	if g := se.do(t, "GET", settingsAtR, first, nil, nil); g.code != 401 {
		t.Fatalf("the replaced session still works: %d", g.code)
	}

	live := func(cookie string) string { return se.sessionRow(t, cookie, "coalesce(revoked_reason, 'live')") }
	// Only the browser's own session is replaced: a client naming another
	// session (here the same user's, signed in elsewhere) without a cookie
	// is ignored, as the gateway drops the header.
	elsewhere := se.login(t, "user")
	handle := se.sessionRow(t, elsewhere, "handle")
	resp = step("", "user@example.test", map[string]string{authn.StepUpHeader: handle}, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || live(elsewhere) != "live" {
		t.Fatalf("a client-named session: %d %s", resp.StatusCode, live(elsewhere))
	}
	// And only the same user's: a step-up from user's browser in which the
	// IdP signs in someone else leaves user's session alone.
	resp = step(second, "other@example.test", nil, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || sessionCookie(resp) == "" || live(second) != "live" {
		t.Fatalf("a step-up as another user: %d %s", resp.StatusCode, live(second))
	}
}

// OIDC: the step-up asks for prompt=login and max_age; an ID token whose
// auth_time is older than the request, or absent, is refused.
func TestStepUpEndToEndOIDC(t *testing.T) {
	oe := oidcFixture(t)
	r := stepUpPosture(t, oe.gwEnv)
	resp, _ := oe.signIn(t, "user@example.test", "/", nil)
	_ = resp.Body.Close()
	cookie := sessionCookie(resp)
	oe.ack(cookie)
	oe.e.mustOwner("UPDATE iam.session SET auth_time = auth_time - interval '20 minutes'")
	g := oe.do(t, "GET", "/api/v1/posture/settings?bu="+r, cookie, nil, nil)
	loginURL, _ := g.body["login_url"].(string)
	if g.code != 401 || loginURL != "/api/v1/auth/oidc/"+oe.idpID+"/login?max_age=900&step_up=1" {
		t.Fatalf("stale OIDC sign-in: %d %s", g.code, g.raw)
	}
	step := func(extra map[string]any) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", oe.url+loginURL+"&return=%2F", nil)
		req.Header.Set("Cookie", "__Host-sid="+cookie)
		start, err := oe.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = start.Body.Close()
		loc := start.Header.Get("Location")
		if !strings.Contains(loc, "prompt=login") || !strings.Contains(loc, "max_age=900") {
			t.Fatalf("step-up authorization URL %s", loc)
		}
		code, state, err := oe.p.Authorize(loc, "user@example.test", extra)
		if err != nil {
			t.Fatal(err)
		}
		cb, err := httpGet(oe.client, oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/callback?"+url.Values{"code": {code}, "state": {state}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		return cb
	}
	for name, extra := range map[string]map[string]any{
		"old auth_time": {"auth_time": time.Now().Add(-10 * time.Minute).Unix()},
		"no auth_time":  {"auth_time": nil},
	} {
		resp := step(extra)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 || sessionCookie(resp) != "" {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	resp = step(nil)
	_ = resp.Body.Close()
	fresh := sessionCookie(resp)
	if resp.StatusCode != 200 || fresh == "" {
		t.Fatalf("step-up: %d", resp.StatusCode)
	}
	oe.ack(fresh)
	if g := oe.do(t, "GET", "/api/v1/posture/settings?bu="+r, fresh, nil, nil); g.code != 200 {
		t.Fatalf("after the OIDC step-up: %d %s", g.code, g.raw)
	}
}

// Service accounts: their authentication time is the access token's issue
// time (they authenticate when they get one), carried in the internal token.
func TestStepUpServiceAccountAuthTime(t *testing.T) {
	se := saFixture(t)
	sa := se.createSA(t, "Feed", "A", "client_credentials", "bu.view")
	access := se.accessToken(t, sa, se.secret(t, sa))
	issued := se.e.adminQuery("SELECT floor(extract(epoch FROM issued_at))::bigint FROM iam.sa_access_token ORDER BY issued_at DESC LIMIT 1")
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusTeapot {
		t.Fatalf("proxied: %d", r.code)
	}
	up := <-se.upstream
	c, err := authz.VerifyJWT(se.keys, strings.TrimPrefix(up.Header.Get("Authorization"), "Bearer "), "posture", time.Now())
	want, _ := strconv.ParseInt(issued, 10, 64)
	if err != nil || c.AuthTime == 0 || c.AuthTime != want {
		t.Fatalf("service account auth_time %d, token issued %s (%v)", c.AuthTime, issued, err)
	}
}

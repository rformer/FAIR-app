package tests

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// F-001 T-19 (AC-34; design §5.1 step 6): a new session must acknowledge
// the system-use banner before it reaches anything but /me, the
// acknowledgment and logout; on by default (banner.enabled), required when
// the setting cannot be read; the text is versioned, managed through the
// iam API with banner.manage, and audited.

func TestBannerGatesTheSession(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	cookie := ge.loginUnacknowledged(t, "user")

	me := ge.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	banner, _ := me.body["banner"].(map[string]any)
	if me.code != 200 || banner["required"] != true || banner["version"] != float64(1) ||
		!strings.Contains(banner["text"].(string), "authorized use only") {
		t.Fatalf("/me before acknowledgment: %d %s", me.code, me.raw)
	}
	// Nothing else: the service is never reached.
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/posture/settings"}, {"GET", "/api/v1/me/sessions"}, {"GET", "/api/v1/sessions"},
		{"DELETE", "/api/v1/me/sessions"}, {"POST", "/api/v1/posture/exports"},
	} {
		r := ge.do(t, c.method, c.path, cookie, nil, ge.csrf(t, cookie))
		if r.code != http.StatusForbidden || r.body["error"] != "banner_required" {
			t.Errorf("%s %s before acknowledgment: %d %s", c.method, c.path, r.code, r.raw)
		}
	}
	select {
	case r := <-ge.upstream:
		t.Fatalf("the service was reached before acknowledgment: %s", r.URL)
	default:
	}

	// The acknowledgment: same-site with the CSRF token, the version shown.
	if r := ge.do(t, "POST", "/api/v1/auth/banner/ack", cookie, map[string]any{"version": 1}, nil); r.code != http.StatusForbidden || r.body["error"] != "csrf" {
		t.Fatalf("acknowledgment without CSRF token: %d %s", r.code, r.raw)
	}
	hdr := ge.csrf(t, cookie)
	for body, want := range map[string]int{`{}`: 400, `{"version": 0}`: 400, `{"version": 2}`: 409, `{"version": 1, "x": 1}`: 400} {
		r := ge.raw(t, "POST", "/api/v1/auth/banner/ack", cookie, []byte(body), hdr)
		if r.code != want {
			t.Errorf("acknowledging %s: %d, want %d (%s)", body, r.code, want, r.raw)
		}
	}
	if r := ge.do(t, "POST", "/api/v1/auth/banner/ack", cookie, map[string]any{"version": 1}, hdr); r.code != http.StatusNoContent {
		t.Fatalf("acknowledgment: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "GET", "/api/v1/posture/settings", cookie, nil, nil); r.code != http.StatusTeapot {
		t.Fatalf("after acknowledgment: %d %s", r.code, r.raw)
	}
	<-ge.upstream
	me = ge.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	if b := me.body["banner"].(map[string]any); b["required"] != false || b["acknowledged_at"] == nil || b["text"] != nil {
		t.Fatalf("/me after acknowledgment: %s", me.raw)
	}
	if got := ge.sessionRow(t, cookie, "banner_version"); got != "1" {
		t.Fatalf("acknowledged version %q", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'session.banner_acknowledged' AND payload->>'reason' = 'banner version 1'"); got != "1" {
		t.Fatalf("%s acknowledgments audited", got)
	}

	// Every new session acknowledges again; it may sign out without doing so.
	second := ge.loginUnacknowledged(t, "user")
	if r := ge.do(t, "GET", "/api/v1/posture/settings", second, nil, nil); r.code != http.StatusForbidden {
		t.Fatalf("a new session inherits the acknowledgment: %d", r.code)
	}
	if r := ge.do(t, "POST", "/api/v1/auth/logout", second, nil, ge.csrf(t, second)); r.code != http.StatusNoContent {
		t.Fatalf("logout before acknowledgment: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "POST", "/api/v1/auth/banner/ack", second, map[string]any{"version": 1}, hdr); r.code != http.StatusUnauthorized {
		t.Fatalf("acknowledging a closed session: %d %s", r.code, r.raw)
	}

	// banner.enabled off: no gate; unreadable: the gate stays (fail closed).
	third := ge.loginUnacknowledged(t, "user")
	ge.g.BannerEnabled = func() (bool, error) { return false, nil }
	if r := ge.do(t, "GET", "/api/v1/posture/settings", third, nil, nil); r.code != http.StatusTeapot {
		t.Fatalf("banner disabled: %d %s", r.code, r.raw)
	}
	<-ge.upstream
	if b := ge.do(t, "GET", "/api/v1/me", third, nil, nil).body["banner"].(map[string]any); b["required"] != false {
		t.Fatalf("banner disabled, /me: %v", b)
	}
	ge.g.BannerEnabled = func() (bool, error) { return false, errors.New("stale settings") }
	if r := ge.do(t, "GET", "/api/v1/posture/settings", third, nil, nil); r.code != http.StatusForbidden {
		t.Fatalf("banner setting unreadable: %d %s", r.code, r.raw)
	}
	// Sessions cannot be acknowledged by any application role directly.
	e.mustFail("app_rw", "SELECT iam.session_banner_ack('\\x00', 1)", "permission denied")
	e.mustFail("app_gateway", "UPDATE iam.banner SET text = 'x'", "permission denied")
}

func TestBannerTextAPI(t *testing.T) {
	ie := idpFixture(t) // the gateway with the iam API; admin is Platform Admin (banner.manage)
	e := ie.e
	if r := ie.do(t, "GET", "/api/v1/banner", ie.admin, nil, nil); r.code != 200 || r.body["version"] != float64(1) {
		t.Fatalf("read: %d %s", r.code, r.raw)
	}
	text := "Authorized users only. Activity is logged.\n\nContact security@example.test."
	r := ie.do(t, "PUT", "/api/v1/banner", ie.admin, map[string]any{"text": text, "reason": "legal review 7"}, ie.hdr())
	if r.code != 200 || r.body["version"] != float64(2) {
		t.Fatalf("change: %d %s", r.code, r.raw)
	}
	if r := ie.do(t, "PUT", "/api/v1/banner", ie.admin, map[string]any{"text": "   ", "reason": "x"}, ie.hdr()); r.code != http.StatusBadRequest {
		t.Fatalf("blank text: %d %s", r.code, r.raw)
	}
	user := ie.login(t, "user") // Executive Viewer: may read, not change
	if r := ie.do(t, "GET", "/api/v1/banner", user, nil, nil); r.code != 200 || r.body["text"] != text {
		t.Fatalf("read as user: %d %s", r.code, r.raw)
	}
	h := ie.csrf(t, user)
	h["Idempotency-Key"] = "banner-user-change-1"
	if r := ie.do(t, "PUT", "/api/v1/banner", user, map[string]any{"text": "mine", "reason": "x"}, h); r.code != http.StatusForbidden {
		t.Fatalf("change without banner.manage: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery(`SELECT payload->>'severity' || ':' || (payload->>'reason') || ':' || (payload->'attributes'->>'version')
		FROM iam.event_outbox WHERE payload->>'type' = 'banner.changed'`); got != "high:legal review 7:2" {
		t.Fatalf("banner change audit %q", got)
	}
	// A new session is shown the new version; acknowledging the old one is refused.
	fresh := ie.loginUnacknowledged(t, "user")
	b := ie.do(t, "GET", "/api/v1/me", fresh, nil, nil).body["banner"].(map[string]any)
	if b["version"] != float64(2) || b["text"] != text {
		t.Fatalf("new session banner: %v", b)
	}
	fh := ie.csrf(t, fresh)
	if r := ie.do(t, "POST", "/api/v1/auth/banner/ack", fresh, map[string]any{"version": 1}, fh); r.code != http.StatusConflict {
		t.Fatalf("acknowledging the old version: %d %s", r.code, r.raw)
	}
	if r := ie.do(t, "POST", "/api/v1/auth/banner/ack", fresh, map[string]any{"version": 2}, fh); r.code != http.StatusNoContent {
		t.Fatalf("acknowledging the new version: %d %s", r.code, r.raw)
	}
}

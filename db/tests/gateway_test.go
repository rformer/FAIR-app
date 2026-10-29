package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-13 (AC-31, AC-33, AC-35): gateway sessions against the real
// database and session functions.

func (e *env) gatewayPool() *pgxpool.Pool {
	e.t.Helper()
	cc, err := dbconn.Config("development", "app_gateway", e.secrets["app_gateway"], "fair-test")
	if err != nil {
		e.t.Fatal(err)
	}
	cc.Database = e.db
	pc, _ := pgxpool.ParseConfig("")
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(pool.Close)
	return pool
}

type gwEnv struct {
	e        *env
	g        *gateway.Gateway
	url      string
	keys     *authz.LocalKeys
	mu       sync.Mutex
	idle     time.Duration
	absolute time.Duration
	upstream chan *http.Request // requests the posture stand-in received
	handler  atomic.Value       // the gateway's handler (rebuilt by resetHandler)
}

// resetHandler rebuilds the gateway's handler after its configuration changed.
func (ge *gwEnv) resetHandler(t *testing.T) {
	t.Helper()
	ge.handler.Store(ge.g.Handler())
}

func gatewayFixture(t *testing.T) *gwEnv {
	t.Helper()
	e := setup(t)
	postureAdmins(e) // admin and admin2: Platform Admin (session.view, session.revoke); ctxKey1 installed
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('user@example.test', 'User'), ('other@example.test', 'Other')")
	e.mustOwner(grant("admin", "user:user", "Executive Viewer", "ENTERPRISE"))
	e.drain()

	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "gw-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	ge := &gwEnv{e: e, keys: keys, idle: 15 * time.Minute, absolute: 12 * time.Hour, upstream: make(chan *http.Request, 10)}
	posture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ge.upstream <- r.Clone(context.Background())
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(posture.Close)
	up, _ := url.Parse(posture.URL)
	pepper := []byte("pepper-0123456789abcdef-0123456789abcdef")
	ge.g = &gateway.Gateway{
		Sessions: gateway.Sessions{DB: e.gatewayPool(), Pepper: pepper, Timeouts: func() (time.Duration, time.Duration, error) {
			ge.mu.Lock()
			defer ge.mu.Unlock()
			return ge.idle, ge.absolute, nil
		}},
		ContextKey: ctxKey1,
		JWT:        keys,
		Upstreams:  map[string]*url.URL{"posture": up},
	}
	ge.handler.Store(ge.g.Handler())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ge.handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	ge.url = srv.URL
	ge.g.Origin = srv.URL
	return ge
}

// login creates a session for user that has acknowledged the system-use
// banner (T-19) and returns the cookie value.
func (ge *gwEnv) login(t *testing.T, user string) string {
	t.Helper()
	tok := ge.loginUnacknowledged(t, user)
	ge.e.mustOwner("UPDATE iam.session SET banner_ack_at = now(), banner_version = 1 WHERE id_hmac = '\\x" + hmacSID(ge.g.Sessions.Pepper, tok) + "'")
	return tok
}

// loginUnacknowledged creates a session as a login does: the banner not
// yet acknowledged.
func (ge *gwEnv) loginUnacknowledged(t *testing.T, user string) string {
	t.Helper()
	id := ge.e.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + user + "@example.test'")
	_, tok, err := ge.g.Sessions.Create(context.Background(), gateway.Login{UserID: id, AuthMethod: "oidc",
		MFA: map[string]any{"amr": []string{"mfa"}}, IP: net.ParseIP("203.0.113.7"), UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type gwResp struct {
	code int
	body map[string]any
	raw  string
	hdr  http.Header
}

// do sends a request with the session cookie (if any), the CSRF token and
// the platform's Origin unless the header map overrides them.
func (ge *gwEnv) do(t *testing.T, method, path, cookie string, body any, hdr map[string]string) gwResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, ge.url+path, rd)
	if cookie != "" {
		req.Header.Set("Cookie", gateway.CookieName+"="+cookie)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return gwResp{resp.StatusCode, m, string(raw), resp.Header}
}

// csrf returns the headers a state-changing request from the UI carries.
func (ge *gwEnv) csrf(t *testing.T, cookie string) map[string]string {
	t.Helper()
	me := ge.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	tok, _ := me.body["csrf_token"].(string)
	if me.code != 200 || tok == "" {
		t.Fatalf("/me: %d %s", me.code, me.raw)
	}
	return map[string]string{gateway.CSRFHeader: tok, "Origin": ge.url}
}

func (ge *gwEnv) sessionRow(t *testing.T, cookie string, cols string) string {
	t.Helper()
	m := hmacSID(ge.g.Sessions.Pepper, cookie)
	return ge.e.adminQuery("SELECT " + cols + " FROM iam.session WHERE id_hmac = '\\x" + m + "'")
}

// AC-35 and storage: the cookie's attributes; only an HMAC is stored, with
// a pepper the database never sees; no application role reads sessions.
func TestGatewaySessionCookieAndStorage(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	tok := ge.login(t, "user")
	if len(tok) != 43 {
		t.Fatalf("token %q is not 256 bits in base64url", tok)
	}
	// The raw token appears nowhere in the database.
	if got := e.adminQuery("SELECT count(*) FROM iam.session s WHERE position('" + tok + "' IN s::text) > 0 OR encode(s.id_hmac, 'escape') LIKE '%" + tok + "%'"); got != "0" {
		t.Fatal("the raw session token is stored")
	}
	if got := ge.sessionRow(t, tok, "length(id_hmac)::text || ':' || auth_method || ':' || host(ip) || ':' || ip_prefix::text"); got != "32:oidc:203.0.113.7:203.0.113.0/24" {
		t.Fatalf("stored session %q", got)
	}
	// No application role can read or write the table directly.
	for _, role := range []string{"app_gateway", "app_rw", "app_posture", "app_engine"} {
		e.mustFail(role, "SELECT count(*) FROM iam.session", "permission denied")
	}
	e.mustFail("app_rw", "SELECT * FROM iam.session_lookup('\\x00', '1 minute', '1 hour')", "permission denied")

	// The cookie: __Host-, Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, no expiry.
	rec := httptest.NewRecorder()
	gateway.SetCookie(rec, tok)
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-sid" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("cookie %+v", c)
	}

	// /me identifies the session; a forged or malformed cookie is unauthenticated.
	me := ge.do(t, "GET", "/api/v1/me", tok, nil, nil)
	if me.code != 200 || me.body["auth_method"] != "oidc" || me.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("/me: %d %s", me.code, me.raw)
	}
	for _, bad := range []string{"", "x", strings.Repeat("A", 43), tok[:42] + "B"} {
		if r := ge.do(t, "GET", "/api/v1/me", bad, nil, nil); r.code != 401 {
			t.Errorf("cookie %q: %d", bad, r.code)
		}
	}
	// A disabled user cannot sign in.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'other@example.test'")
	id := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'other@example.test'")
	if _, _, err := ge.g.Sessions.Create(context.Background(), gateway.Login{UserID: id, AuthMethod: "oidc"}); !errors.Is(err, gateway.ErrUserInactive) {
		t.Fatalf("disabled user signed in: %v", err)
	}
}

// AC-31: idle and absolute timeouts as configured, a tightened timeout
// applying to existing sessions, last_seen throttled, disabled users out.
func TestGatewayTimeouts(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	ended := func(tok, why, reason string) {
		t.Helper()
		r := ge.do(t, "GET", "/api/v1/me", tok, nil, nil)
		if r.code != 401 || !strings.Contains(r.raw, why) || !strings.Contains(r.hdr.Get("Set-Cookie"), "Max-Age=0") {
			t.Fatalf("%s: %d %s %q", reason, r.code, r.raw, r.hdr.Get("Set-Cookie"))
		}
		if got := ge.sessionRow(t, tok, "revoked_reason"); got != reason {
			t.Fatalf("revoked_reason %q, want %s", got, reason)
		}
		if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = 'session.expired' AND payload->>'reason' = '" + reason + "'"); got != "1" {
			t.Fatalf("%s audit events: %s", reason, got)
		}
	}

	// Idle: 15 minutes without a request.
	a := ge.login(t, "user")
	e.admin(e.db, "UPDATE iam.session SET last_seen_at = now() - interval '15 minutes 1 second' WHERE id_hmac = '\\x"+hmacSID(ge.g.Sessions.Pepper, a)+"'")
	ended(a, "inactivity", "idle_timeout")

	// Absolute: 12 hours, however active.
	b := ge.login(t, "user")
	e.admin(e.db, "UPDATE iam.session SET created_at = now() - interval '13 hours', absolute_expiry_at = now() - interval '1 hour' WHERE id_hmac = '\\x"+hmacSID(ge.g.Sessions.Pepper, b)+"'")
	ended(b, "maximum duration", "absolute_timeout")

	// Tightened by a Platform Admin: an existing session obeys the new limit.
	c := ge.login(t, "user")
	e.admin(e.db, "UPDATE iam.session SET created_at = now() - interval '2 hours', last_seen_at = now() WHERE id_hmac = '\\x"+hmacSID(ge.g.Sessions.Pepper, c)+"'")
	if r := ge.do(t, "GET", "/api/v1/me", c, nil, nil); r.code != 200 {
		t.Fatalf("within 12 h: %d", r.code)
	}
	ge.mu.Lock()
	ge.absolute = time.Hour
	ge.mu.Unlock()
	if r := ge.do(t, "GET", "/api/v1/me", c, nil, nil); r.code != 401 {
		t.Fatalf("a tightened absolute timeout did not apply: %d", r.code)
	}
	ge.mu.Lock()
	ge.absolute = 12 * time.Hour
	ge.mu.Unlock()

	// last_seen is written at most once a minute.
	d := ge.login(t, "user")
	sid := hmacSID(ge.g.Sessions.Pepper, d)
	e.admin(e.db, "UPDATE iam.session SET last_seen_at = now() - interval '30 seconds' WHERE id_hmac = '\\x"+sid+"'")
	before := ge.sessionRow(t, d, "last_seen_at")
	ge.do(t, "GET", "/api/v1/me", d, nil, nil)
	if after := ge.sessionRow(t, d, "last_seen_at"); after != before {
		t.Fatal("last_seen written within the minute")
	}
	e.admin(e.db, "UPDATE iam.session SET last_seen_at = now() - interval '61 seconds' WHERE id_hmac = '\\x"+sid+"'")
	ge.do(t, "GET", "/api/v1/me", d, nil, nil)
	if got := ge.sessionRow(t, d, "now() - last_seen_at < interval '5 seconds'"); got != "t" {
		t.Fatal("last_seen not refreshed after a minute")
	}

	// A user disabled (e.g. by SCIM) loses every session at the next request.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'user@example.test'")
	ended(d, "disabled", "user_disabled")
}

// AC-33: users see and revoke their own sessions; admins with session.view
// and session.revoke see and revoke other users' (with a reason), audited.
func TestGatewayRevocation(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	mine, phone := ge.login(t, "user"), ge.login(t, "user")
	admin := ge.login(t, "admin")
	userID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")

	list := ge.do(t, "GET", "/api/v1/me/sessions", mine, nil, nil)
	items, _ := list.body["sessions"].([]any)
	if list.code != 200 || len(items) != 2 {
		t.Fatalf("own sessions: %d %s", list.code, list.raw)
	}
	var phoneHandle string
	current := 0
	for _, it := range items {
		m := it.(map[string]any)
		if m["current"] == true {
			current++
		} else {
			phoneHandle = m["session"].(string)
		}
		if _, leaked := m["id_hmac"]; leaked {
			t.Fatal("the session HMAC is exposed")
		}
	}
	if current != 1 || phoneHandle == "" {
		t.Fatalf("sessions %s", list.raw)
	}

	// A user may not see or revoke others' sessions.
	adminID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")
	if r := ge.do(t, "GET", "/api/v1/sessions?user="+adminID, mine, nil, nil); r.code != 403 {
		t.Fatalf("user listing another user's sessions: %d", r.code)
	}
	adminHandle := ge.do(t, "GET", "/api/v1/me", admin, nil, nil).body["session"].(string)
	if r := ge.do(t, "DELETE", "/api/v1/sessions/"+adminHandle, mine, nil, ge.csrf(t, mine)); r.code != 403 {
		t.Fatalf("user revoking an admin's session: %d %s", r.code, r.raw)
	}

	// Revoke one's own other session: it ends at once.
	if r := ge.do(t, "DELETE", "/api/v1/me/sessions/"+phoneHandle, mine, nil, ge.csrf(t, mine)); r.code != 204 {
		t.Fatalf("revoking own session: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "GET", "/api/v1/me", phone, nil, nil); r.code != 401 || !strings.Contains(r.raw, "revoked") {
		t.Fatalf("revoked session still works: %d %s", r.code, r.raw)
	}

	// An admin lists and revokes another user's session; a reason is required.
	l := ge.do(t, "GET", "/api/v1/sessions?user="+userID, admin, nil, nil)
	if items, _ := l.body["sessions"].([]any); l.code != 200 || len(items) != 1 {
		t.Fatalf("admin list: %d %s", l.code, l.raw)
	}
	mineHandle := ge.do(t, "GET", "/api/v1/me", mine, nil, nil).body["session"].(string)
	if r := ge.do(t, "DELETE", "/api/v1/sessions/"+mineHandle, admin, nil, ge.csrf(t, admin)); r.code != 422 {
		t.Fatalf("admin revoke without a reason: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "DELETE", "/api/v1/sessions/"+mineHandle, admin, map[string]string{"reason": "lost laptop, ticket SEC-42"}, ge.csrf(t, admin)); r.code != 204 {
		t.Fatalf("admin revoke: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "GET", "/api/v1/me", mine, nil, nil); r.code != 401 {
		t.Fatal("a session revoked by an admin still works")
	}
	ev := e.adminQuery(`SELECT payload->>'severity' || ':' || (payload->>'reason') || ':' || (payload->'attributes'->>'user_id')
		FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = 'session.revoked' ORDER BY id DESC LIMIT 1`)
	if ev != "high:lost laptop, ticket SEC-42:"+userID {
		t.Fatalf("admin revocation audit %q", ev)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.session.revoked'"); got != "2" {
		t.Fatalf("iam.session.revoked events: %s", got)
	}

	// Sign out everywhere else, then log out.
	a, b2, c := ge.login(t, "user"), ge.login(t, "user"), ge.login(t, "user")
	if r := ge.do(t, "DELETE", "/api/v1/me/sessions", a, nil, ge.csrf(t, a)); r.code != 200 || r.body["revoked"] != float64(2) {
		t.Fatalf("revoke others: %d %s", r.code, r.raw)
	}
	for _, s := range []string{b2, c} {
		if r := ge.do(t, "GET", "/api/v1/me", s, nil, nil); r.code != 401 {
			t.Fatal("another session survived")
		}
	}
	out := ge.do(t, "POST", "/api/v1/auth/logout", a, nil, ge.csrf(t, a))
	if out.code != 204 || !strings.Contains(out.hdr.Get("Set-Cookie"), "__Host-sid=;") || ge.sessionRow(t, a, "revoked_reason") != "logout" {
		t.Fatalf("logout: %d %q", out.code, out.hdr.Get("Set-Cookie"))
	}
	if r := ge.do(t, "GET", "/api/v1/me", a, nil, nil); r.code != 401 {
		t.Fatal("a logged-out session still works")
	}
}

// AC-35: CSRF. State-changing requests need the session's token in
// X-CSRF-Token and a same-origin request.
func TestGatewayCSRF(t *testing.T) {
	ge := gatewayFixture(t)
	tok, other := ge.login(t, "user"), ge.login(t, "admin")
	good := ge.csrf(t, tok)
	otherTok := ge.csrf(t, other)[gateway.CSRFHeader]
	cases := map[string]map[string]string{
		"no token":                       {"Origin": ge.url},
		"wrong token":                    {gateway.CSRFHeader: "AAAA", "Origin": ge.url},
		"another session's token":        {gateway.CSRFHeader: otherTok, "Origin": ge.url},
		"cross-site origin":              {gateway.CSRFHeader: good[gateway.CSRFHeader], "Origin": "https://evil.example"},
		"no origin, cross-site metadata": {gateway.CSRFHeader: good[gateway.CSRFHeader], "Sec-Fetch-Site": "cross-site"},
		"no origin, no metadata":         {gateway.CSRFHeader: good[gateway.CSRFHeader]},
	}
	for name, hdr := range cases {
		for _, rq := range [][2]string{{"POST", "/api/v1/auth/logout"}, {"DELETE", "/api/v1/me/sessions"}, {"POST", "/api/v1/posture/settings/x"}} {
			if r := ge.do(t, rq[0], rq[1], tok, nil, hdr); r.code != 403 || r.body["error"] != "csrf" {
				t.Errorf("%s: %s %s gave %d %s", name, rq[0], rq[1], r.code, r.raw)
			}
		}
	}
	select {
	case r := <-ge.upstream:
		t.Fatalf("a refused request reached the service: %s %s", r.Method, r.URL)
	default:
	}
	// Same-origin by Fetch Metadata alone is accepted; so is a GET without a token.
	if r := ge.do(t, "DELETE", "/api/v1/me/sessions", tok, nil, map[string]string{gateway.CSRFHeader: good[gateway.CSRFHeader], "Sec-Fetch-Site": "same-origin"}); r.code != 200 {
		t.Fatalf("same-origin request refused: %d %s", r.code, r.raw)
	}
	if r := ge.do(t, "GET", "/api/v1/me/sessions", tok, nil, nil); r.code != 200 {
		t.Fatalf("GET without a token: %d", r.code)
	}
	if r := ge.do(t, "POST", "/api/v1/auth/logout", tok, nil, good); r.code != 204 {
		t.Fatalf("a good request: %d %s", r.code, r.raw)
	}
}

// The proxy: services get the gateway's own short-lived credentials, never
// the browser's; unauthenticated requests never reach them.
func TestGatewayProxy(t *testing.T) {
	ge := gatewayFixture(t)
	tok := ge.login(t, "user")
	userID := ge.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")

	if r := ge.do(t, "GET", "/api/v1/posture/registry", "", nil, nil); r.code != 401 {
		t.Fatalf("unauthenticated: %d", r.code)
	}
	if r := ge.do(t, "GET", "/api/v1/unknown/x", tok, nil, nil); r.code != 404 {
		t.Fatalf("unknown service: %d", r.code)
	}
	hdr := ge.csrf(t, tok)
	hdr["Authorization"] = "Bearer forged"
	hdr[server.DBContextHeader] = "forged"
	hdr["Idempotency-Key"] = "k-123456789"
	r := ge.do(t, "POST", "/api/v1/posture/settings/session.idle_timeout?x=1", tok, map[string]any{"value": "10m0s"}, hdr)
	if r.code != http.StatusTeapot {
		t.Fatalf("proxied: %d %s", r.code, r.raw)
	}
	up := <-ge.upstream
	if up.URL.Path != "/api/v1/posture/settings/session.idle_timeout" || up.URL.RawQuery != "x=1" || up.Header.Get("Idempotency-Key") != "k-123456789" {
		t.Fatalf("forwarded %s?%s", up.URL.Path, up.URL.RawQuery)
	}
	for _, h := range []string{"Cookie", gateway.CSRFHeader} {
		if up.Header.Get(h) != "" {
			t.Errorf("%s reached the service", h)
		}
	}
	dbTok := up.Header.Get(server.DBContextHeader)
	if dbTok == "forged" || !strings.HasPrefix(dbTok, "v1.k1."+userID+".") {
		t.Fatalf("DB context %q", dbTok)
	}
	claims, err := authz.VerifyJWT(ge.keys, strings.TrimPrefix(up.Header.Get("Authorization"), "Bearer "), "posture", time.Now())
	if err != nil || claims.Subject != userID || claims.DBContext != authz.DBContextHash(dbTok) || claims.Expiry-claims.IssuedAt > int64(gateway.TokenTTL/time.Second) {
		t.Fatalf("JWT %+v %v", claims, err)
	}
	// The database accepts the DB context as that user.
	var who string
	if err := authz.WithDBContext(context.Background(), ge.g.Sessions.DB, dbTok, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT user_id::text FROM iam.session_list(NULL) LIMIT 1").Scan(&who)
	}); err != nil || who != userID {
		t.Fatalf("DB context: %q %v", who, err)
	}
}

// hmacSID is the stored id of a session token (gateway.Sessions).
func hmacSID(pepper []byte, token string) string {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte("sid\x00" + token))
	return hex.EncodeToString(m.Sum(nil))
}

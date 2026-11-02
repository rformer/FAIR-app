package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/breakglass"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-40: the STRIDE suite for F-001 (design §7), written as attacks.
// TestSTRIDECatalog maps every §7 threat to these tests and to earlier ones
// that attack the same mitigation.

// Spoofing: clients and services forge the headers the gateway owns. A
// valid login ticket sent by a client creates no session; client-supplied
// internal credentials never reach a service; a service cannot set the
// session cookie or hand the browser a login ticket.
func TestSTRIDEF001HeaderSpoofing(t *testing.T) {
	be := bgFixture(t)
	e := be.e
	// A rogue service behind the gateway answers with the session cookie and
	// a login ticket of its own.
	tok, err := authn.IssueTicket(be.g.Tickets, authn.Ticket{UserID: e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'"),
		AuthMethod: "oidc", MFA: map[string]any{"satisfied": true}, ReturnTo: "/"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rogue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", gateway.CookieName+"=planted-by-a-service; Path=/; Secure; HttpOnly")
		w.Header().Set(authn.TicketHeader, tok)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rogue.Close)
	u, _ := url.Parse(rogue.URL)
	be.g.Upstreams["rogue"] = u
	be.resetHandler(t)
	sessions := func() string { return e.adminQuery("SELECT count(*) FROM iam.session") }
	before := sessions()

	// A client presenting a valid ticket: on a login route, a service route
	// and the session API. No session results.
	for _, path := range []string{"/api/v1/auth/oidc/" + "00000000-0000-0000-0000-000000000000" + "/callback", "/api/v1/posture/x", "/api/v1/me"} {
		r := be.do(t, "GET", path, "", nil, map[string]string{authn.TicketHeader: tok})
		if bgCookie(r) != "" {
			t.Errorf("%s: a client's ticket made a session", path)
		}
	}
	if sessions() != before {
		t.Fatal("a client-supplied login ticket created a session")
	}
	// A signed-in user: forged internal credentials are replaced before the
	// service sees them.
	admin := be.login(t, "admin")
	forged, _ := authz.MintJWT(be.keys, authz.Claims{Subject: "00000000-0000-0000-0000-000000000001", ScopeVersion: 1, DBContext: "x"}, "posture", time.Minute, time.Now())
	r := be.do(t, "GET", "/api/v1/posture/x", admin, nil, map[string]string{"Authorization": "Bearer " + forged, server.DBContextHeader: "v1.forged"})
	up := <-be.upstream
	if r.code != http.StatusTeapot || strings.Contains(up.Header.Get("Authorization"), forged) || up.Header.Get(server.DBContextHeader) == "v1.forged" ||
		up.Header.Get(authn.TicketHeader) != "" {
		t.Fatalf("forged internal credentials reached the service: %v", up.Header)
	}
	// Without a session, a valid internal JWT is not a credential at the gateway.
	if r := be.do(t, "GET", "/api/v1/posture/x", "", nil, map[string]string{"Authorization": "Bearer " + forged}); r.code != http.StatusUnauthorized {
		t.Fatalf("an internal JWT from a client: %d", r.code)
	}
	// A service cannot plant the session cookie or a ticket in the browser.
	r = be.do(t, "GET", "/api/v1/rogue/anything", admin, nil, nil)
	if r.code != 200 || strings.Contains(strings.Join(r.hdr.Values("Set-Cookie"), ";"), "planted-by-a-service") || r.hdr.Get(authn.TicketHeader) != "" {
		t.Fatalf("a service's cookie or ticket reached the browser: %d %v", r.code, r.hdr)
	}
}

// Information disclosure: out-of-scope objects are indistinguishable from
// objects that do not exist (AC-25).
func TestSTRIDEF001Enumeration(t *testing.T) {
	be := bgFixture(t)
	e := be.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('scoped@example.test', 'Scoped')")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Scoped Admin') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['user.view', 'bu.view', 'access.view', 'role.view', 'service_account.manage', 'access_review.manage',
		                    'access_review.decide', 'entitlement.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:scoped", "Scoped Admin", "A"))
	e.mustOwner(grant("admin", "user:bob", "Executive Viewer", "B"))
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('BGroup')")
	e.mustOwner(grant("admin", "group:BGroup", "Executive Viewer", "B"))
	e.drain()
	admin := be.login(t, "admin")
	buB := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'B'")
	sa := be.do(t, "POST", "/api/v1/service-accounts", admin, map[string]any{"name": "B feed", "bu_id": buB, "scopes": []string{"bu.view"},
		"auth_method": "client_credentials", "reason": "x"}, be.hdrs(admin))
	mp := be.do(t, "POST", "/api/v1/group-mappings", admin, map[string]any{"group_id": e.adminQuery("SELECT id FROM iam.grp WHERE display_name = 'BGroup'"),
		"role_id": e.adminQuery("SELECT id FROM iam.role WHERE name = 'Executive Viewer'"), "bu_id": buB, "reason": "x"}, be.hdrs(admin))
	cp := be.do(t, "POST", "/api/v1/access-reviews", admin, map[string]any{"name": "B", "bu_id": buB, "due_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		"reason": "x"}, be.hdrs(admin))
	if sa.code != 201 || mp.code != 201 || cp.code != 201 {
		t.Fatalf("setup: %d %d %d", sa.code, mp.code, cp.code)
	}
	ids := map[string]string{
		"users":            e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'bob@example.test'"),
		"groups":           e.adminQuery("SELECT id FROM iam.grp WHERE display_name = 'BGroup'"),
		"bus":              buB,
		"service-accounts": sa.body["id"].(string),
		"group-mappings":   mp.body["id"].(string),
		"access-reviews":   cp.body["campaign"].(map[string]any)["id"].(string),
	}
	scoped := be.login(t, "scoped")
	missing := "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f"
	for res, id := range ids {
		for _, suffix := range []string{"", "/tokens", "/certificates"} {
			if suffix != "" && res != "service-accounts" {
				continue
			}
			hidden := be.do(t, "GET", "/api/v1/"+res+"/"+id+suffix, scoped, nil, nil)
			absent := be.do(t, "GET", "/api/v1/"+res+"/"+missing+suffix, scoped, nil, nil)
			if hidden.code != http.StatusNotFound || hidden.code != absent.code || hidden.raw != absent.raw {
				t.Errorf("%s%s: out of scope %d %q, missing %d %q", res, suffix, hidden.code, hidden.raw, absent.code, absent.raw)
			}
		}
	}
	// Mutations too: acting on an out-of-scope object answers as for a
	// missing one.
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/service-accounts/%s/disable"}, {"PATCH", "/api/v1/service-accounts/%s"}, {"POST", "/api/v1/access-reviews/%s/close"},
	} {
		res := strings.Split(c.path, "/")[3]
		body := map[string]any{"reason": "probe"}
		hidden := be.do(t, c.method, strings.Replace(c.path, "%s", ids[res], 1), scoped, body, be.hdrs(scoped))
		absent := be.do(t, c.method, strings.Replace(c.path, "%s", missing, 1), scoped, body, be.hdrs(scoped))
		if hidden.code != absent.code || hidden.raw != absent.raw {
			t.Errorf("%s %s: out of scope %d %q, missing %d %q", c.method, c.path, hidden.code, hidden.raw, absent.code, absent.raw)
		}
	}
	// The entitlement report says nothing of B either.
	if r := be.do(t, "GET", "/api/v1/entitlements/report", scoped, nil, nil); r.code != 200 || strings.Contains(r.raw, "bob@") {
		t.Fatalf("report: %d %s", r.code, r.raw)
	}
}

// Denial of service: the unauthenticated credential endpoints are
// rate-limited per client (the token endpoint, break-glass), as discovery
// and SCIM are (internal/authn, internal/scim).
func TestSTRIDEF001RateLimits(t *testing.T) {
	se := saFixture(t)
	se.g.ServiceAccounts.PerMinute = 3
	sa := se.createSA(t, "Limited", "A", "client_credentials", "bu.view")
	secret := se.secret(t, sa)
	cc := url.Values{"grant_type": {"client_credentials"}}
	var codes []int
	for range 5 {
		r := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: secret})
		codes = append(codes, r.code)
		if r.code == http.StatusTooManyRequests && r.hdr.Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	if codes[0] != 200 || codes[2] != 200 || codes[3] != http.StatusTooManyRequests || codes[4] != http.StatusTooManyRequests {
		t.Fatalf("token endpoint under a flood: %v", codes)
	}

	be := bgFixture(t)
	be.e.mustOwner(`SELECT iam.breakglass_install_enable('[{"email": "bg1@example.test", "name": "BG"}]', ARRAY['\x` + strings.Repeat("aa", 32) + `'::bytea], 'dr')`)
	bg, err := breakglass.New(be.e.appPool(), be.g.Tickets, bgOrigin, nil)
	if err != nil {
		t.Fatal(err)
	}
	bg.PerMinute = 2
	codes = nil
	for range 4 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "POST", breakglass.Prefix+"login/begin", strings.NewReader("{}"))
		req.Header.Set("X-Forwarded-For", "198.51.100.9")
		bg.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("break-glass under a flood: %v", codes)
	}
}

// Elevation of privilege: a service account's token reaches nothing beyond
// its scopes: no administration, not even of itself.
func TestSTRIDEF001ServiceAccountEscalation(t *testing.T) {
	se := saFixture(t)
	sa := se.createSA(t, "Reader", "A", "client_credentials", "bu.view", "role.view")
	access := se.accessToken(t, sa, se.secret(t, sa))
	if r := se.bearer(t, "GET", "/api/v1/roles", access, ""); r.code != 200 {
		t.Fatalf("within its scopes: %d %s", r.code, r.raw)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/roles"}, {"POST", "/api/v1/service-accounts"}, {"PATCH", "/api/v1/service-accounts/" + sa},
		{"POST", "/api/v1/service-accounts/" + sa + "/tokens"}, {"POST", "/api/v1/breakglass/enable"}, {"GET", "/api/v1/users"},
		{"POST", "/api/v1/access-reviews"}, {"GET", "/api/v1/entitlements/report"}, {"POST", "/api/v1/group-mappings"},
		{"POST", "/api/v1/sod-rules"}, {"PUT", "/api/v1/banner"},
	} {
		req, _ := http.NewRequestWithContext(context.Background(), c.method, se.url+c.path, strings.NewReader(`{"reason":"escalate"}`))
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(server.IdempotencyHeader, "esc-"+c.method+c.path)
		req.Header.Set("X-Forwarded-For", loginIP)
		r := send(t, http.DefaultClient, req)
		if r.code != http.StatusNotFound && r.code != http.StatusForbidden {
			t.Errorf("%s %s with a service account's token: %d %s", c.method, c.path, r.code, r.raw)
		}
	}
	// Nor the gateway's session APIs.
	if r := se.bearer(t, "GET", "/api/v1/sessions?user="+sa, access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("session API with a bearer token: %d", r.code)
	}
}

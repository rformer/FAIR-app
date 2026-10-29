package tests

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-20 (design §5.8): session network binding through the gateway.
// Sessions come from loginIP (203.0.113.7); the test client is the trusted
// ingress, so X-Forwarded-For names the client.

func from(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }

// nch is the network-changed claim of the internal JWT the service got.
func nch(t *testing.T, r *http.Request) bool {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("no JWT: %q", r.Header.Get("Authorization"))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c authz.Claims
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.NetworkChanged
}

func (ge *gwEnv) networkEvents(t *testing.T) string {
	t.Helper()
	return ge.e.adminQuery(`SELECT coalesce(string_agg((payload->>'reason') || ':' || (payload->'attributes'->>'action') || ':' ||
		(payload->'attributes'->>'new_ip'), '|' ORDER BY id), '') FROM iam.event_outbox WHERE payload->>'type' = 'session.network_changed'`)
}

func TestNetworkBindingModes(t *testing.T) {
	ge := gatewayFixture(t)
	e := ge.e
	posture := func(cookie string, hdr map[string]string) (gwResp, *http.Request) {
		t.Helper()
		r := ge.do(t, "GET", "/api/v1/posture/settings", cookie, nil, hdr)
		if r.code != http.StatusTeapot {
			return r, nil
		}
		return r, <-ge.upstream
	}

	// off (the Enterprise Baseline default): no audit, no interruption, but
	// the session is marked and its tokens say so.
	ge.g.NetworkBinding = func() (string, error) { return "off", nil }
	c := ge.login(t, "user")
	if _, up := posture(c, from("203.0.113.200")); up == nil || nch(t, up) {
		t.Fatal("same /24: refused or marked")
	}
	if got := ge.sessionRow(t, c, "network_changed_at IS NULL"); got != "t" {
		t.Fatal("same /24 marked the session")
	}
	_, up := posture(c, from("198.51.100.9"))
	if up == nil || !nch(t, up) {
		t.Fatal("off: another network refused, or not marked in the token")
	}
	if got := ge.networkEvents(t); got != "" {
		t.Fatalf("off audited a network change: %s", got)
	}
	// Back home, the mark stays (the session did leave its network).
	if _, up := posture(c, nil); up == nil || !nch(t, up) {
		t.Fatal("the mark was lost")
	}

	// flag: audited once, shown on the sessions view, the session goes on.
	ge.g.NetworkBinding = func() (string, error) { return "flag", nil }
	f := ge.login(t, "user")
	for _, ip := range []string{"198.51.100.9", "192.0.2.44"} {
		if _, up := posture(f, from(ip)); up == nil || !nch(t, up) {
			t.Fatalf("flag from %s: refused or unmarked", ip)
		}
	}
	if got := ge.networkEvents(t); got != "flag:flagged:198.51.100.9" {
		t.Fatalf("flag audit %q", got)
	}
	list := ge.do(t, "GET", "/api/v1/me/sessions", f, nil, nil)
	var flagged int
	for _, s := range list.body["sessions"].([]any) {
		if s.(map[string]any)["network_changed_at"] != nil {
			flagged++
		}
	}
	if list.code != 200 || flagged != 2 { // c (marked under off) and f
		t.Fatalf("sessions view: %d flagged: %s", flagged, list.raw)
	}

	// reauthenticate: the session is revoked, audited, and the answer says
	// where to sign in again (the session's IdP).
	ge.g.NetworkBinding = func() (string, error) { return "reauthenticate", nil }
	idp := e.adminQuery("INSERT INTO iam.idp (kind, name, metadata) VALUES ('oidc', 'Corp', '{}') RETURNING id")
	userID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")
	_, tok, err := ge.g.Sessions.Create(t.Context(), gateway.Login{UserID: userID, AuthMethod: "oidc", IDPID: idp,
		IP: netip.MustParseAddr(loginIP).AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	ge.e.mustOwner("UPDATE iam.session SET banner_ack_at = now() WHERE idp_id = '" + idp + "'")
	if _, up := posture(tok, from("203.0.113.99")); up == nil {
		t.Fatal("reauthenticate: same network refused")
	}
	r, up := posture(tok, from("198.51.100.9"))
	if up != nil || r.code != http.StatusUnauthorized || r.body["login_url"] != "/api/v1/auth/oidc/"+idp+"/login" ||
		!strings.Contains(r.body["detail"].(string), "network changed") || !strings.Contains(r.hdr.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("reauthenticate: %d %s", r.code, r.raw)
	}
	if got := ge.sessionRow(t, tok, "revoked_reason"); got != "network_change" {
		t.Fatalf("revoked_reason %q", got)
	}
	// The ended session keeps answering with the way back, from any network.
	if r := ge.do(t, "GET", "/api/v1/me", tok, nil, nil); r.code != 401 || r.body["login_url"] == nil {
		t.Fatalf("after revocation: %d %s", r.code, r.raw)
	}
	if got := ge.networkEvents(t); !strings.HasSuffix(got, "|reauthenticate:revoked:198.51.100.9") {
		t.Fatalf("reauthenticate audit %q", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'session.revoked' AND payload->>'reason' = 'network_change'"); got != "1" {
		t.Fatalf("%s revocations audited", got)
	}
	// A session flagged earlier is revoked once the mode is reauthenticate.
	if r, _ := posture(f, from("192.0.2.44")); r.code != http.StatusUnauthorized {
		t.Fatalf("flagged session under reauthenticate: %d", r.code)
	}
	// Unreadable settings: the strictest mode.
	ge.g.NetworkBinding = func() (string, error) { return "", errors.New("stale") }
	s := ge.login(t, "user")
	if r, _ := posture(s, from("198.51.100.9")); r.code != http.StatusUnauthorized {
		t.Fatalf("unreadable setting: %d", r.code)
	}
}

// The client address is only believed from the trusted ingress, and an
// ASN change inside the same prefix is a network change.
func TestNetworkBindingClientAddressAndASN(t *testing.T) {
	ge := gatewayFixture(t)
	ge.g.NetworkBinding = func() (string, error) { return "reauthenticate", nil }
	c := ge.login(t, "user")
	// A client prepending an address of its own choosing changes nothing:
	// the right-most untrusted address is the client.
	if r := ge.do(t, "GET", "/api/v1/me", c, nil, from("198.51.100.9, "+loginIP)); r.code != 200 {
		t.Fatalf("spoofed left-most address: %d %s", r.code, r.raw)
	}
	// From a hop that is not the trusted ingress the header is ignored: the
	// connection's address (127.0.0.1) is not the login's network.
	ge.g.Sessions.Network = gateway.Network{Header: "X-Forwarded-For", Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if r := ge.do(t, "GET", "/api/v1/me", c, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("header from an untrusted hop believed: %d %s", r.code, r.raw)
	}

	// ASN: 203.0.113.0/25 and /25 upper half belong to different systems.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ip2asn-v4.tsv"), []byte("203.0.113.0\t203.0.113.127\t64500\tZZ\tA\n"+
		"203.0.113.128\t203.0.113.255\t64501\tZZ\tB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := gateway.LoadASNDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	ge.g.Sessions.Network = gateway.Network{Header: "X-Forwarded-For", Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, ASN: db}
	a := ge.login(t, "user")
	if got := ge.sessionRow(t, a, "asn"); got != "64500" {
		t.Fatalf("recorded ASN %q", got)
	}
	if r := ge.do(t, "GET", "/api/v1/me", a, nil, from("203.0.113.100")); r.code != 200 {
		t.Fatalf("same prefix and ASN: %d", r.code)
	}
	r := ge.do(t, "GET", "/api/v1/me", a, nil, from("203.0.113.200"))
	if r.code != http.StatusUnauthorized {
		t.Fatalf("same /24, another ASN: %d %s", r.code, r.raw)
	}
	if got := ge.e.adminQuery("SELECT payload->'attributes'->>'asn' || '>' || (payload->'attributes'->>'new_asn') FROM iam.event_outbox WHERE payload->>'type' = 'session.network_changed'"); !strings.Contains(got, "64500>64501") {
		t.Fatalf("ASN audit %q", got)
	}
	// The services see the client's address, not the ingress's.
	ge.g.NetworkBinding = nil
	b := ge.login(t, "user")
	ge.do(t, "GET", "/api/v1/posture/settings", b, nil, from("192.0.2.1, "+loginIP))
	select {
	case up := <-ge.upstream:
		if got := up.Header.Get("X-Forwarded-For"); got != loginIP {
			t.Fatalf("X-Forwarded-For to the service %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not forwarded")
	}
}

// A BU whose own session.network_binding is reauthenticate refuses a
// session whose network changed, though the instance only flags it (the
// service's permission check, step-up).
func TestNetworkBindingStrictBU(t *testing.T) {
	ie := idpFixture(t)
	ie.g.NetworkBinding = func() (string, error) { return "flag", nil }
	pool := ie.e.appPool()
	ie.api.Authz = authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool),
		NetworkBinding: func(string) (string, error) { return "reauthenticate", nil }})
	if r := ie.do(t, "GET", "/api/v1/idps", ie.admin, nil, nil); r.code != 200 {
		t.Fatalf("home network: %d %s", r.code, r.raw)
	}
	r := ie.do(t, "GET", "/api/v1/idps", ie.admin, nil, from("198.51.100.9"))
	if r.code != http.StatusUnauthorized || r.body["error"] != "step_up_required" || r.hdr.Get("WWW-Authenticate") != "step_up max_age=0" {
		t.Fatalf("strict BU after a network change: %d %s %v", r.code, r.raw, r.hdr)
	}
	// The gateway still serves the session (flag), only the strict BU refuses.
	if r := ie.do(t, "GET", "/api/v1/me", ie.admin, nil, from("198.51.100.9")); r.code != 200 {
		t.Fatalf("the session itself: %d", r.code)
	}
}

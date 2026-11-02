package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn/breakglass"
	"github.com/rformer/fair-app/internal/authn/breakglass/webauthntest"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/iamapi"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-001 T-34 (AC-39 to AC-45, AC-47; design §5.7): break-glass, off by
// default, enabled at install or with a second approval, WebAuthn only, no
// risk data, loud, locked after repeated failures, and off at once.

const bgRPID, bgOrigin = "fair.example.test", "https://fair.example.test"

type bgEnv struct {
	*gwEnv
	hdrs     func(cookie string) map[string]string
	lastCode string
}

// newAuthenticatorFor enrolls a new key for the account with the code last
// issued for it.
func newAuthenticatorFor(t *testing.T, be *bgEnv, _ string) *webauthntest.Authenticator {
	t.Helper()
	a := newAuthenticator()
	if r := be.enroll(t, a, be.lastCode); r.code != http.StatusCreated {
		t.Fatalf("enroll with the new code: %d %s", r.code, r.raw)
	}
	return a
}

func bgFixture(t *testing.T) *bgEnv {
	t.Helper()
	ge := gatewayFixture(t)
	e := ge.e
	seedPosture(t, e)                             // breakglass.enabled false, lockout window 15 minutes (Enterprise Baseline)
	setInstance(e, "auth.lockout_threshold", "3") // AC-47's default (FedRAMP, CMMC); the Baseline allows 5
	if err := (settings.DBRegistrar{DB: e.appPool()}).Register(context.Background(), "F-001", "1", settings.F001Defs()); err != nil {
		t.Fatal(err) // as the iam service does at startup
	}
	if w := e.adminQuery("SELECT (iam.instance_setting('auth.lockout_window') #>> '{}')::interval"); w != "00:15:00" {
		t.Fatalf("lockout window read as %s", w)
	}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('bob@example.test', 'Bob')")
	pool := e.appPool()
	ticketKeys := newJWTKeys(t)
	api := &iamapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), DeploymentMode: config.ModeSelfHosted, Dev: true}
	bg, err := breakglass.New(pool, ticketKeys, bgOrigin, nil)
	if err != nil {
		t.Fatal(err)
	}
	bg.PerMinute = 1000
	mux := http.NewServeMux()
	h := api.Handler(ge.keys, nil)
	for _, p := range iamapi.Prefixes {
		mux.Handle(p, h)
		mux.Handle(p+"/", h)
	}
	mux.Handle(breakglass.Prefix, bg)
	iam := httptest.NewServer(mux)
	t.Cleanup(iam.Close)
	u, _ := url.Parse(iam.URL)
	ge.g.Upstreams["iam"] = u
	ge.g.Tickets = ticketKeys
	ge.resetHandler(t)
	be := &bgEnv{gwEnv: ge}
	n := 0
	be.hdrs = func(cookie string) map[string]string {
		h := ge.csrf(t, cookie)
		n++
		h["Idempotency-Key"] = fmt.Sprintf("bg-test-%d-%s", n, cookie[:8])
		return h
	}
	return be
}

func (be *bgEnv) ceremony(t *testing.T, path string, body map[string]any) (string, []byte) {
	t.Helper()
	r := be.do(t, "POST", "/api/v1/auth/breakglass/"+path, "", body, nil)
	id, _ := r.body["ceremony"].(string)
	opts, _ := json.Marshal(r.body["options"])
	if r.code != 200 || id == "" {
		t.Fatalf("%s: %d %s", path, r.code, r.raw)
	}
	return id, opts
}

func (be *bgEnv) enroll(t *testing.T, a *webauthntest.Authenticator, code string) gwResp {
	t.Helper()
	id, opts := be.ceremony(t, "enroll/begin", map[string]any{"code": code})
	cred, err := a.Register(opts)
	if err != nil {
		t.Fatal(err)
	}
	return be.do(t, "POST", "/api/v1/auth/breakglass/enroll/finish", "", map[string]any{"ceremony": id, "code": code, "credential": json.RawMessage(cred)}, nil)
}

func (be *bgEnv) bgLogin(t *testing.T, a *webauthntest.Authenticator) gwResp {
	t.Helper()
	id, opts := be.ceremony(t, "login/begin", map[string]any{})
	cred, err := a.Assert(opts)
	if err != nil {
		t.Fatal(err)
	}
	return be.do(t, "POST", "/api/v1/auth/breakglass/login/finish", "", map[string]any{"ceremony": id, "credential": json.RawMessage(cred), "return": "/posture"}, nil)
}

func bgCookie(r gwResp) string {
	for _, c := range (&http.Response{Header: r.hdr}).Cookies() {
		if c.Name == gateway.CookieName {
			return c.Value
		}
	}
	return ""
}

func newAuthenticator() *webauthntest.Authenticator { return webauthntest.New(bgRPID, bgOrigin) }

func TestBreakglass(t *testing.T) {
	be := bgFixture(t)
	e := be.e
	hashOf := func(code string) string { s := sha256.Sum256([]byte(code)); return hex.EncodeToString(s[:]) }

	// AC-39: off by default; no account exists; the routes do not.
	if e.adminQuery("SELECT iam.breakglass_enabled()") != "f" || e.adminQuery("SELECT count(*) FROM iam.app_user WHERE source = 'breakglass'") != "0" {
		t.Fatal("break-glass is not off by default")
	}
	for _, p := range []string{"login/begin", "enroll/begin", "login/finish"} {
		if r := be.do(t, "POST", "/api/v1/auth/breakglass/"+p, "", map[string]any{}, nil); r.code != http.StatusNotFound {
			t.Fatalf("%s while off: %d %s", p, r.code, r.raw)
		}
	}
	// It changes only through break-glass, never the settings workflow.
	e.ownerFails(`INSERT INTO posture.change (key, new_value, direction, requested_by, state)
		VALUES ('breakglass.enabled', 'true', 'loosen', `+uid("admin")+`, 'requested')`, "only by enabling or disabling break-glass")

	// AC-40: at install, before anyone signed in, with a reason; the accounts
	// hold Platform Admin at the root and must enroll (no password).
	code1, code2 := "fbg_install-one-0123456789", "fbg_install-two-0123456789"
	holders := `'[{"email": "bg1@example.test", "name": "Break Glass 1"}, {"email": "bg2@example.test", "name": "Break Glass 2"}]'`
	hashes := `ARRAY['\x` + hashOf(code1) + `'::bytea, '\x` + hashOf(code2) + `'::bytea]`
	e.ownerFails("SELECT iam.breakglass_install_enable("+holders+", "+hashes+", '')", "a reason is required")
	e.ownerFails(`SELECT iam.breakglass_install_enable('[{"email": "a@x.test", "name": "A"}, {"email": "b@x.test", "name": "B"}, {"email": "c@x.test", "name": "C"}]', `+hashes+", 'dr')", "one or two")
	e.ownerFails(`SELECT iam.breakglass_install_enable('[{"email": "admin@example.test", "name": "A"}]', `+hashes+", 'dr')", "address of its own")
	e.mustOwner("SELECT iam.breakglass_install_enable(" + holders + ", " + hashes + ", 'disaster recovery per runbook 7')")
	if e.adminQuery("SELECT iam.breakglass_enabled()") != "t" {
		t.Fatal("not enabled at install")
	}
	if got := e.adminQuery(`SELECT string_agg(u.email || ':' || u.status || ':' || r.name || ':' || b.code, ',' ORDER BY u.email)
		FROM iam.app_user u JOIN iam.assignment a ON a.principal_id = u.id JOIN iam.role r ON r.id = a.role_id JOIN iam.bu b ON b.id = a.bu_id
		WHERE u.source = 'breakglass'`); got != "bg1@example.test:active:Platform Admin:ENTERPRISE,bg2@example.test:active:Platform Admin:ENTERPRISE" {
		t.Fatalf("accounts: %s", got)
	}
	if got := e.adminQuery(`SELECT count(*) FROM iam.breakglass_enrollment WHERE code_hash IN ('\x` + hashOf(code1) + `', '\x` + hashOf(code2) + `')`); got != "2" {
		t.Fatal("enrollment codes not stored as their hashes")
	}
	if got := e.adminQuery(`SELECT payload->>'actor' || ':' || (payload->'attributes'->>'at_install') || ':' || (payload->>'reason') FROM iam.event_outbox
		WHERE payload->>'type' = 'breakglass.enabled'`); got != "system:installer:true:disaster recovery per runbook 7" {
		t.Fatalf("install audit: %s", got)
	}
	e.ownerFails("SELECT iam.breakglass_install_enable("+holders+", "+hashes+", 'again')", "in use")
	// Every profile fixes the setting at false: being on is an exception (the
	// installer's at install), so drift sees no unapproved deviation.
	installer := "00000000-0000-4000-8000-00000000f001"
	if got := e.adminQuery(`SELECT e.state || ':' || (e.owner_id = '` + installer + `') || ':' || (e.approved_by = '` + installer + `') || ':' || s.source
		FROM posture.exception e JOIN posture.setting_value s ON s.exception_id = e.id WHERE e.key = 'breakglass.enabled'`); got != "active:true:true:exception" {
		t.Fatalf("install-time exception: %s", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.drift_scan() WHERE detail->>'key' = 'breakglass.enabled'"); got != "0" {
		t.Fatalf("drift findings for break-glass: %s", got)
	}
	if e.adminQuery("SELECT status FROM iam.app_user WHERE id = '"+installer+"'") != "disabled" {
		t.Fatal("the installer stand-in can sign in")
	}
	e.drain()

	// Enrollment with the code: refused when the registration is wrong in
	// any way, then registered once.
	bg1 := newAuthenticator()
	if r := be.do(t, "POST", "/api/v1/auth/breakglass/enroll/begin", "", map[string]any{"code": "fbg_wrong"}, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %s", r.code, r.raw)
	}
	for name, fault := range map[string]func(*webauthntest.Authenticator){
		"no user verification":  func(a *webauthntest.Authenticator) { a.NoUV = true },
		"another origin":        func(a *webauthntest.Authenticator) { a.Origin = "https://evil.example" },
		"another relying party": func(a *webauthntest.Authenticator) { a.RPID = "evil.example" },
		"another challenge":     func(a *webauthntest.Authenticator) { a.Challenge = []byte("not-the-challenge-0123456789abcd") },
		"the login ceremony":    func(a *webauthntest.Authenticator) { a.WrongType = true },
	} {
		bad := newAuthenticator()
		fault(bad)
		if r := be.enroll(t, bad, code1); r.code != http.StatusBadRequest {
			t.Errorf("enrollment with %s: %d %s", name, r.code, r.raw)
		}
	}
	if r := be.enroll(t, bg1, code1); r.code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/auth/breakglass/enroll/begin", "", map[string]any{"code": code1}, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("a spent code: %d %s", r.code, r.raw)
	}

	// AC-42, AC-43: a WebAuthn login, audited high and announced.
	r := be.bgLogin(t, bg1)
	cookie := bgCookie(r)
	if r.code != 200 || cookie == "" {
		t.Fatalf("login: %d %s", r.code, r.raw)
	}
	bgID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'bg1@example.test'")
	if got := e.adminQuery("SELECT auth_method || ':' || (mfa_evidence->>'webauthn') FROM iam.session WHERE user_id = '" + bgID + "'"); got != "breakglass:true" {
		t.Fatalf("session: %s", got)
	}
	if got := e.adminQuery(`SELECT (SELECT payload->>'severity' FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = 'breakglass.login') || ':' ||
		(SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.breakglass.login') || ':' ||
		(SELECT count(*) FROM iam.notice_outbox WHERE kind = 'breakglass.login' AND channels = 'all') || ':' ||
		(SELECT count(*) FROM posture.secops_outbox)`); got != "high:1:1:0" {
		t.Fatalf("login announced as %s (audit severity, NATS, notices, SecOps outside SaaS)", got)
	}
	me := be.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	if me.code != 200 {
		t.Fatalf("break-glass session: %d %s", me.code, me.raw)
	}
	// In SaaS mode the vendor's SecOps webhook hears of it too.
	e.mustOwner("SELECT posture.set_deployment_mode('saas')")
	if r := be.bgLogin(t, bg1); r.code != 200 {
		t.Fatalf("second login: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT event->>'type' || ':' || (event->>'email') FROM posture.secops_outbox"); got != "breakglass.login:bg1@example.test" {
		t.Fatalf("SecOps outbox: %q", got)
	}
	e.mustOwner("SELECT posture.set_deployment_mode('self-hosted')")

	// Assertions wrong in any way are refused; those naming the account count.
	for name, fault := range map[string]func(*webauthntest.Authenticator){
		"no user verification": func(a *webauthntest.Authenticator) { a.NoUV = true },
		"another origin":       func(a *webauthntest.Authenticator) { a.Origin = "https://evil.example" },
	} {
		cp := *bg1
		fault(&cp)
		if r := be.bgLogin(t, &cp); r.code != http.StatusUnauthorized {
			t.Errorf("login with %s: %d %s", name, r.code, r.raw)
		}
		bg1.Count = cp.Count
	}
	if got := e.adminQuery("SELECT count(*) || ':' || (SELECT status FROM iam.app_user WHERE id = '" + bgID + "') FROM iam.login_failure WHERE user_id = '" + bgID + "'"); got != "2:active" {
		t.Fatalf("failures: %s", got)
	}
	// AC-47: the third failure within 15 minutes locks the account.
	cp := *bg1
	cp.CorruptSig = true
	if r := be.bgLogin(t, &cp); r.code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d %s", r.code, r.raw)
	}
	bg1.Count = cp.Count
	if got := e.adminQuery("SELECT status || ':' || disabled_reason FROM iam.app_user WHERE id = '" + bgID + "'"); got != "locked:lockout" {
		t.Fatalf("after 3 failures: %s", got)
	}
	if r := be.do(t, "GET", "/api/v1/me", cookie, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("session of a locked account: %d %s", r.code, r.raw)
	}
	if r := be.bgLogin(t, bg1); r.code != http.StatusUnauthorized {
		t.Fatalf("locked account signs in: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'user.locked' AND payload->>'severity' = 'high'"); got != "1" {
		t.Fatalf("lockout audit: %s", got)
	}
	// Unlocking (user administration) starts afresh.
	admin := be.login(t, "admin")
	if r := be.do(t, "POST", "/api/v1/users/"+bgID+"/unlock", admin, map[string]any{"reason": "verified the holder"}, be.hdrs(admin)); r.code != 200 {
		t.Fatalf("unlock: %d %s", r.code, r.raw)
	}
	if r := be.bgLogin(t, bg1); r.code != 200 {
		t.Fatalf("after unlock: %d %s", r.code, r.raw)
	}
	// A counter that does not advance (a cloned key) is refused.
	clone := *bg1
	clone.FixedCount = true
	if r := be.bgLogin(t, &clone); r.code != http.StatusUnauthorized {
		t.Fatalf("cloned counter: %d %s", r.code, r.raw)
	}
	// A key that is not the account's, and a replayed ceremony.
	stranger := newAuthenticator()
	stranger.UserHandle = bg1.UserHandle
	if r := be.bgLogin(t, stranger); r.code != http.StatusUnauthorized {
		t.Fatalf("an unregistered key: %d %s", r.code, r.raw)
	}
	id, opts := be.ceremony(t, "login/begin", map[string]any{})
	cred, _ := bg1.Assert(opts)
	body := map[string]any{"ceremony": id, "credential": json.RawMessage(cred)}
	if r := be.do(t, "POST", "/api/v1/auth/breakglass/login/finish", "", body, nil); r.code != 200 {
		t.Fatalf("login: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/auth/breakglass/login/finish", "", body, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("replayed ceremony: %d %s", r.code, r.raw)
	}

	// AC-44: no risk data, ever.
	e.ownerFails(grant("admin", "user:bg1", "Executive Viewer", "ENTERPRISE"), "risk-data permission")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Ops Admin') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['bu.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:bg1", "Ops Admin", "ENTERPRISE"))
	e.ownerFails(`INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		VALUES (`+roleID("Ops Admin")+`, 2, ARRAY['bu.view', 'register.view'], 'widen')`, "risk-data permission")
	grp := e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Everyone') RETURNING id")
	e.ownerFails("INSERT INTO iam.grp_member (grp_id, user_id) VALUES ('"+grp+"', '"+bgID+"')", "in no group")

	// AC-41: after install, enabling needs a reason and a second approval.
	bob := be.login(t, "bob")
	if r := be.do(t, "GET", "/api/v1/breakglass", bob, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without breakglass.manage: %d %s", r.code, r.raw)
	}
	st := be.do(t, "GET", "/api/v1/breakglass", admin, nil, nil)
	if st.code != 200 || st.body["enabled"] != true || len(st.body["accounts"].([]any)) != 2 {
		t.Fatalf("status: %d %s", st.code, st.raw)
	}

	// AC-45: disabling is immediate, needs no approval, ends the sessions.
	live := bgCookie(be.bgLogin(t, bg1))
	if r := be.do(t, "POST", "/api/v1/breakglass/disable", admin, map[string]any{"reason": "incident closed"}, be.hdrs(admin)); r.code != 200 ||
		r.body["accounts_disabled"] != float64(2) {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "GET", "/api/v1/me", live, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("break-glass session after disabling: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/auth/breakglass/login/begin", "", map[string]any{}, nil); r.code != http.StatusNotFound {
		t.Fatalf("login route after disabling: %d %s", r.code, r.raw)
	}
	if e.adminQuery("SELECT iam.breakglass_enabled()") != "f" {
		t.Fatal("the setting is still on")
	}

	newHolders := []map[string]string{{"email": "bg1@example.test", "name": "Break Glass 1"}}
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"no reason":         {map[string]any{"holders": newHolders, "reason": ""}, http.StatusBadRequest},
		"three holders":     {map[string]any{"holders": []map[string]string{{"email": "a@x.test", "name": "A"}, {"email": "b@x.test", "name": "B"}, {"email": "c@x.test", "name": "C"}}, "reason": "dr"}, http.StatusBadRequest},
		"an existing users": {map[string]any{"holders": []map[string]string{{"email": "bob@example.test", "name": "Bob"}}, "reason": "dr"}, http.StatusConflict},
	} {
		if r := be.do(t, "POST", "/api/v1/breakglass/enable", admin, c.body, be.hdrs(admin)); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	req := be.do(t, "POST", "/api/v1/breakglass/enable", admin, map[string]any{"holders": newHolders, "reason": "IdP migration weekend"}, be.hdrs(admin))
	approval, _ := req.body["approval_id"].(string)
	if req.code != http.StatusAccepted {
		t.Fatalf("request: %d %s", req.code, req.raw)
	}
	apply := func() gwResp {
		return be.do(t, "POST", "/api/v1/breakglass/apply", admin, map[string]any{"approval_id": approval}, be.hdrs(admin))
	}
	if r := apply(); r.code != http.StatusConflict {
		t.Fatalf("apply before approval: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "POST", "/api/v1/approvals/"+approval+"/decision", admin, map[string]any{"approve": true, "reason": "self"}, be.hdrs(admin)); r.code != http.StatusForbidden {
		t.Fatalf("self-approval: %d %s", r.code, r.raw)
	}
	admin2 := be.login(t, "admin2")
	if r := be.do(t, "POST", "/api/v1/approvals/"+approval+"/decision", admin2, map[string]any{"approve": true, "reason": "agreed"}, be.hdrs(admin2)); r.code != 200 {
		t.Fatalf("approve: %d %s", r.code, r.raw)
	}
	h := be.hdrs(admin)
	ap := be.do(t, "POST", "/api/v1/breakglass/apply", admin, map[string]any{"approval_id": approval}, h)
	accts, _ := ap.body["accounts"].([]any)
	if ap.code != 200 || len(accts) != 1 {
		t.Fatalf("apply: %d %s", ap.code, ap.raw)
	}
	newCode := accts[0].(map[string]any)["enrollment_code"].(string)
	if again := be.do(t, "POST", "/api/v1/breakglass/apply", admin, map[string]any{"approval_id": approval}, h); again.code != http.StatusConflict ||
		strings.Contains(again.raw, newCode) {
		t.Fatalf("replay: %d %s", again.code, again.raw)
	}
	if got := e.adminQuery(`SELECT (payload->'attributes'->>'approved_by' = ` + uid("admin2") + `::text) || ':' || (payload->>'severity')
		FROM iam.event_outbox WHERE payload->>'type' = 'breakglass.enabled' ORDER BY id DESC LIMIT 1`); got != "true:high" {
		t.Fatalf("enable audit: %s", got)
	}
	exc := e.adminQuery("SELECT id FROM posture.exception WHERE key = 'breakglass.enabled' AND state = 'active'")
	if got := e.adminQuery(`SELECT (owner_id = ` + uid("admin") + `) || ':' || (approved_by = ` + uid("admin2") + `) || ':' ||
		(SELECT string_agg(state, ',' ORDER BY created_at) FROM posture.exception WHERE key = 'breakglass.enabled')
		FROM posture.exception WHERE id = '` + exc + `'`); got != "true:true:superseded,active" {
		t.Fatalf("exception after re-enabling: %s", got)
	}
	if got := e.adminQuery("SELECT string_agg(email || ':' || status, ',' ORDER BY email) FROM iam.app_user WHERE source = 'breakglass'"); got != "bg1@example.test:active,bg2@example.test:disabled" {
		t.Fatalf("accounts after re-enabling: %s", got)
	}
	// Enabling again means enrolling again: the old key no longer works.
	if r := be.bgLogin(t, bg1); r.code != http.StatusUnauthorized {
		t.Fatalf("old key after re-enabling: %d %s", r.code, r.raw)
	}
	fresh := newAuthenticator()
	if r := be.enroll(t, fresh, newCode); r.code != http.StatusCreated {
		t.Fatalf("enroll again: %d %s", r.code, r.raw)
	}
	if r := be.bgLogin(t, fresh); r.code != 200 {
		t.Fatalf("login with the new key: %d %s", r.code, r.raw)
	}
	// A new code for a lost key removes the old one.
	nc := be.do(t, "POST", "/api/v1/breakglass/accounts/"+bgID+"/enrollment", admin, map[string]any{"reason": "key lost"}, be.hdrs(admin))
	if nc.code != http.StatusCreated {
		t.Fatalf("new code: %d %s", nc.code, nc.raw)
	}
	if r := be.bgLogin(t, fresh); r.code != http.StatusUnauthorized {
		t.Fatalf("the replaced key: %d %s", r.code, r.raw)
	}
	be.lastCode = nc.body["enrollment_code"].(string)

	// The exception expires: auto-revert turns break-glass off and the
	// accounts with it, sessions included.
	live = bgCookie(be.bgLogin(t, newAuthenticatorFor(t, be, bgID)))
	expire(e, exc)
	if out, err := posture.RevertDue(context.Background(), e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 || out[0].Err != nil {
		t.Fatalf("revert: %+v %v", out, err)
	}
	if got := e.adminQuery("SELECT iam.breakglass_enabled() || ':' || (SELECT string_agg(status::text, ',') FROM iam.app_user WHERE source = 'breakglass')"); got != "false:disabled,disabled" {
		t.Fatalf("after expiry: %s", got)
	}
	if r := be.do(t, "GET", "/api/v1/me", live, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("session after expiry: %d %s", r.code, r.raw)
	}

	// The tables are the functions' alone.
	for _, tbl := range []string{"iam.webauthn_credential", "iam.breakglass_enrollment", "iam.webauthn_ceremony", "iam.login_failure", "iam.notice_outbox"} {
		e.mustFail("app_rw", "SELECT * FROM "+tbl, "permission denied")
	}
	e.mustFail("app_rw", "SELECT iam.breakglass_install_enable('[]', '{}', 'x')", "permission denied")
	e.mustFail("app_rw", "SELECT posture.breakglass_set(true, NULL, NULL, NULL, NULL)", "permission denied")
}

// F-001 T-35 (AC-46): the IdP-outage recovery drill, the runbook
// (docs/operations/idp-outage-recovery.md) step by step: break-glass off,
// the installation in use, no IdP reachable; an operator with cluster-level
// access enables break-glass in an emergency, a holder enrolls and signs in
// without any IdP, administers, and turns break-glass off again.
func TestIdPOutageRecoveryDrill(t *testing.T) {
	be := bgFixture(t)
	e := be.e
	ctx := context.Background()
	step := 0
	logStep := func(format string, args ...any) {
		step++
		t.Logf("DRILL %d: "+format, append([]any{step}, args...)...)
	}
	admin := be.login(t, "admin") // the installation is in use
	logStep("installation in use (admin session), break-glass off: %s", e.adminQuery("SELECT iam.breakglass_enabled()"))

	// The operator's tool: `iam breakglass`, connected as app_migrator.
	cc, err := migrate.ConnConfig("development", e.secrets["app_migrator"])
	if err != nil {
		t.Fatal(err)
	}
	cc.Database = e.db
	run := func(args ...string) (string, error) {
		conn, err := pgx.ConnectConfig(ctx, cc)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		var out strings.Builder
		err = breakglass.Command(ctx, conn, args, &out)
		return out.String(), err
	}
	holder := []string{"-holder", "ops1@example.test=Ops One"}
	if _, err := run(append([]string{"enable", "-reason", "IdP down"}, holder...)...); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("the install path after install: %v", err)
	}
	logStep("install-time enable refused: the installation is in use")
	if _, err := run(append([]string{"enable", "-emergency", "-reason", "IdP down"}, holder...)...); err == nil || !strings.Contains(err.Error(), "-operator") {
		t.Fatalf("emergency without the operator: %v", err)
	}
	if _, err := run(append([]string{"enable", "-emergency", "-operator", "Jo Operator"}, holder...)...); err == nil {
		t.Fatal("emergency without a reason")
	}
	// The database insists too, whatever calls it.
	e.ownerFails(`SELECT * FROM iam.breakglass_emergency_enable('[{"email": "ops1@example.test", "name": "Ops One"}]', ARRAY['\x`+
		strings.Repeat("ab", 32)+`'::bytea], 'IdP down', ' ')`, "operator")
	logStep("emergency enable refused without -operator and without -reason")

	out, err := run(append([]string{"enable", "-emergency", "-operator", "Jo Operator", "-reason", "INC-1234: Entra ID outage"}, holder...)...)
	if err != nil {
		t.Fatalf("emergency enable: %v", err)
	}
	m := regexp.MustCompile(`shown once: (fbg_\S+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, `"type":"breakglass.emergency_enabled"`) || !strings.Contains(out, `"severity":"critical"`) || strings.Count(out, m[1]) != 1 {
		t.Fatalf("command output: %s", out)
	}
	logStep("emergency enable by operator Jo Operator: install-log line breakglass.emergency_enabled (critical); one enrollment code printed once")
	if got := e.adminQuery(`SELECT iam.breakglass_enabled() || ':' ||
		(SELECT (expires_at <= now() + interval '24 hours') || ':' || (approved_by = iam.installer_user()) FROM posture.exception WHERE key = 'breakglass.enabled' AND state = 'active') || ':' ||
		(SELECT payload->>'severity' || ':' || (payload->>'actor') FROM iam.event_outbox WHERE payload->>'type' = 'breakglass.emergency_enabled') || ':' ||
		(SELECT count(*) FROM iam.notice_outbox WHERE kind = 'breakglass.emergency_enabled')`); got != "true:true:true:critical:operator:Jo Operator:1" {
		t.Fatalf("after the emergency enable: %s", got)
	}
	logStep("on under a posture exception expiring within 24 hours; audited critical as operator:Jo Operator; every channel notified")
	if _, err := run(append([]string{"enable", "-emergency", "-operator", "Jo Operator", "-reason", "again"}, holder...)...); err == nil {
		t.Fatal("a second emergency enable while on")
	}
	logStep("a second emergency enable while on is refused")

	key := newAuthenticator()
	if r := be.enroll(t, key, m[1]); r.code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", r.code, r.raw)
	}
	e.drain()
	r := be.bgLogin(t, key)
	ops := bgCookie(r)
	if r.code != 200 || ops == "" {
		t.Fatalf("break-glass login: %d %s", r.code, r.raw)
	}
	logStep("holder ops1 enrolled a security key and signed in with WebAuthn, no IdP involved")
	if r := be.do(t, "POST", "/api/v1/auth/banner/ack", ops, map[string]any{"version": 1}, be.csrf(t, ops)); r.code != http.StatusNoContent {
		t.Fatalf("banner: %d %s", r.code, r.raw)
	}
	logStep("the holder acknowledged the system-use notification, like every session")
	if r := be.do(t, "GET", "/api/v1/idps", ops, nil, nil); r.code != 200 {
		t.Fatalf("IdP administration as break-glass: %d %s", r.code, r.raw)
	}
	logStep("as Platform Admin the holder reaches IdP administration (/api/v1/idps) to repair or switch the IdP")

	if r := be.do(t, "POST", "/api/v1/breakglass/disable", ops, map[string]any{"reason": "INC-1234 resolved"}, be.hdrs(ops)); r.code != 200 {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "GET", "/api/v1/me", ops, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("break-glass session after disabling: %d %s", r.code, r.raw)
	}
	if r := be.do(t, "GET", "/api/v1/me", admin, nil, nil); r.code != 200 {
		t.Fatalf("other sessions: %d %s", r.code, r.raw)
	}
	logStep("break-glass disabled with no approval: its session ended at once, the accounts are disabled, other sessions unaffected")
	if got := e.adminQuery("SELECT iam.breakglass_enabled() || ':' || (SELECT string_agg(status::text, ',') FROM iam.app_user WHERE source = 'breakglass')"); got != "false:disabled" {
		t.Fatalf("after the drill: %s", got)
	}
	logStep("final state: break-glass off, ops1 disabled")
}

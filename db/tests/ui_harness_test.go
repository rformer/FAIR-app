package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/postureapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-32: the UI end-to-end harness (scripts/ui-e2e.sh). It seeds a
// posture scenario through the real services, then serves the built web UI
// (web/dist) and the real Posture API behind the real gateway (F-001 T-13:
// sessions, CSRF, the system-use banner of T-19). /dev/as/{user} stands in
// for a federated login: it creates the user's session, unacknowledged, as
// a redeemed login ticket does, and sets the cookie. It runs until
// web/.harness-stop appears. Not a test of its own: set FAIR_UI_HARNESS=1.
func TestPostureUIHarness(t *testing.T) {
	if os.Getenv("FAIR_UI_HARNESS") != "1" {
		t.Skip("set FAIR_UI_HARNESS=1 (scripts/ui-e2e.sh) to run the UI harness")
	}
	ctx := context.Background()
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline) // admin, admin2, auditor, nobody
	e := ae.e
	seedPostureScenario(t, ae)

	pool := e.posturePool()
	api := &postureapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool), MaxAge: time.Second}), Audit: audit.NewMemory()}
	apiHandler := api.Handler(ae.keys, nil)
	dist := filepath.Join("..", "..", "web", "dist")

	posture := httptest.NewServer(apiHandler)
	defer posture.Close()
	up, _ := url.Parse(posture.URL)
	// The UI: built assets, and index.html for the app's routes.
	files := http.FileServer(http.Dir(dist))
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dist, "index.html"))
	})
	g := &gateway.Gateway{
		Sessions: gateway.Sessions{DB: e.gatewayPool(), Pepper: []byte("harness-pepper-0123456789abcdef-0123"),
			Timeouts: func() (time.Duration, time.Duration, error) { return 30 * time.Minute, 12 * time.Hour, nil }},
		ContextKey: ctxKey1,
		JWT:        ae.keys,
		Origin:     "http://localhost:8099",
		Upstreams:  map[string]*url.URL{"posture": up},
		UI:         ui,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /dev/ready", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /dev/as/{user}", func(w http.ResponseWriter, r *http.Request) {
		id := e.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + r.PathValue("user") + "@example.test'")
		_, tok, err := g.Sessions.Create(r.Context(), gateway.Login{UserID: id, AuthMethod: "oidc",
			MFA: map[string]any{"amr": []string{"mfa"}, "satisfied": true}, UserAgent: r.UserAgent()})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		gateway.SetCookie(w, tok) // Secure: Chromium accepts it from http://localhost
		http.Redirect(w, r, "/posture", http.StatusSeeOther)
	})
	mux.Handle("/", g.Handler())

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "0.0.0.0:8099")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(lis) }()
	defer func() { _ = srv.Close() }()
	t.Log("HARNESS READY on :8099")
	stop := filepath.Join("..", "..", "web", ".harness-stop")
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(stop); err == nil {
			_ = os.Remove(stop)
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("harness timed out without web/.harness-stop")
}

// seedPostureScenario builds what the Posture page shows, through the real
// services: an in-bounds loosening, an approved exception expiring in 10
// days, a reverted exception, BU overrides (one in a restricted BU), a
// pending switch to FedRAMP Moderate with conflicts, drift findings from a
// direct database edit, and undecided Kubernetes access.
func seedPostureScenario(t *testing.T, ae apiEnv) {
	t.Helper()
	ctx := context.Background()
	e := ae.e
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	set := func(key string, value any, explanation string) settings.Result {
		t.Helper()
		res, err := ae.set.Set(ctx, admin, settings.Request{Key: key, Value: value, Explanation: explanation})
		if err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		return res
	}
	approve := func(res settings.Result) posture.Exception {
		t.Helper()
		if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
			t.Fatal(err)
		}
		x, err := ae.set.ApplyApproved(ctx, res.ChangeID)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	set(settings.KeySessionIdleTimeout, 25*time.Minute, "call centre shifts")
	lockout := approve(set(settings.KeyAuthLockoutThreshold, 12, "legacy kiosk accounts"))
	e.timeTravel("UPDATE posture.exception SET expires_at = now() + interval '10 days' WHERE id = '" + lockout.ID + "'")
	token := approve(set(settings.KeyTokenMaxLifetime, 120*24*time.Hour, "integration partner migration"))
	expire(e, token.ID)
	if out, err := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 {
		t.Fatalf("seed revert: %+v %v", out, err)
	}

	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.drain()
	for _, code := range []string{"A", "R"} {
		bu := e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + code + "'")
		// A fresh context: adding BUs moved the admin's scope version.
		if _, err := ae.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeySessionNetworkBinding, BUID: bu, Value: "reauthenticate"}); err != nil {
			t.Fatal(err)
		}
	}
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	e.drain()

	sw := posture.Switches{DB: e.posturePool(), Audit: audit.NewMemory()}
	if _, err := sw.Request(ctx, e.principal("admin"), settings.ProfileFedRAMPModerate, "1.1.0", ""); err != nil {
		t.Fatalf("seed switch: %v", err)
	}

	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1.0"' WHERE key = 'tls.min_version' AND bu_id IS NULL`)
	if _, err := (posture.Drift{DB: e.posturePool(), Audit: audit.NewMemory()}).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.posturePool().QueryRow(ctx, "SELECT count(*) FROM posture.drift_findings()").Scan(&n); err != nil || n == 0 {
		t.Fatalf("seed drift: %d %v", n, err)
	}
	b, _ := json.Marshal(map[string]any{"exceptions": 2, "drift_findings": n})
	t.Logf("scenario seeded: %s", b)
	if _, err := os.Stat(filepath.Join("..", "..", "web", "dist", "index.html")); errors.Is(err, os.ErrNotExist) {
		t.Fatal(fmt.Errorf("web/dist is not built (npm run build in web/)"))
	}
}

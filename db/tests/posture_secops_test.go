package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-15 (AC-23): SaaS vendor SecOps notification on weakening.

// secopsReceiver is a TLS webhook that verifies signatures.
type secopsReceiver struct {
	mu       sync.Mutex
	secret   []byte
	fail     bool
	events   []map[string]any
	ids      []string
	badSigs  int
	requests int
}

func (r *secopsReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests++
	body, _ := io.ReadAll(req.Body)
	if !posture.VerifySecOps(r.secret, req.Header.Get("X-FAIR-Timestamp"), body, req.Header.Get("X-FAIR-Signature")) {
		r.badSigs++
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	if r.fail {
		http.Error(w, "SecOps intake down", http.StatusServiceUnavailable)
		return
	}
	var ev map[string]any
	_ = json.Unmarshal(body, &ev)
	r.events = append(r.events, ev)
	r.ids = append(r.ids, req.Header.Get("X-FAIR-Delivery"))
	w.WriteHeader(http.StatusAccepted)
}

func outboxCount(e *env) string {
	return e.adminQuery("SELECT count(*) FROM posture.secops_outbox")
}

// Self-hosted (or not yet recorded): weakening changes notify nobody.
func TestSecOpsSelfHostedSilent(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	e.mustOwner("SELECT posture.set_deployment_mode('self-hosted')")
	if res, err := ev.Change(ctx, e.principal("admin"), posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"30m0s"`)}); err != nil || res.Direction != "loosen" {
		t.Fatalf("loosen: %+v %v", res, err)
	}
	if n := outboxCount(e); n != "0" {
		t.Fatalf("self-hosted queued %s SecOps notifications", n)
	}
}

// Verification for T-15 (mode-gated): in SaaS mode every weakening change,
// and only a weakening change, is queued in the change's transaction and
// delivered, signed, to the SecOps webhook; failures are retried.
func TestSecOpsSaaSNotifiesWeakening(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	e.mustOwner("SELECT posture.set_deployment_mode('saas')")

	// Tightening: nothing to report.
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"10m0s"`)}); err != nil {
		t.Fatal(err)
	}
	if n := outboxCount(e); n != "0" {
		t.Fatalf("a tightening queued %s notifications", n)
	}
	// In-bounds weakening: reported, though no approval was needed.
	if _, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"30m0s"`)}); err != nil {
		t.Fatal(err)
	}
	// Out of bounds: reported when the approved exception applies, not when requested.
	res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable, Value: json.RawMessage(`"8760h0m0s"`), Explanation: "contractors"})
	if err != nil {
		t.Fatal(err)
	}
	if n := outboxCount(e); n != "1" {
		t.Fatalf("%s notifications after a pending request, want 1", n)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.ApplyApproved(ctx, res.ChangeID); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery(`SELECT string_agg(event->>'type' || ':' || (event->>'key') || ':' || (event->>'previous') || '->' || (event->>'value'), ',' ORDER BY id) FROM posture.secops_outbox`); got !=
		`setting.weakened:session.idle_timeout:10m0s->30m0s,setting.exception_created:auth.inactive_disable_after:2160h0m0s->8760h0m0s` {
		t.Fatalf("queued %s", got)
	}

	// Delivery: the intake is down first, then recovers.
	rcv := &secopsReceiver{secret: []byte(strings.Repeat("s", 32)), fail: true}
	srv := httptest.NewTLSServer(rcv)
	defer srv.Close()
	hook := &posture.SecOpsWebhook{URL: srv.URL, Secret: rcv.secret, Client: srv.Client(), Now: time.Now}
	pool := e.posturePool()
	if d, f, err := posture.DeliverSecOps(ctx, pool, hook, 50); err != nil || d != 0 || f != 2 {
		t.Fatalf("intake down: delivered %d, failed %d, %v", d, f, err)
	}
	if got := e.adminQuery("SELECT string_agg(attempts || ':' || (next_attempt_at > now()) || ':' || (last_error LIKE '%503%'), ',') FROM posture.secops_outbox"); got != "1:true:true,1:true:true" {
		t.Fatalf("after failure: %s", got)
	}
	// Backed off: nothing is due yet.
	if d, f, _ := posture.DeliverSecOps(ctx, pool, hook, 50); d+f != 0 {
		t.Fatalf("retried before the backoff (%d, %d)", d, f)
	}
	rcv.fail = false
	e.admin(e.db, "UPDATE posture.secops_outbox SET next_attempt_at = now()") // time passes
	if d, f, err := posture.DeliverSecOps(ctx, pool, hook, 50); err != nil || d != 2 || f != 0 {
		t.Fatalf("recovered: delivered %d, failed %d, %v", d, f, err)
	}
	if rcv.badSigs != 0 || len(rcv.events) != 2 || rcv.events[1]["approved_by"] != admin2.UserID || rcv.ids[0] == rcv.ids[1] {
		t.Fatalf("received %+v (ids %v, bad signatures %d)", rcv.events, rcv.ids, rcv.badSigs)
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.secops_outbox WHERE delivered_at IS NULL"); got != "0" {
		t.Fatalf("%s undelivered", got)
	}
	if d, f, _ := posture.DeliverSecOps(ctx, pool, hook, 50); d+f != 0 {
		t.Fatalf("delivered twice (%d, %d)", d, f)
	}
	// A wrong secret is caught by the receiver, and the notification stays queued.
	_, _ = ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuthLockoutThreshold, Value: json.RawMessage(`10`)})
	bad := &posture.SecOpsWebhook{URL: srv.URL, Secret: []byte(strings.Repeat("x", 32)), Client: srv.Client(), Now: time.Now}
	if d, f, _ := posture.DeliverSecOps(ctx, pool, bad, 50); d != 0 || f != 1 || rcv.badSigs != 1 {
		t.Fatalf("wrong secret: delivered %d, failed %d, bad signatures %d", d, f, rcv.badSigs)
	}
}

// The notification is part of the change: no change without it, and nobody
// but the installer can switch the mode or touch the queue.
func TestSecOpsGuarded(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	e.mustOwner("SELECT posture.set_deployment_mode('saas')")
	// The queue insert fails, so the weakening must not apply either.
	e.admin(e.db, "ALTER TABLE posture.secops_outbox ADD CONSTRAINT test_block CHECK (false) NOT VALID")
	if _, err := ev.Change(ctx, e.principal("admin"), posture.ChangeRequest{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"30m0s"`)}); err == nil {
		t.Fatal("a weakening applied without its SecOps notification")
	}
	if got := valueOf(e, settings.KeySessionIdleTimeout); got != `"15m0s":profile` {
		t.Fatalf("value %s", got)
	}
	e.admin(e.db, "ALTER TABLE posture.secops_outbox DROP CONSTRAINT test_block")

	e.wantState("app_posture", "PERFORM posture.set_deployment_mode('self-hosted')", "42501")
	e.wantState("app_rw", "PERFORM posture.secops_claim()", "42501")
	e.wantState("app_posture", "DELETE FROM posture.secops_outbox", "42501")
	if state := e.adminState("PERFORM posture.set_deployment_mode('cloud')"); state != "PF004" {
		t.Fatalf("invalid mode: %s", state)
	}
	if got := mustAs(e, "app_posture", "SELECT posture.deployment_mode()"); got != "saas" {
		t.Fatalf("mode %s", got)
	}
}

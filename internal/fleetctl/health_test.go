package fleetctl

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLive runs the live sources against a local TLS server standing in
// for an instance's API server, the operations Prometheus and the gateway.
func TestLive(t *testing.T) {
	var query, promAuth string
	ready := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/ocirepositories":
			if r.Header.Get("Authorization") != "Bearer kube-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprintf(w, `{"metadata":{},"items":[{"metadata":{"name":"fair-release","generation":2},
				"status":{"observedGeneration":2,"artifact":{"revision":"v0.2.0@%s","lastUpdateTime":"2026-11-27T08:00:00Z"},
				"conditions":[{"type":"Ready","status":"True","message":"stored artifact"}]}}]}`, d2)
		case "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations":
			items := []string{}
			for _, n := range append(append([]string{}, fleetSteps...), releaseSteps...) {
				st, gen := "True", 1
				if n == "fair-observability" {
					gen = 2 // a new generation not yet reconciled
				}
				items = append(items, fmt.Sprintf(`{"metadata":{"name":%q,"generation":%d},"spec":{"suspend":%v},
					"status":{"observedGeneration":1,"lastAppliedRevision":"v0.2.0@%s","conditions":[{"type":"Ready","status":%q,"message":"Applied"}]}}`,
					n, gen, n == "fair-secrets", d2, st))
			}
			_, _ = fmt.Fprintf(w, `{"metadata":{},"items":[%s]}`, strings.Join(items, ","))
		case "/api/v1/query":
			query, promAuth = r.URL.Query().Get("query"), r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
				"resultType": "vector", "result": []any{map[string]any{"metric": map[string]string{"alertname": "ApiAvailabilityBudgetBurn", "job": "gateway"}, "value": []any{1, "1"}}},
			}})
		case "/readyz":
			w.WriteHeader(ready)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, "creds", "canary-1")
	if err := os.MkdirAll(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "token"), []byte("kube-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "prom-token")
	if err := os.WriteFile(tok, []byte("prom-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := Live{Credentials: filepath.Join(dir, "creds"), Prometheus: srv.URL + "/", PromToken: tok, PromCA: ca, ReadyCA: ca, Timeout: 5 * time.Second}
	in := Instance{ID: "canary-1", Health: Health{Kubernetes: srv.URL, Readyz: []string{srv.URL + "/readyz"}}, Pin: v02}
	ctx := context.Background()

	fx, err := l.Flux(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !fx.Source.Ready || fx.Source.Revision != "v0.2.0@"+d2 || !fx.Since.Equal(time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("source %+v since %s", fx.Source, fx.Since)
	}
	if p := fx.Problem(v02); p != "fair-secrets not ready: suspended" {
		t.Errorf("problem %q", p)
	}
	for i := range fx.Steps {
		if fx.Steps[i].Name == "fair-secrets" {
			fx.Steps[i].Ready = true
		}
	}
	if p := fx.Problem(v02); p != "fair-observability not ready: generation not yet observed" {
		t.Errorf("problem %q", p)
	}

	alerts, err := l.Alerts(ctx, in, 72*time.Hour+time.Second)
	if err != nil || len(alerts) != 1 || alerts[0] != "ApiAvailabilityBudgetBurn (gateway)" {
		t.Errorf("alerts %v %v", alerts, err)
	}
	if query != `max_over_time(ALERTS{alertstate="firing",slo!="",fair_instance="canary-1"}[259201s])` || promAuth != "Bearer prom-token" {
		t.Errorf("query %q auth %q", query, promAuth)
	}
	if _, err := l.Alerts(ctx, in, 0); err != nil || query != `ALERTS{alertstate="firing",slo!="",fair_instance="canary-1"}` {
		t.Errorf("instant query %q %v", query, err)
	}
	if _, err := l.Alerts(ctx, Instance{ID: `x"} or vector(1) #`}, 0); err == nil {
		t.Error("an instance id that escapes the selector was queried")
	}

	if err := l.Ready(ctx, in); err != nil {
		t.Errorf("ready: %v", err)
	}
	ready = http.StatusServiceUnavailable
	if err := l.Ready(ctx, in); err == nil {
		t.Error("503 is ready")
	}

	// Without the CA, nothing is trusted.
	if _, err := (Live{Prometheus: srv.URL}).Alerts(ctx, in, 0); err == nil {
		t.Error("an untrusted Prometheus answered")
	}
	if _, err := (Live{Prometheus: "http://prometheus.example.test"}).Alerts(ctx, in, 0); err == nil {
		t.Error("plain HTTP Prometheus used")
	}
	if _, err := (Live{Credentials: filepath.Join(dir, "none")}).Flux(ctx, in); err == nil {
		t.Error("Flux read without credentials")
	}
}

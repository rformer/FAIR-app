package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/iam/server"
	"github.com/rformer/fair-app/internal/platform/health"
)

func newServer(t *testing.T, check health.CheckFunc) *httptest.Server {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	reg := health.New(time.Second, log)
	if check != nil {
		reg.Add("database", check)
	}
	srv := httptest.NewServer(server.Handler(server.Deps{Log: log, Health: reg, Version: "test", Profile: "fedramp-moderate"}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestHealthAndReadiness(t *testing.T) {
	srv := newServer(t, func(context.Context) error { return nil })
	if r := get(t, srv.URL+"/healthz", nil); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
	if r := get(t, srv.URL+"/readyz", nil); r.StatusCode != 200 {
		t.Fatalf("readyz %d", r.StatusCode)
	}
}

func TestReadinessFailsWithoutLeakingErrors(t *testing.T) {
	srv := newServer(t, func(context.Context) error { return errors.New("password authentication failed for user app_rw") })
	r := get(t, srv.URL+"/readyz", nil)
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d", r.StatusCode)
	}
	b, _ := io.ReadAll(r.Body)
	if strings.Contains(string(b), "password") || strings.Contains(string(b), "app_rw") {
		t.Fatalf("readiness leaked error detail: %s", b)
	}
	// Liveness must stay up during a dependency outage.
	if r := get(t, srv.URL+"/healthz", nil); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	srv := newServer(t, nil)
	r := get(t, srv.URL+"/version", map[string]string{"X-Request-ID": "abc-123"})
	for _, h := range []string{"X-Content-Type-Options", "Content-Security-Policy", "Cache-Control", "Strict-Transport-Security"} {
		if r.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if r.Header.Get("X-Request-ID") != "abc-123" {
		t.Fatalf("request id not propagated")
	}
	var v map[string]any
	_ = json.NewDecoder(r.Body).Decode(&v)
	if v["service"] != "iam" || v["profile"] != "fedramp-moderate" {
		t.Fatalf("version body %v", v)
	}
	r = get(t, srv.URL+"/version", map[string]string{"X-Request-ID": "bad id<script>"})
	if id := r.Header.Get("X-Request-ID"); id == "" || strings.ContainsAny(id, " <>") {
		t.Fatalf("unsafe request id echoed: %q", id)
	}
}

func TestUnknownRoutes404(t *testing.T) {
	srv := newServer(t, nil)
	if r := get(t, srv.URL+"/api/v1/users", nil); r.StatusCode != 404 {
		t.Fatalf("got %d", r.StatusCode)
	}
}

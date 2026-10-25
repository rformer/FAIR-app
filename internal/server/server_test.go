package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthAndHeaders(t *testing.T) {
	s := New(Options{Plaintext: true})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

func TestReadinessDoesNotLeakErrors(t *testing.T) {
	s := New(Options{Plaintext: true})
	s.AddReadinessCheck(ReadinessCheck{Name: "db", Check: func(context.Context) error {
		return errors.New("password authentication failed for user app_rw")
	}})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Fatal("readiness output leaked dependency error details")
	}
}

func TestTLSFloor(t *testing.T) {
	c := TLSConfig()
	if c.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS minimum below 1.2 violates the hard floor")
	}
}

func TestUnknownMethodRejected(t *testing.T) {
	s := New(Options{Plaintext: true})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", rec.Code)
	}
}

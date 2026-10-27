package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
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

// F-015 T-24: step-up is 401 with the challenge; every other refusal is 404.
func TestWriteAuthzError(t *testing.T) {
	for _, tc := range []struct {
		err       error
		code      int
		challenge string
	}{
		{&authz.StepUpError{MaxAge: 15 * time.Minute}, http.StatusUnauthorized, "step_up max_age=900"},
		{fmt.Errorf("wrapped: %w", &authz.StepUpError{MaxAge: time.Hour}), http.StatusUnauthorized, "step_up max_age=3600"},
		{authz.ErrStepUpRequired, http.StatusUnauthorized, "step_up"},
		{authz.ErrDenied, http.StatusNotFound, ""},
		{authz.ErrStaleScope, http.StatusNotFound, ""},
		{errors.New("settings stale: secret detail"), http.StatusNotFound, ""},
	} {
		rec := httptest.NewRecorder()
		WriteAuthzError(rec, tc.err)
		if rec.Code != tc.code || rec.Header().Get("WWW-Authenticate") != tc.challenge {
			t.Errorf("%v: %d %q, want %d %q", tc.err, rec.Code, rec.Header().Get("WWW-Authenticate"), tc.code, tc.challenge)
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%v: error leaked: %s", tc.err, rec.Body.String())
		}
	}
}

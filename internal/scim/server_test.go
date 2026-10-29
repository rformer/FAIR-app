package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Design §7: rate limits per token.
func TestRateLimitPerToken(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Server{PerMinute: 2, Now: func() time.Time { return now }}
	a, b := []byte("token-a"), []byte("token-b")
	for i := range 2 {
		if !s.allow(a) {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if s.allow(a) {
		t.Fatal("the third request in a minute was allowed")
	}
	if !s.allow(b) {
		t.Fatal("another token was limited")
	}
	now = now.Add(30 * time.Second)
	if !s.allow(a) || s.allow(a) {
		t.Fatal("refill is not one request per 30 s")
	}
}

// Without a bearer token nothing reaches the store.
func TestUnauthenticated(t *testing.T) {
	s := &Server{}
	for _, h := range []string{"", "Bearer ", "Basic abc", "bearer"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, Prefix+"/Users", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%q: %d", h, w.Code)
		}
	}
}

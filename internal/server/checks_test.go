package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// F-012 T-09 (AC-22): readiness covers key files.
func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "db-context.key")
	keys := filepath.Join(dir, "jwt")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "k1.pem"), []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"KEY": key, "DIR": keys}
	c := KeyFiles(func(k string) string { return env[k] }, "KEY", "DIR", "UNSET")
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("present keys: %v", err)
	}
	if err := os.Remove(filepath.Join(keys, "k1.pem")); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("an empty key directory is ready")
	}
	env["DIR"] = keys
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("a missing key file is ready")
	}
}

func TestEveryReusesOnlySuccess(t *testing.T) {
	calls, fail := 0, false
	c := Every(time.Hour, ReadinessCheck{Name: "remote", Check: func(context.Context) error {
		calls++
		if fail {
			return errors.New("down")
		}
		return nil
	}})
	ctx := context.Background()
	_ = c.Check(ctx)
	_ = c.Check(ctx)
	if calls != 1 {
		t.Fatalf("a success was not reused: %d calls", calls)
	}
	c2 := Every(time.Hour, ReadinessCheck{Name: "remote", Check: func(context.Context) error { calls++; return errors.New("down") }})
	calls = 0
	_ = c2.Check(ctx)
	_ = c2.Check(ctx)
	if calls != 2 {
		t.Fatalf("a failure was reused: %d calls", calls)
	}
	_ = fail
}

// A degraded dependency is reported but keeps the service ready; any other
// failing check makes it unready.
func TestDegradedReadiness(t *testing.T) {
	s := New(Options{})
	s.AddReadinessCheck(ReadinessCheck{Name: "engine", Degraded: true, Check: func(context.Context) error { return errors.New("down") }})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"engine":"degraded"`) {
		t.Fatalf("degraded: %d %s", rec.Code, rec.Body)
	}
	s.AddReadinessCheck(ReadinessCheck{Name: "keys", Check: func(context.Context) error { return errors.New("gone") }})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a missing key is ready: %d", rec.Code)
	}
}

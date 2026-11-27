package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// F-014 T-05 (D-OQ13): the installation-state gate, per state and method;
// health always answers; a state is kept for the TTL; a failed read with
// nothing recent is closed.
func TestInstallGate(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0", Plaintext: true})
	s.Mux().HandleFunc("/api/v1/x", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	call := func(method, path string) (int, string) {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, _ := call("POST", "/api/v1/x"); code != http.StatusNoContent {
		t.Fatalf("without a reader: %d", code)
	}

	state, reads := "open", 0
	var readErr error
	clock := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s.UseInstallState(func(context.Context) (string, error) { reads++; return state, readErr }, time.Second)
	s.gate.now = func() time.Time { return clock }
	tick := func() { clock = clock.Add(2 * time.Second) }

	for _, c := range []struct {
		state, method string
		code          int
		error         string
	}{
		{"open", "POST", 204, ""},
		{"installing", "POST", 204, ""},
		{"upgrading", "GET", 204, ""},
		{"upgrading", "HEAD", 204, ""},
		{"upgrading", "POST", 503, "upgrading"},
		{"upgrading", "DELETE", 503, "upgrading"},
		{"closed", "GET", 503, "installation_closed"},
		{"restoring", "GET", 503, "installation_closed"},
		{"restoring", "POST", 503, "installation_closed"},
		{"something-new", "GET", 503, "installation_closed"},
	} {
		state = c.state
		tick()
		code, body := call(c.method, "/api/v1/x")
		if code != c.code || (c.error != "" && !strings.Contains(body, `"error":"`+c.error+`"`)) {
			t.Errorf("%s %s: %d %s", c.state, c.method, code, body)
		}
		if code == 503 {
			if code, _ := call("GET", "/healthz"); code != 200 {
				t.Errorf("%s: /healthz %d", c.state, code)
			}
		}
	}

	// Kept for the TTL: a state change is seen only after it.
	state = "open"
	tick()
	call("GET", "/api/v1/x")
	n := reads
	state = "closed"
	if code, _ := call("GET", "/api/v1/x"); code != 204 || reads != n {
		t.Errorf("within the TTL: %d, %d reads", code, reads-n)
	}
	tick()
	if code, _ := call("GET", "/api/v1/x"); code != 503 {
		t.Errorf("after the TTL: %d", code)
	}

	// A failed read keeps a recent state, then fails closed.
	state, readErr = "open", nil
	tick()
	call("GET", "/api/v1/x")
	readErr = errors.New("database down")
	tick()
	if code, _ := call("GET", "/api/v1/x"); code != 204 {
		t.Errorf("failed read, recent state: %d", code)
	}
	clock = clock.Add(2 * time.Minute)
	if code, body := call("GET", "/api/v1/x"); code != 503 || !strings.Contains(body, "installation_closed") {
		t.Errorf("failed read, nothing recent: %d %s", code, body)
	}
}

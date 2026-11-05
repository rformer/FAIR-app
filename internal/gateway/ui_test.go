package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-002 T-14 (AC-37): the app's routes load the app; files are served as
// they are; a missing asset is a 404.
func TestStaticUI(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<!doctype html>app", "assets/app.js": "js", "favicon.svg": "svg"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := StaticUI(dir)
	for _, c := range []struct {
		path string
		code int
		body string
	}{
		{"/", 200, "app"},
		{"/posture", 200, "app"},
		{"/audit?target=setting:tls.min_version", 200, "app"},
		{"/audit/anything/deeper", 200, "app"},
		{"/assets/app.js", 200, "js"},
		{"/favicon.svg", 200, "svg"},
		{"/assets/missing.js", 404, ""},
		{"/assets", 200, "app"},     // a directory is not served as a listing
		{"/../index.html", 301, ""}, // cleaned to /index.html, which FileServer sends to /
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, c.path, nil))
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("%s: %d %q, want %d %q", c.path, rec.Code, rec.Body.String(), c.code, c.body)
		}
	}
}

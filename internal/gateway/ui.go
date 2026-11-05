package gateway

import (
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

// StaticUI serves the built web UI in dir (FAIR_UI_DIR): its files as they
// are, and index.html for any other path, so the app's own routes
// (/posture, /audit?target=..., F-002 T-14, AC-37) load the app. A missing
// file under /assets/ stays a 404: it is a stale or wrong asset, not a
// route.
func StaticUI(dir string) http.Handler {
	root := http.Dir(dir)
	files := http.FileServer(root)
	index := filepath.Join(dir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		if p != "/" {
			if f, err := root.Open(p); err == nil {
				st, err := f.Stat()
				_ = f.Close()
				if err == nil && !st.IsDir() {
					files.ServeHTTP(w, r)
					return
				}
			}
			if strings.HasPrefix(p, "/assets/") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	})
}

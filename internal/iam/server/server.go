// Package server wires iam's HTTP surface. Phase 0 serves health, readiness
// and version only; F-001 API routes are added from Phase 1 onward.
package server

import (
	"crypto/fips140"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/rformer/fair-app/internal/platform/health"
	"github.com/rformer/fair-app/internal/platform/otelx"
	"github.com/rformer/fair-app/pkg/audit"
)

// Deps are the server's collaborators.
type Deps struct {
	Log     *slog.Logger
	Health  *health.Registry
	Version string
	Profile string
}

// Handler returns the full HTTP handler with middleware applied.
func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.LivenessHandler())
	mux.Handle("GET /readyz", d.Health.ReadinessHandler())
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "iam", "version": d.Version, "profile": d.Profile, "fips140": fips140.Enabled(),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	})

	var h http.Handler = mux
	h = otelx.Middleware("iam", h)
	h = accessLog(d.Log, h)
	h = requestID(h)
	h = securityHeaders(h)
	h = recoverer(d.Log, h)
	return h
}

// New returns an http.Server with conservative timeouts.
func New(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

var reqIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// requestID propagates the gateway's X-Request-ID, or creates one. Values
// that are not plain tokens are replaced to keep logs injection-free.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !reqIDRe.MatchString(id) {
			id = audit.NewID()
		}
		w.Header().Set("X-Request-ID", id)
		r.Header.Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

type recorder struct {
	http.ResponseWriter
	code int
}

func (r *recorder) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }

func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		log.Info("http request", "method", r.Method, "route", r.Pattern, "status", rec.code,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", r.Header.Get("X-Request-ID"))
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic", "value", v, "request_id", r.Header.Get("X-Request-ID"))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

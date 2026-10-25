// Package server provides the hardened HTTP server shared by platform services:
// TLS 1.2+ (hard floor), conservative timeouts, security headers, liveness and
// readiness endpoints, and graceful shutdown.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// ReadinessCheck reports whether a dependency is ready. Name appears in /readyz output.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Options configures a Server.
type Options struct {
	Addr        string
	TLSCertFile string
	TLSKeyFile  string
	Plaintext   bool // development only; callers must have validated config
	Logger      *slog.Logger
}

// Server wraps http.Server with platform defaults.
type Server struct {
	opts   Options
	mux    *http.ServeMux
	srv    *http.Server
	mu     sync.RWMutex
	checks []ReadinessCheck
}

// New builds a Server. Register handlers on Mux() before calling Run.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{opts: opts, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)

	s.srv = &http.Server{
		Addr:              opts.Addr,
		Handler:           SecurityHeaders(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig:         TLSConfig(),
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
	}
	return s
}

// Mux returns the router for registering application handlers.
func (s *Server) Mux() *http.ServeMux { return s.mux }

// Handler returns the full handler chain (useful for tests).
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// AddReadinessCheck registers a dependency check for /readyz.
func (s *Server) AddReadinessCheck(c ReadinessCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, c)
}

// TLSConfig returns the platform TLS configuration. TLS 1.2 is the hard floor
// (F-015 R-08); TLS 1.3 is preferred. Cipher suites for TLS 1.2 are limited to
// AEAD ECDHE suites; in FIPS mode Go further restricts to approved algorithms.
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}
}

// Run serves until ctx is cancelled, then shuts down gracefully within timeout.
func (s *Server) Run(ctx context.Context, shutdownTimeout time.Duration) error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln, shutdownTimeout)
}

// Serve is like Run but uses an existing listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.opts.Plaintext {
			s.opts.Logger.Warn("serving WITHOUT TLS (development mode)", "addr", ln.Addr().String())
			err = s.srv.Serve(ln)
		} else {
			s.opts.Logger.Info("serving with TLS", "addr", ln.Addr().String())
			err = s.srv.ServeTLS(ln, s.opts.TLSCertFile, s.opts.TLSKeyFile)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.srv.Shutdown(sctx); err != nil {
			return err
		}
		return <-errCh
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	checks := append([]ReadinessCheck(nil), s.checks...)
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	status := http.StatusOK
	results := make(map[string]string, len(checks))
	for _, c := range checks {
		if err := c.Check(ctx); err != nil {
			status = http.StatusServiceUnavailable
			// Do not leak dependency error details to unauthenticated callers.
			results[c.Name] = "not ready"
			continue
		}
		results[c.Name] = "ok"
	}
	writeJSON(w, status, map[string]any{"status": http.StatusText(status), "checks": results})
}

// SecurityHeaders adds baseline response headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

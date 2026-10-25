// Package health serves liveness and readiness endpoints.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// CheckFunc returns nil when the dependency is usable.
type CheckFunc func(ctx context.Context) error

// Registry holds readiness checks.
type Registry struct {
	mu      sync.RWMutex
	checks  map[string]CheckFunc
	timeout time.Duration
	log     *slog.Logger
}

// New returns a registry; each check gets timeout to complete.
func New(timeout time.Duration, log *slog.Logger) *Registry {
	return &Registry{checks: map[string]CheckFunc{}, timeout: timeout, log: log}
}

// Add registers a readiness check.
func (r *Registry) Add(name string, fn CheckFunc) {
	r.mu.Lock()
	r.checks[name] = fn
	r.mu.Unlock()
}

// Result of one readiness run.
type Result struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// Run executes every check concurrently.
func (r *Registry) Run(ctx context.Context) Result {
	r.mu.RLock()
	names := make([]string, 0, len(r.checks))
	for n := range r.checks {
		names = append(names, n)
	}
	r.mu.RUnlock()
	sort.Strings(names)

	res := Result{Status: "ok", Checks: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			r.mu.RLock()
			fn := r.checks[n]
			r.mu.RUnlock()
			cctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			err := fn(cctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Status = "fail"
				res.Checks[n] = "fail"
				r.log.Warn("readiness check failed", "check", n, "error", err)
				return
			}
			res.Checks[n] = "ok"
		}(n)
	}
	wg.Wait()
	return res
}

// LivenessHandler reports that the process is serving. It never checks
// dependencies: a database outage must not cause restarts.
func LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// ReadinessHandler runs the checks. Error details go to the log, not the
// response, so the endpoint discloses nothing about internals.
func (r *Registry) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		res := r.Run(req.Context())
		code := http.StatusOK
		if res.Status != "ok" {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, res)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

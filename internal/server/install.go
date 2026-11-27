package server

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// InstallStateTTL is how long a service keeps the installation state it read
// (F-014 design D-OQ13).
const InstallStateTTL = 10 * time.Second

// Installation states (F-014 design §5; install.installation.state).
const (
	StateInstalling      = "installing"
	StateOpen            = "open"
	StateUpgrading       = "upgrading"
	StateRestoring       = "restoring"
	StateClosed          = "closed"
	StateDecommissioning = "decommissioning"
)

// installGate answers requests by the installation's state (F-014 T-05,
// D-OQ13): closed or restoring, 503 installation_closed to everything but
// health; upgrading, 503 upgrading to mutations only (reads continue). An
// unknown state, or one never read, is closed (fail closed).
type installGate struct {
	mu   sync.Mutex
	read func(context.Context) (string, error)
	ttl  time.Duration
	now  func() time.Time

	state string
	at    time.Time
}

// UseInstallState makes the server honour the installation's state, read by
// read (install.state()) and kept for ttl. Call it before serving.
func (s *Server) UseInstallState(read func(context.Context) (string, error), ttl time.Duration) {
	s.gate.mu.Lock()
	defer s.gate.mu.Unlock()
	s.gate.read, s.gate.ttl, s.gate.state, s.gate.at = read, ttl, "", time.Time{}
	if s.gate.now == nil {
		s.gate.now = time.Now
	}
}

// current is the state in force: the cached one while fresh, otherwise read
// again; a failed read keeps a value at most a minute old, else "" (closed).
func (g *installGate) current(ctx context.Context) (string, bool) {
	g.mu.Lock()
	read, ttl, state, at, now := g.read, g.ttl, g.state, g.at, g.now
	g.mu.Unlock()
	if read == nil {
		return StateOpen, false
	}
	t := now()
	if state != "" && t.Sub(at) < ttl {
		return state, true
	}
	got, err := read(ctx)
	if err != nil {
		if state != "" && t.Sub(at) < time.Minute {
			return state, true
		}
		return "", true
	}
	g.mu.Lock()
	g.state, g.at = got, t
	g.mu.Unlock()
	return got, true
}

func (g *installGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		state, gated := g.current(r.Context())
		if !gated {
			next.ServeHTTP(w, r)
			return
		}
		switch state {
		case StateOpen, StateInstalling, StateDecommissioning:
			next.ServeHTTP(w, r)
		case StateUpgrading:
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
			default:
				unavailable(w, "upgrading", "the installation is being upgraded; reads continue, changes wait until it finishes")
			}
		default: // closed, restoring, or not known
			unavailable(w, "installation_closed", "the installation is closed")
		}
	})
}

func unavailable(w http.ResponseWriter, code, detail string) {
	w.Header().Set("Retry-After", strconv.Itoa(int(InstallStateTTL/time.Second)))
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": code, "detail": detail})
}

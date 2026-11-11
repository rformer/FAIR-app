// Package enginegate is engine-gate (F-005 T-10, design §2, §11; ADR-013):
// the simulation engine pod's only network listener. It terminates mutual
// TLS (internal/enginetls: TLS 1.2 or later, FIPS 140 module, the risk
// service's certificate pinned) and copies the decrypted bytes, unchanged,
// to the engine's Unix socket in the pod. It parses nothing: the gRPC
// stream between the risk service and the engine passes through as is.
//
// A plain HTTP listener answers the kubelet's probes only: /healthz (the
// gate runs) and /readyz (the engine's socket accepts a connection).
package enginegate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rformer/fair-app/internal/keys"
)

// Defaults.
const (
	ListenAddr       = ":8444"
	HealthAddr       = ":8081"
	SocketPath       = "/run/engine/engine.sock"
	MaxConns         = 64
	HandshakeTimeout = 10 * time.Second
)

// Gate forwards authenticated connections to the engine's socket.
type Gate struct {
	TLS      *tls.Config
	Socket   string
	MaxConns int
	Log      *slog.Logger

	mu     sync.Mutex
	active int
}

// Active is the number of connections being forwarded.
func (g *Gate) Active() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active
}

// Serve accepts on ln until ctx ends, then closes every connection.
func (g *Gate) Serve(ctx context.Context, ln net.Listener) error {
	if g.MaxConns <= 0 {
		g.MaxConns = MaxConns
	}
	sem := make(chan struct{}, g.MaxConns)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			g.Log.Warn("engine-gate: connection refused, at the limit", "peer", conn.RemoteAddr().String(), "limit", g.MaxConns)
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			g.handle(ctx, conn)
		}()
	}
}

func (g *Gate) handle(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()
	peer := raw.RemoteAddr().String()
	tc := tls.Server(raw, g.TLS)
	hctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		g.Log.Warn("engine-gate: handshake refused", "peer", peer, "error", err.Error())
		return
	}
	var d net.Dialer
	up, err := d.DialContext(ctx, "unix", g.Socket)
	if err != nil {
		g.Log.Error("engine-gate: the engine's socket is unavailable", "error", err.Error())
		return
	}
	g.mu.Lock()
	g.active++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.active--
		g.mu.Unlock()
	}()
	pipe(ctx, tc, up)
}

// pipe copies both ways until either side ends or ctx is done, then closes
// both.
func pipe(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
	<-done
}

// Health serves /healthz and /readyz.
func Health(socket string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "unix", socket)
		if err != nil {
			http.Error(w, "the engine is not ready", http.StatusServiceUnavailable)
			return
		}
		_ = c.Close()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// InstallCheck is what CheckInstall needs.
type InstallCheck struct {
	Env    string // FAIR_ENV
	Getenv func(string) string
}

// CheckInstall refuses a production install without the gate's TLS
// directory (certificate, key and client pins, not open to other users) and
// the engine's socket path.
func CheckInstall(c InstallCheck) error {
	if c.Env != "production" {
		return nil
	}
	var errs []error
	dir := c.Getenv("FAIR_ENGINE_GATE_TLS_DIR")
	if dir == "" {
		errs = append(errs, errors.New("FAIR_ENGINE_GATE_TLS_DIR is required in production"))
	} else {
		if _, err := keys.ReadPins(dir + "/" + keys.ClientPins); err != nil {
			errs = append(errs, fmt.Errorf("FAIR_ENGINE_GATE_TLS_DIR: %w", err))
		}
		if _, err := tls.LoadX509KeyPair(dir+"/"+keys.CertFile, dir+"/"+keys.KeyFile); err != nil {
			errs = append(errs, fmt.Errorf("FAIR_ENGINE_GATE_TLS_DIR: %w", err))
		}
		errs = append(errs, keys.CheckPermissions(dir))
	}
	if c.Getenv("FAIR_ENGINE_SOCKET") == "" {
		errs = append(errs, errors.New("FAIR_ENGINE_SOCKET is required in production"))
	}
	return errors.Join(errs...)
}

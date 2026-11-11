package enginegate

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/enginetls"
	"github.com/rformer/fair-app/internal/keys"
)

// fakeEngine answers Info on a Unix socket, as the Python engine does.
type fakeEngine struct {
	enginev1.UnimplementedEngineServer
}

func (fakeEngine) Info(context.Context, *enginev1.InfoRequest) (*enginev1.EngineInfo, error) {
	return &enginev1.EngineInfo{Version: "0.1.0", Architecture: "amd64", Validation: &enginev1.Validation{Passed: true}}, nil
}

type channel struct {
	dir    string // the key directory (keys.Init)
	socket string
	addr   string
	gate   *Gate
}

func socketDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are short (108 bytes); t.TempDir can be longer.
	d, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func start(t *testing.T, now func() time.Time) *channel {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets")
	}
	c := &channel{dir: t.TempDir(), socket: filepath.Join(socketDir(t), "engine.sock")}
	if _, err := keys.Init(c.dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	ul, err := net.Listen("unix", c.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	enginev1.RegisterEngineServer(srv, fakeEngine{})
	go func() { _ = srv.Serve(ul) }()
	t.Cleanup(srv.Stop)

	conf, err := enginetls.ServerConfig(filepath.Join(c.dir, keys.EngineGate, keys.TLSDir), now)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.addr = ln.Addr().String()
	c.gate = &Gate{TLS: conf, Socket: c.socket, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.gate.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return c
}

func (c *channel) clientDir() string { return filepath.Join(c.dir, keys.Risk, keys.EngineClientDir) }

func info(t *testing.T, addr string, conf *tls.Config) error {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(conf)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := enginev1.NewEngineClient(conn).Info(ctx, &enginev1.InfoRequest{})
	if err == nil && got.GetVersion() != "0.1.0" {
		t.Errorf("Info through the gate: %v", got)
	}
	return err
}

func clientConf(t *testing.T, dir string) *tls.Config {
	t.Helper()
	c, err := enginetls.ClientConfig(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The pinned risk client reaches the engine through the gate (F-005 T-10).
func TestChannel(t *testing.T) {
	c := start(t, time.Now)
	if err := info(t, c.addr, clientConf(t, c.clientDir())); err != nil {
		t.Fatalf("the pinned client is refused: %v", err)
	}
}

// An unpinned client certificate, or none, is refused; so is TLS below 1.2;
// and the client refuses a gate it has not pinned.
func TestRefusals(t *testing.T) {
	c := start(t, time.Now)
	other := t.TempDir()
	if _, err := keys.Init(other, time.Now()); err != nil {
		t.Fatal(err)
	}
	otherClient := filepath.Join(other, keys.Risk, keys.EngineClientDir)

	// A client certificate the gate has not pinned (that client pins this
	// gate, so only the gate's check refuses it).
	unpinned := clientConf(t, otherClient)
	unpinned.VerifyPeerCertificate = clientConf(t, c.clientDir()).VerifyPeerCertificate
	if err := info(t, c.addr, unpinned); err == nil {
		t.Error("an unpinned client certificate was accepted")
	}

	// No client certificate at all.
	none := clientConf(t, c.clientDir())
	none.GetClientCertificate = nil
	if err := info(t, c.addr, none); err == nil {
		t.Error("a client without a certificate was accepted")
	}

	// TLS 1.1.
	old := clientConf(t, c.clientDir())
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	old.CipherSuites = nil
	if err := info(t, c.addr, old); err == nil {
		t.Error("TLS 1.1 was accepted")
	}

	// The client pins another gate.
	wrongGate := clientConf(t, c.clientDir())
	wrongGate.VerifyPeerCertificate = clientConf(t, otherClient).VerifyPeerCertificate
	if err := info(t, c.addr, wrongGate); err == nil {
		t.Error("the client accepted a gate it does not pin")
	}

	// The pinned client still works after all that.
	if err := info(t, c.addr, clientConf(t, c.clientDir())); err != nil {
		t.Errorf("the pinned client: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.gate.Active() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.gate.Active() != 0 {
		t.Errorf("connections left open: %d", c.gate.Active())
	}
}

// An expired certificate is refused even when pinned.
func TestExpired(t *testing.T) {
	c := start(t, func() time.Time { return time.Now().Add(keys.EngineCertValidity + 24*time.Hour) })
	if err := info(t, c.addr, clientConf(t, c.clientDir())); err == nil {
		t.Error("an expired client certificate was accepted")
	}
}

// After `iam keys rotate -kind engine`, the gate accepts the new client and
// the old one, and the client accepts the new gate: either side can roll
// out first. Certificates and pins are re-read on every handshake.
func TestRotation(t *testing.T) {
	c := start(t, time.Now)
	oldClient := t.TempDir()
	copyDir(t, c.clientDir(), oldClient)
	if _, err := keys.Rotate(c.dir, keys.KindEngine, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := keys.Check(c.dir); err != nil {
		t.Fatalf("check after rotation: %v", err)
	}
	if err := info(t, c.addr, clientConf(t, c.clientDir())); err != nil {
		t.Errorf("the new client: %v", err)
	}
	old := clientConf(t, oldClient)
	old.VerifyPeerCertificate = clientConf(t, c.clientDir()).VerifyPeerCertificate // it holds both gate pins after rollout
	if err := info(t, c.addr, old); err != nil {
		t.Errorf("the previous client during the rollout: %v", err)
	}
	pins, err := keys.ReadPins(filepath.Join(c.dir, keys.EngineGate, keys.TLSDir, keys.ClientPins))
	if err != nil || len(pins) != 2 {
		t.Errorf("client pins after rotation: %v %v", pins, err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	es, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		b, err := os.ReadFile(filepath.Join(from, e.Name())) // #nosec G304 -- the test's own files
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHealth(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets")
	}
	sock := filepath.Join(socketDir(t), "engine.sock")
	h := Health(sock)
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if get("/healthz") != http.StatusNoContent || get("/readyz") != http.StatusServiceUnavailable {
		t.Error("before the engine listens")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if get("/readyz") != http.StatusNoContent {
		t.Error("the engine listens")
	}
	if get("/") != http.StatusNotFound {
		t.Error("only the probes are served")
	}
}

func TestCheckInstall(t *testing.T) {
	dir := t.TempDir()
	if _, err := keys.Init(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"FAIR_ENGINE_GATE_TLS_DIR": filepath.Join(dir, keys.EngineGate, keys.TLSDir), "FAIR_ENGINE_SOCKET": "/run/engine/engine.sock"}
	get := func(k string) string { return vars[k] }
	if err := CheckInstall(InstallCheck{Env: "production", Getenv: get}); err != nil {
		t.Errorf("complete: %v", err)
	}
	if err := CheckInstall(InstallCheck{Env: "development", Getenv: func(string) string { return "" }}); err != nil {
		t.Errorf("development: %v", err)
	}
	vars["FAIR_ENGINE_GATE_TLS_DIR"] = t.TempDir()
	if err := CheckInstall(InstallCheck{Env: "production", Getenv: get}); err == nil {
		t.Error("an empty TLS directory")
	}
}

// TestLiveEngine calls Info on real engine and gate images through the
// channel (F-005 T-10): FAIR_TEST_ENGINE_ADDR names the gate and
// FAIR_TEST_ENGINE_CLIENT_DIR the risk side of the key directory.
func TestLiveEngine(t *testing.T) {
	addr, dir := os.Getenv("FAIR_TEST_ENGINE_ADDR"), os.Getenv("FAIR_TEST_ENGINE_CLIENT_DIR")
	if addr == "" || dir == "" {
		t.Skip("FAIR_TEST_ENGINE_ADDR and FAIR_TEST_ENGINE_CLIENT_DIR not set")
	}
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(clientConf(t, dir))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := enginev1.NewEngineClient(conn).Info(ctx, &enginev1.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetVersion() == "" || !got.GetValidation().GetPassed() {
		t.Errorf("the engine: %v", got)
	}
	t.Logf("engine %s on %s, validation suite %s passed", got.GetVersion(), got.GetArchitecture(), got.GetValidation().GetSuiteVersion())
}

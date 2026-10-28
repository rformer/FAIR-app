package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The hand-built ClientHellos must be understood by a real TLS stack, not
// only by the fixtures' raw server. A real Go TLS server that accepts TLS 1.0
// and CBC suites cannot run in FIPS mode, so the test re-runs this binary
// with GODEBUG=fips140=off as that server (TestHelperLegacyTLSServer).
func TestRawProbesAgainstRealTLS(t *testing.T) {
	ctx := context.Background()
	cfg := Config{}

	// A FIPS-mode server with the platform's settings: nothing weak accepted.
	good := serve(t, "good")
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if ok, _ := rawAccepts(ctx, cfg, good, "endpoint", v, legacySuites); ok {
			t.Errorf("platform server judged to accept %s", tls.VersionName(v))
		}
	}
	if ok, s := rawAccepts(ctx, cfg, good, "endpoint", tls.VersionTLS12, weakSuites); ok {
		t.Errorf("platform server judged to accept %s", suiteName(s))
	}
	if res := probeEndpoint(ctx, cfg, good, "endpoint"); len(res.problems) != 0 || !strings.HasPrefix(res.version, "TLS 1.3") {
		t.Errorf("platform server: %+v", res)
	}

	// A legacy server in a non-FIPS process.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperLegacyTLSServer$") // #nosec G204 G702 -- this test binary
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=off", "FAIR_LEGACY_TLS_HELPER=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sc := bufio.NewScanner(out)
	addr := ""
	for sc.Scan() {
		if a, ok := strings.CutPrefix(sc.Text(), "LISTEN "); ok {
			addr = a
			break
		}
	}
	if addr == "" {
		t.Fatal("legacy TLS helper did not start")
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if ok, _ := rawAccepts(ctx, cfg, addr, "endpoint", v, legacySuites); !ok {
			t.Errorf("legacy server's %s not detected", tls.VersionName(v))
		}
	}
	if ok, s := rawAccepts(ctx, cfg, addr, "endpoint", tls.VersionTLS12, weakSuites); !ok {
		t.Error("legacy server's CBC suites not detected")
	} else {
		t.Logf("weak suite detected: %s", suiteName(s))
	}
	res := probeEndpoint(ctx, cfg, addr, "endpoint")
	t.Logf("legacy server findings: %v", res.problems)
	if res.severity != "high" || len(res.problems) < 3 {
		t.Errorf("legacy server: %+v", res)
	}
}

// TestHelperLegacyTLSServer is the legacy server for the test above; it
// does nothing in a normal run.
func TestHelperLegacyTLSServer(t *testing.T) {
	if os.Getenv("FAIR_LEGACY_TLS_HELPER") != "1" {
		t.Skip("helper process only")
	}
	cert := selfSigned(t, time.Now().Add(24*time.Hour))
	conf := &tls.Config{ // #nosec G402 -- deliberately weak: the thing under test detects it
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}, // #nosec G402 -- deliberately weak, see above
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("LISTEN " + lis.Addr().String() + "\n")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_ = c.(*tls.Conn).HandshakeContext(context.Background())
		}(c)
	}
}

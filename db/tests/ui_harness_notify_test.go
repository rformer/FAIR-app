package tests

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/notifyapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-009 T-13: the notify service in the UI harness. The destination guard
// refuses loopback, so the test relay listens on this container's private
// address and the guard runs as in an air-gapped install (private addresses
// only); the relay speaks real STARTTLS with a certificate the page is given
// as a trust anchor (GET /dev/smtp). The collector and fan-out run every two
// seconds, as the notify service's leader does.
type harnessNotify struct {
	Upstream *url.URL
	SMTP     *testSMTP
	stop     func()
}

func startHarnessNotify(t *testing.T, e *env, keys authz.KeyProvider) harnessNotify {
	t.Helper()
	ip := privateAddr(t)
	relay := newTestSMTP(t, ip)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relay"), []byte("relay-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := notify.Guard{Allowed: func() []string { return []string{ip.String()} }, AirGapped: true}
	keyring, err := notify.NewKeyring(map[string][]byte{"whk-1": []byte("harness-webhook-secrets-key-32b!")})
	if err != nil {
		t.Fatal(err)
	}
	pool := notifyPool(t, e)
	composer := func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} }
	api := &notifyapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool), MaxAge: time.Second}),
		Keys: keyring, Guard: guard, Mail: notify.SMTPSender{Guard: guard, Dir: dir, Hostname: "fair-harness"},
		Post: notify.WebhookSender{Guard: guard}, Composer: composer}
	srv := httptest.NewServer(api.Handler(keys, nil))
	up, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for ctx.Err() == nil {
			if _, _, err := (notify.Collector{DB: pool}).Collect(ctx); err != nil && ctx.Err() == nil {
				t.Logf("harness collect: %v", err)
			}
			if _, err := (notify.FanOut{DB: pool}).Step(ctx); err != nil && ctx.Err() == nil {
				t.Logf("harness fan-out: %v", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}()
	return harnessNotify{Upstream: up, SMTP: relay, stop: func() { cancel(); srv.Close(); relay.Close() }}
}

// ServeDev answers GET /dev/smtp: where the relay is, its certificate, and
// what it received (recipients and subjects).
func (h harnessNotify) ServeDev(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.SMTP.Info())
}

// privateAddr is this host's first private IPv4 address.
func privateAddr(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() && ip.IsPrivate() {
				return ip.Unmap()
			}
		}
	}
	t.Fatal("no private IPv4 address for the test relay")
	return netip.Addr{}
}

// testSMTP is a small relay: EHLO, STARTTLS (TLS 1.2+), AUTH PLAIN, MAIL,
// RCPT, DATA, QUIT. It records each message's recipient and subject.
type testSMTP struct {
	lis  net.Listener
	cert tls.Certificate
	pem  string
	mu   sync.Mutex
	got  []map[string]string
}

func newTestSMTP(t *testing.T, ip netip.Addr) *testSMTP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fair-test-relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{ip.AsSlice()}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := &testSMTP{lis: lis, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *testSMTP) Close() { _ = s.lis.Close() }

func (s *testSMTP) Info() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, p, _ := net.SplitHostPort(s.lis.Addr().String())
	return map[string]any{"host": h, "port": p, "ca": s.pem, "messages": append([]map[string]string{}, s.got...)}
}

func (s *testSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	r, w := bufio.NewReader(c), c
	say := func(lines ...string) { _, _ = w.Write([]byte(strings.Join(lines, "\r\n") + "\r\n")) }
	say("220 fair-test-relay ESMTP")
	secure, to := false, ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if secure {
				say("250-fair-test-relay", "250 AUTH PLAIN")
			} else {
				say("250-fair-test-relay", "250 STARTTLS")
			}
		case cmd == "STARTTLS" && !secure:
			say("220 ready")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if tc.Handshake() != nil {
				return
			}
			c, r, w, secure = tc, bufio.NewReader(tc), tc, true
		case strings.HasPrefix(cmd, "AUTH PLAIN") && secure:
			say("235 accepted")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			if !secure {
				say("530 STARTTLS first")
				continue
			}
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			to = strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>")
			say("250 ok")
		case cmd == "DATA":
			say("354 go ahead")
			subject := ""
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\n" {
					break
				}
				if subject == "" && strings.HasPrefix(l, "Subject: ") {
					subject = strings.TrimSpace(l[len("Subject: "):])
				}
			}
			s.mu.Lock()
			s.got = append(s.got, map[string]string{"to": to, "subject": subject})
			s.mu.Unlock()
			say("250 queued")
		case cmd == "RSET", cmd == "NOOP":
			say("250 ok")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}

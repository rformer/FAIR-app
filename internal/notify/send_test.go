package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCert is a self-signed certificate for 127.0.0.1 and its PEM.
func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// smtpServer is a minimal relay: implicit TLS or STARTTLS (offered or not),
// AUTH PLAIN, and replies chosen per command.
type smtpServer struct {
	implicit, offerSTARTTLS bool
	user, pass              string
	rcptReply               string // default "250 ok"
	cert                    tls.Certificate
	mu                      sync.Mutex
	got                     []string // the DATA received
	plainAuth               bool     // credentials were offered before TLS
	addr                    string
}

func (s *smtpServer) start(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s.addr = l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
}

func (s *smtpServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	secure := false
	if s.implicit {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
		if tc.Handshake() != nil {
			return
		}
		c, secure = tc, true
	}
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(lines ...string) {
		for _, l := range lines {
			_, _ = w.WriteString(l + "\r\n")
		}
		_ = w.Flush()
	}
	say("220 relay ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			ext := []string{"250-relay"}
			if s.offerSTARTTLS && !secure {
				ext = append(ext, "250-STARTTLS")
			}
			say(append(ext, "250 AUTH PLAIN")...)
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			s.mu.Lock()
			if !secure {
				s.plainAuth = true
			}
			s.mu.Unlock()
			b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			if string(b) == "\x00"+s.user+"\x00"+s.pass {
				say("235 ok")
			} else {
				say("535 bad credentials")
			}
		case strings.HasPrefix(cmd, "MAIL FROM"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			if s.rcptReply != "" {
				say(s.rcptReply)
			} else {
				say("250 ok")
			}
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.got = append(s.got, b.String())
			s.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 no")
		}
	}
}

func loopbackGuard() Guard {
	return Guard{Allowed: func() []string { return []string{"127.0.0.1"} }, allowForTest: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
}

func TestSMTPSender(t *testing.T) {
	cert, pemCA := testCert(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relay-password"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := composer.Email(sampleEnvelope(), "A risk acceptance waits for your decision")
	if err != nil {
		t.Fatal(err)
	}
	send := func(srv *smtpServer, mode string, mutate func(*SMTPConfig)) (Sent, error) {
		host, port, _ := net.SplitHostPort(srv.addr)
		p, _ := strconv.Atoi(port)
		cfg := SMTPConfig{Host: host, Port: p, TLSMode: mode, TrustAnchors: pemCA, From: "FAIR <fair@example.com>", Username: "fair", PasswordFile: "relay-password"}
		if mutate != nil {
			mutate(&cfg)
		}
		return SMTPSender{Guard: loopbackGuard(), Dir: dir}.Send(context.Background(), cfg, "Ana <ana@example.com>", m, "d-42")
	}
	// STARTTLS, required and offered: authenticated inside TLS, delivered.
	srv := &smtpServer{offerSTARTTLS: true, user: "fair", pass: "s3cret", cert: cert}
	srv.start(t)
	sent, err := send(srv, "starttls", nil)
	if err != nil || !strings.HasPrefix(sent.TLSVersion, "TLS 1.") {
		t.Fatalf("starttls: %+v %v", sent, err)
	}
	if srv.plainAuth {
		t.Fatal("credentials offered before TLS")
	}
	data := srv.got[0]
	for _, want := range []string{"Message-ID: <d-42@fair-notify>", "Subject: [FAIR] A risk acceptance waits for your decision", "multipart/alternative",
		"text/plain; charset=utf-8", "text/html; charset=utf-8", "To: \"Ana\" <ana@example.com>", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(data, want) {
			t.Errorf("message lacks %q", want)
		}
	}
	// Implicit TLS.
	isrv := &smtpServer{implicit: true, user: "fair", pass: "s3cret", cert: cert}
	isrv.start(t)
	if _, err := send(isrv, "implicit", nil); err != nil || len(isrv.got) != 1 {
		t.Fatalf("implicit: %v", err)
	}
	// STARTTLS stripped: nothing is sent, no credentials, permanent.
	strip := &smtpServer{user: "fair", pass: "s3cret", cert: cert}
	strip.start(t)
	if _, err := send(strip, "starttls", nil); err == nil || !IsPermanent(err) || len(strip.got) != 0 || strip.plainAuth {
		t.Fatalf("stripped STARTTLS: %v, %d messages, plain auth %v", err, len(strip.got), strip.plainAuth)
	}
	// An untrusted certificate: no delivery.
	_, otherCA := testCert(t)
	if _, err := send(srv, "starttls", func(c *SMTPConfig) { c.TrustAnchors = otherCA }); err == nil {
		t.Fatal("an untrusted relay certificate")
	}
	// Replies: 5xx permanent, 4xx retryable.
	rej := &smtpServer{offerSTARTTLS: true, user: "fair", pass: "s3cret", cert: cert, rcptReply: "550 no such user"}
	rej.start(t)
	if _, err := send(rej, "starttls", nil); err == nil || !IsPermanent(err) {
		t.Errorf("550: %v", err)
	}
	busy := &smtpServer{offerSTARTTLS: true, user: "fair", pass: "s3cret", cert: cert, rcptReply: "451 try later"}
	busy.start(t)
	if _, err := send(busy, "starttls", nil); err == nil || IsPermanent(err) {
		t.Errorf("451: %v", err)
	}
	// The guard decides: an unlisted relay is refused before any connection.
	if _, err := (SMTPSender{Guard: Guard{}, Dir: dir}).Send(context.Background(), SMTPConfig{Host: "127.0.0.1", Port: 25, TLSMode: "starttls",
		From: "fair@example.com"}, "ana@example.com", m, "d"); !errors.Is(err, ErrRefused) {
		t.Errorf("unlisted: %v", err)
	}
	// Configurations refused.
	for name, c := range map[string]SMTPConfig{
		"plaintext":      {Host: "relay", Port: 25, TLSMode: "none", From: "a@b.c"},
		"a path":         {Host: "relay", Port: 25, TLSMode: "starttls", From: "a@b.c", Username: "u", PasswordFile: "../etc/passwd"},
		"a user alone":   {Host: "relay", Port: 25, TLSMode: "starttls", From: "a@b.c", Username: "u"},
		"no from":        {Host: "relay", Port: 25, TLSMode: "starttls"},
		"bad port":       {Host: "relay", Port: 0, TLSMode: "starttls", From: "a@b.c"},
		"bad anchors":    {Host: "relay", Port: 25, TLSMode: "starttls", From: "a@b.c", TrustAnchors: "nope"},
		"host with port": {Host: "relay:25", Port: 25, TLSMode: "starttls", From: "a@b.c"},
	} {
		if err := c.Check(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The Standard Webhooks example signature.
func TestSignStandardWebhooks(t *testing.T) {
	got, err := Sign("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`))
	if err != nil || got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("%s %v", got, err)
	}
	s, err := NewWebhookSecret()
	if err != nil || !strings.HasPrefix(s, SecretPrefix) {
		t.Fatal(s, err)
	}
	if k, _ := secretKey(s); len(k) != 32 {
		t.Errorf("a secret of %d bytes", len(k))
	}
	if _, err := Sign("nope", "id", 1, nil); err == nil {
		t.Error("a malformed secret signed")
	}
}

func TestWebhookSender(t *testing.T) {
	secret, _ := NewWebhookSecret()
	previous, _ := NewWebhookSecret()
	var mu sync.Mutex
	var heads []http.Header
	var bodies [][]byte
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		heads, bodies = append(heads, r.Header.Clone()), append(bodies, b)
		st := status
		mu.Unlock()
		w.WriteHeader(st)
		_, _ = w.Write([]byte(strings.Repeat("x", 100<<10))) // more than is read
	}))
	defer srv.Close()
	now := time.Unix(1_800_000_000, 0)
	ws := WebhookSender{Guard: loopbackGuard(), TLS: srv.Client().Transport.(*http.Transport).TLSClientConfig, Now: func() time.Time { return now }}
	body, _ := composer.WebhookBody(sampleEnvelope(), "d-7")
	sent, err := ws.Send(context.Background(), srv.URL+"/hook", secret, "", "d-7", body)
	if err != nil || sent.Status != 200 {
		t.Fatalf("send: %+v %v", sent, err)
	}
	h := heads[0]
	want, _ := Sign(secret, "d-7", now.Unix(), bodies[0])
	if h.Get("webhook-id") != "d-7" || h.Get("webhook-timestamp") != "1800000000" || h.Get("webhook-signature") != want || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", h)
	}
	// With the previous secret during a rotation: both signatures; a retry
	// carries the same id.
	if _, err := ws.Send(context.Background(), srv.URL+"/hook", secret, previous, "d-7", body); err != nil {
		t.Fatal(err)
	}
	old, _ := Sign(previous, "d-7", now.Unix(), body)
	if got := heads[1].Get("webhook-signature"); got != want+" "+old || heads[1].Get("webhook-id") != "d-7" {
		t.Errorf("rotation signatures %q", got)
	}
	// Answers: 408, 429, 5xx retry; other 4xx and 3xx are permanent.
	for code, permanent := range map[int]bool{408: false, 429: false, 500: false, 503: false, 400: true, 401: true, 404: true, 410: true, 302: true} {
		mu.Lock()
		status = code
		mu.Unlock()
		_, err := ws.Send(context.Background(), srv.URL+"/hook", secret, "", "d-8", body)
		if err == nil || IsPermanent(err) != permanent {
			t.Errorf("%d: %v (permanent %v)", code, err, IsPermanent(err))
		}
	}
	for _, bad := range []string{"http://127.0.0.1/hook", "https://u:p@127.0.0.1/hook", "ftp://x"} {
		if _, err := ws.Send(context.Background(), bad, secret, "", "d", body); !IsPermanent(err) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// A host the allow-list lacks: refused, nothing sent.
	n := len(heads)
	if _, err := (WebhookSender{Guard: Guard{}}).Send(context.Background(), srv.URL+"/hook", secret, "", "d", body); !errors.Is(err, ErrRefused) || len(heads) != n {
		t.Errorf("unlisted: %v", err)
	}
}

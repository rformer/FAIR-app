package notify

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// F-009 T-15: the unit half of the STRIDE suite for design §7 (the rows map
// to these and others in db/tests TestSTRIDECatalog).

// I: secrets and credentials disclosed: TLS 1.2 is the floor and
// certificates are verified, for the relay and for webhooks; nothing, and
// no credential, is sent otherwise.
func TestSTRIDEF009TLSFloor(t *testing.T) {
	cert, pemCA := testCert(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relay-password"), []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := composer.Email(sampleEnvelope(), "A test")
	if err != nil {
		t.Fatal(err)
	}
	send := func(srv *smtpServer, mode, anchors string) error {
		host, port, _ := net.SplitHostPort(srv.addr)
		p, _ := strconv.Atoi(port)
		cfg := SMTPConfig{Host: host, Port: p, TLSMode: mode, TrustAnchors: anchors, From: "fair@example.com", Username: "fair", PasswordFile: "relay-password"}
		_, err := SMTPSender{Guard: loopbackGuard(), Dir: dir}.Send(context.Background(), cfg, "ana@example.com", m, "d-1")
		return err
	}
	for name, c := range map[string]struct {
		srv     *smtpServer
		mode    string
		anchors string
	}{
		"implicit TLS 1.1":       {&smtpServer{implicit: true, user: "fair", pass: "s3cret", cert: cert, maxTLS: tls.VersionTLS11}, "implicit", pemCA},
		"STARTTLS at TLS 1.1":    {&smtpServer{offerSTARTTLS: true, user: "fair", pass: "s3cret", cert: cert, maxTLS: tls.VersionTLS11}, "starttls", pemCA},
		"an unverified relay":    {&smtpServer{implicit: true, user: "fair", pass: "s3cret", cert: cert}, "implicit", ""},
		"an unverified STARTTLS": {&smtpServer{offerSTARTTLS: true, user: "fair", pass: "s3cret", cert: cert}, "starttls", ""},
		"STARTTLS never offered": {&smtpServer{offerSTARTTLS: false, user: "fair", pass: "s3cret", cert: cert}, "starttls", pemCA},
	} {
		c.srv.start(t)
		if err := send(c.srv, c.mode, c.anchors); err == nil {
			t.Errorf("%s: sent", name)
		}
		c.srv.mu.Lock()
		if len(c.srv.got) != 0 || c.srv.plainAuth {
			t.Errorf("%s: a message (%d) or credentials in the clear (%v)", name, len(c.srv.got), c.srv.plainAuth)
		}
		c.srv.mu.Unlock()
	}

	// Webhooks: a receiver at TLS 1.1, or with a certificate nobody vouches for.
	var received atomic.Int32
	h := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { received.Add(1) })
	old := httptest.NewUnstartedServer(h)
	old.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} // #nosec G402 -- an old-TLS server the sender must refuse
	old.StartTLS()
	defer old.Close()
	secret, _ := NewWebhookSecret()
	body, _ := composer.WebhookBody(sampleEnvelope(), "d-2")
	ws := WebhookSender{Guard: loopbackGuard(), TLS: old.Client().Transport.(*http.Transport).TLSClientConfig}
	if _, err := ws.Send(context.Background(), old.URL+"/hook", secret, "", "d-2", body); err == nil {
		t.Error("a TLS 1.1 receiver was sent to")
	}
	modern := httptest.NewTLSServer(h)
	defer modern.Close()
	if _, err := (WebhookSender{Guard: loopbackGuard()}).Send(context.Background(), modern.URL+"/hook", secret, "", "d-3", body); err == nil {
		t.Error("an unverified receiver was sent to")
	}
	if n := received.Load(); n != 0 {
		t.Errorf("%d requests reached a refused receiver", n)
	}
}

// S, T: a forged or replayed webhook delivery: the signature covers the id,
// the timestamp and the body under the webhook's own secret, so a receiver
// that checks it and the timestamp's age rejects any change, another
// webhook's secret, and an old delivery replayed.
func TestSTRIDEF009Signing(t *testing.T) {
	secret, _ := NewWebhookSecret()
	other, _ := NewWebhookSecret()
	body := []byte(`{"type":"acceptance.decision_needed"}`)
	now := time.Now().Unix()
	sig, err := Sign(secret, "d-9", now, body)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(id string, ts int64, b []byte, key string) bool {
		want, err := Sign(key, id, ts, b)
		return err == nil && want == sig && time.Since(time.Unix(ts, 0)) < 5*time.Minute
	}
	if !verify("d-9", now, body, secret) {
		t.Fatal("the genuine delivery does not verify")
	}
	for name, ok := range map[string]bool{
		"another body":           verify("d-9", now, []byte(`{"type":"acceptance.decided"}`), secret),
		"another id":             verify("d-10", now, body, secret),
		"another timestamp":      verify("d-9", now+1, body, secret),
		"another webhook's key":  verify("d-9", now, body, other),
		"replayed an hour later": verify("d-9", now-3600, body, secret),
	} {
		if ok {
			t.Errorf("%s verifies", name)
		}
	}
	// Signatures are versioned and base64 HMAC-SHA-256 (32 bytes).
	if !strings.HasPrefix(sig, "v1,") || len(sig) != len("v1,")+44 {
		t.Errorf("signature form %q", sig)
	}
}

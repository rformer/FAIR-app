package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// F-009 T-09 (F-009-AC-08, AC-09, AC-13; design §3.4, §3.5): sending one
// delivery by email or to a webhook. Every connection goes through the
// Guard; failures are classified for the delivery workers (T-10).

// Permanent marks a failure that retrying cannot fix: a refused
// destination, an SMTP 5xx, a webhook 4xx other than 408 and 429.
type Permanent struct{ Err error }

func (p Permanent) Error() string { return p.Err.Error() }
func (p Permanent) Unwrap() error { return p.Err }

// IsPermanent reports whether err is permanent (a refused destination is).
func IsPermanent(err error) bool {
	var p Permanent
	return errors.As(err, &p) || errors.Is(err, ErrRefused)
}

// Sent is what a successful send reports (for tests and the channel's state).
type Sent struct {
	TLSVersion string // e.g. "TLS 1.3"
	Status     int    // a webhook's HTTP status
}

// SMTPConfig is the relay (notify.channel config, design §3.4).
type SMTPConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	TLSMode      string `json:"tls_mode"`                // implicit or starttls
	TrustAnchors string `json:"trust_anchors,omitempty"` // PEM; empty: the system's roots
	From         string `json:"from"`
	Username     string `json:"username,omitempty"`
	PasswordFile string `json:"password_file,omitempty"` // a file name under the SMTP directory
}

// Check refuses a configuration that cannot be used safely.
func (c SMTPConfig) Check() error {
	switch {
	case c.Host == "" || strings.ContainsAny(c.Host, "/:@ \r\n"):
		return errors.New("notify: the relay needs a host name or address")
	case c.Port < 1 || c.Port > 65535:
		return errors.New("notify: the relay's port is 1 to 65535")
	case c.TLSMode != "implicit" && c.TLSMode != "starttls":
		return errors.New("notify: tls_mode is implicit or starttls (never plaintext)")
	case (c.Username == "") != (c.PasswordFile == ""):
		return errors.New("notify: username and password_file go together")
	case c.PasswordFile != "" && (c.PasswordFile != filepath.Base(c.PasswordFile) || strings.HasPrefix(c.PasswordFile, ".")):
		return errors.New("notify: password_file is a file name in the SMTP directory, not a path")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return fmt.Errorf("notify: from: %w", err)
	}
	if c.TrustAnchors != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.TrustAnchors)) {
			return errors.New("notify: trust_anchors holds no PEM certificate")
		}
	}
	return nil
}

func (c SMTPConfig) tlsConfig() *tls.Config {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
	if c.TrustAnchors != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(c.TrustAnchors))
		tc.RootCAs = pool
	}
	return tc
}

// SMTPSender sends email through the relay.
type SMTPSender struct {
	Guard    Guard
	Dir      string // FAIR_NOTIFY_SMTP_DIR: where password files are
	Hostname string // the name given in EHLO; default "fair-notify"
}

// Send sends msg to the address to, as delivery id (its Message-ID).
func (s SMTPSender) Send(ctx context.Context, cfg SMTPConfig, to string, msg Message, id string) (Sent, error) {
	if err := cfg.Check(); err != nil {
		return Sent{}, Permanent{err}
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return Sent{}, Permanent{fmt.Errorf("notify: the recipient's address: %w", err)}
	}
	from, _ := mail.ParseAddress(cfg.From)
	var password string
	if cfg.PasswordFile != "" {
		b, err := os.ReadFile(filepath.Join(s.Dir, cfg.PasswordFile)) // #nosec G304 -- a checked base name in the SMTP directory
		if err != nil {
			return Sent{}, fmt.Errorf("notify: the relay's password file: %w", err)
		}
		password = strings.TrimRight(string(b), "\r\n")
	}
	body, err := mimeMessage(from, rcpt, msg, id)
	if err != nil {
		return Sent{}, Permanent{err}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*Timeout)
	defer cancel()
	conn, err := s.Guard.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return Sent{}, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tc := cfg.tlsConfig()
	var c *smtp.Client
	if cfg.TLSMode == "implicit" {
		tlsConn := tls.Client(conn, tc)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return Sent{}, fmt.Errorf("notify: TLS with the relay: %w", err)
		}
		if c, err = smtp.NewClient(tlsConn, cfg.Host); err != nil {
			return Sent{}, smtpErr(err)
		}
	} else {
		if c, err = smtp.NewClient(conn, cfg.Host); err != nil {
			return Sent{}, smtpErr(err)
		}
	}
	defer func() { _ = c.Close() }()
	hostname := s.Hostname
	if hostname == "" {
		hostname = "fair-notify"
	}
	if err := c.Hello(hostname); err != nil {
		return Sent{}, smtpErr(err)
	}
	if cfg.TLSMode == "starttls" {
		// Required: a relay that does not offer STARTTLS (or a stripping
		// attacker) gets nothing in plaintext.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return Sent{}, Permanent{errors.New("notify: the relay does not offer STARTTLS; nothing was sent")}
		}
		if err := c.StartTLS(tc); err != nil {
			return Sent{}, fmt.Errorf("notify: STARTTLS with the relay: %w", err)
		}
	}
	state, ok := c.TLSConnectionState()
	if !ok || state.Version < tls.VersionTLS12 {
		return Sent{}, Permanent{errors.New("notify: no TLS 1.2 or later with the relay; nothing was sent")}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return Sent{}, smtpErr(err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return Sent{}, smtpErr(err)
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return Sent{}, smtpErr(err)
	}
	w, err := c.Data()
	if err != nil {
		return Sent{}, smtpErr(err)
	}
	if _, err := w.Write(body); err != nil {
		return Sent{}, smtpErr(err)
	}
	if err := w.Close(); err != nil {
		return Sent{}, smtpErr(err)
	}
	_ = c.Quit()
	return Sent{TLSVersion: tls.VersionName(state.Version)}, nil
}

// smtpErr classifies an SMTP failure: 5xx replies are permanent.
func smtpErr(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 && te.Code < 600 {
		return Permanent{err}
	}
	return err
}

// mimeMessage is the message: headers, then text and HTML alternatives,
// quoted-printable. The Message-ID is the delivery id, so a retried
// delivery reads as the same message.
func mimeMessage(from, to *mail.Address, m Message, id string) ([]byte, error) {
	for _, v := range []string{m.Subject, id} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%w: a header value with CR or LF", ErrUnsafe)
		}
	}
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	head := []string{
		"From: " + from.String(),
		"To: " + to.String(),
		"Subject: " + m.Subject,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + id + "@fair-notify>",
		"MIME-Version: 1.0",
		"Auto-Submitted: auto-generated",
		"Content-Type: multipart/alternative; boundary=" + mw.Boundary(),
	}
	var out bytes.Buffer
	out.WriteString(strings.Join(head, "\r\n") + "\r\n\r\n")
	for _, part := range []struct{ ct, body string }{{"text/plain; charset=utf-8", m.Text}, {"text/html; charset=utf-8", m.HTML}} {
		pw, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {part.ct}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if err != nil {
			return nil, err
		}
		qw := quotedprintable.NewWriter(pw)
		if _, err := qw.Write([]byte(strings.ReplaceAll(part.body, "\n", "\r\n"))); err != nil {
			return nil, err
		}
		if err := qw.Close(); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	out.Write(b.Bytes())
	return out.Bytes(), nil
}

// SecretPrefix begins every webhook secret as shown (Standard Webhooks).
const SecretPrefix = "whsec_"

// NewWebhookSecret is a new webhook secret: 32 random bytes, shown once.
func NewWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return SecretPrefix + base64.StdEncoding.EncodeToString(b), nil
}

// secretKey is a secret's key bytes.
func secretKey(secret string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, SecretPrefix))
	if err != nil || !strings.HasPrefix(secret, SecretPrefix) || len(k) < 24 {
		return nil, errors.New("notify: not a webhook secret")
	}
	return k, nil
}

// Sign is the Standard Webhooks signature of body sent as id at ts:
// "v1,<base64 HMAC-SHA-256(key, id.ts.body)>".
func Sign(secret, id string, ts int64, body []byte) (string, error) {
	k, err := secretKey(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, k)
	fmt.Fprintf(mac, "%s.%d.", id, ts)
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// WebhookSender posts deliveries to webhooks.
type WebhookSender struct {
	Guard Guard
	TLS   *tls.Config // roots for webhooks (nil: the system's)
	Now   func() time.Time
}

// Send posts body to target as delivery id, signed by secret and, while
// a rotation is recent, previous too (design §3.4).
func (s WebhookSender) Send(ctx context.Context, target, secret, previous, id string, body []byte) (Sent, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return Sent{}, Permanent{errors.New("notify: a webhook is an https URL without credentials")}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ts := now().Unix()
	sig, err := Sign(secret, id, ts, body)
	if err != nil {
		return Sent{}, Permanent{err}
	}
	if previous != "" {
		old, err := Sign(previous, id, ts, body)
		if err != nil {
			return Sent{}, Permanent{err}
		}
		sig += " " + old
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return Sent{}, Permanent{err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fair-notify")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig)
	resp, err := s.Guard.HTTPClient(s.TLS).Do(req)
	if err != nil {
		if errors.Is(err, ErrRefused) {
			return Sent{}, err
		}
		return Sent{}, fmt.Errorf("notify: posting to the webhook: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponse))
	_ = resp.Body.Close()
	sent := Sent{Status: resp.StatusCode}
	if resp.TLS != nil {
		sent.TLSVersion = tls.VersionName(resp.TLS.Version)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return sent, nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return sent, fmt.Errorf("notify: the webhook answered %d", resp.StatusCode)
	default: // 3xx (never followed) and other 4xx
		return sent, Permanent{fmt.Errorf("notify: the webhook answered %d", resp.StatusCode)}
	}
}

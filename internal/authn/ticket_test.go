package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

func keys(t *testing.T, kid string) *authz.LocalKeys {
	t.Helper()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	lk, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	return lk
}

// F-001 T-15: login tickets are signed by iam, short-lived and verified.
func TestTicket(t *testing.T) {
	iam, other := keys(t, "iam-1"), keys(t, "iam-1")
	now := time.Now()
	tok, err := IssueTicket(iam, Ticket{UserID: "u1", AuthMethod: "saml", IDPID: "idp1", ReturnTo: "/x", AuthTime: now.Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTicket(iam, tok, now.Add(30*time.Second))
	if err != nil || got.UserID != "u1" || got.ReturnTo != "/x" || got.ID == "" || got.Expiry-got.IssuedAt != 60 {
		t.Fatalf("%+v %v", got, err)
	}
	parts := strings.Split(tok, ".")
	for name, c := range map[string]struct {
		kp  authz.KeyProvider
		tok string
		at  time.Time
	}{
		"expired":        {iam, tok, now.Add(61 * time.Second)},
		"another key":    {other, tok, now},
		"claims changed": {iam, parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"admin","iss":"fair-iam","aud":"fair-gateway"}`)) + "." + parts[2], now},
		"alg none":       {iam, b64.EncodeToString([]byte(`{"alg":"none","typ":"fair-login+jwt","kid":"iam-1"}`)) + "." + parts[1] + ".", now},
		"truncated":      {iam, parts[0] + "." + parts[1], now},
		"not yet valid":  {iam, tok, now.Add(-time.Minute)},
	} {
		if _, err := VerifyTicket(c.kp, c.tok, c.at); !errors.Is(err, ErrTicket) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

package authz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeKey(t *testing.T, dir, kid string, public bool) *ecdsa.PrivateKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var blk *pem.Block
	if public {
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		blk = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	} else {
		der, _ := x509.MarshalECPrivateKey(k)
		blk = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	}
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	return k
}

// sign builds a token with arbitrary header and claims (for negative tests).
func sign(t *testing.T, key *ecdsa.PrivateKey, hdr map[string]string, c any) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	p, _ := json.Marshal(c)
	s := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(s))
	r, ss, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return s + "." + b64.EncodeToString(sig)
}

func TestInternalJWT(t *testing.T) {
	gw := t.TempDir()
	k1 := writeKey(t, gw, "2026-10-01", false)
	gateway, err := LoadLocalKeys(gw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	dbc := DBContextHash("v1.k.u.1.2.n.mac")
	c := Claims{Subject: "u-1", ScopeVersion: 7, AuthTime: now.Add(-time.Minute).Unix(), DBContext: dbc}
	tok, err := MintJWT(gateway, c, "posture", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJWT(gateway, tok, "posture", now.Add(time.Minute))
	if err != nil || got.Subject != "u-1" || got.ScopeVersion != 7 || got.DBContext != dbc || got.Issuer != JWTIssuer || got.ID == "" {
		t.Fatalf("verify: %+v %v", got, err)
	}

	// Services verify with public keys only.
	svc := t.TempDir()
	der, _ := x509.MarshalPKIXPublicKey(&k1.PublicKey)
	_ = os.WriteFile(filepath.Join(svc, "2026-10-01.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	verifier, err := LoadLocalKeys(svc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJWT(verifier, tok, "posture", now); err != nil {
		t.Fatalf("public-key verify: %v", err)
	}
	if _, _, err := verifier.SigningKey(); err == nil {
		t.Fatal("a verification-only provider must not sign")
	}

	good := map[string]any{"iss": JWTIssuer, "aud": "posture", "sub": "u-1", "sv": 7, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "x", "dbc": dbc}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	es := map[string]string{"alg": "ES256", "kid": "2026-10-01"}
	parts := strings.Split(tok, ".")
	for name, bad := range map[string]string{
		"tampered claims":  parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"fair-gateway","aud":"posture","sub":"admin"}`)) + "." + parts[2],
		"alg none":         b64.EncodeToString([]byte(`{"alg":"none","kid":"2026-10-01"}`)) + "." + parts[1] + ".",
		"alg HS256":        sign(t, k1, map[string]string{"alg": "HS256", "kid": "2026-10-01"}, good),
		"unknown key":      sign(t, k1, map[string]string{"alg": "ES256", "kid": "other"}, good),
		"no key id":        sign(t, k1, map[string]string{"alg": "ES256"}, good),
		"wrong audience":   sign(t, k1, es, with("aud", "iam")),
		"wrong issuer":     sign(t, k1, es, with("iss", "someone")),
		"lifetime > 5 min": sign(t, k1, es, with("exp", now.Add(10*time.Minute).Unix())),
		"expired":          sign(t, k1, es, with("exp", now.Add(-time.Minute).Unix())),
		"no DB context":    sign(t, k1, es, with("dbc", "")),
		"foreign signer":   sign(t, func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }(), es, good),
		"malformed":        "a.b",
	} {
		if _, err := VerifyJWT(gateway, bad, "posture", now); !errors.Is(err, ErrInvalidJWT) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := MintJWT(gateway, c, "posture", 6*time.Minute, now); err == nil {
		t.Error("minted a JWT longer than 5 minutes")
	}

	// Rotation: a new key signs, the old one still verifies.
	k2 := writeKey(t, gw, "2026-11-01", false)
	rotated, err := LoadLocalKeys(gw)
	if err != nil {
		t.Fatal(err)
	}
	if kid, key, _ := rotated.SigningKey(); kid != "2026-11-01" || !key.Equal(k2) {
		t.Fatalf("signing key after rotation: %s", kid)
	}
	if _, err := VerifyJWT(rotated, tok, "posture", now); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}
}

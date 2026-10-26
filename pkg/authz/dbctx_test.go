package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testKey = ContextKey{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}

func TestMintDBContextFormat(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok, err := MintDBContext(testKey, "6f1c0b9e-1111-4222-8333-944445555666", 42, 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 7 || parts[0] != "v1" || parts[1] != "k1" || parts[3] != "42" || len(parts[5]) != 32 {
		t.Fatalf("token = %s", tok)
	}
	if exp, _ := strconv.ParseInt(parts[4], 10, 64); exp != now.Add(5*time.Minute).Unix() {
		t.Fatalf("expiry = %s", parts[4])
	}
	mac := hmac.New(sha256.New, testKey.Secret)
	mac.Write([]byte(strings.Join(parts[:6], ".")))
	if parts[6] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not verify")
	}
	other, _ := MintDBContext(testKey, "6f1c0b9e-1111-4222-8333-944445555666", 42, 5*time.Minute, now)
	if other == tok {
		t.Fatal("two tokens share a nonce")
	}
}

func TestMintDBContextRejects(t *testing.T) {
	now := time.Now()
	if _, err := MintDBContext(ContextKey{ID: "k1", Secret: []byte("short")}, "u", 1, time.Minute, now); !errors.Is(err, ErrInvalidContextKey) {
		t.Errorf("short secret: %v", err)
	}
	if _, err := MintDBContext(ContextKey{ID: "k.1", Secret: testKey.Secret}, "u", 1, time.Minute, now); !errors.Is(err, ErrInvalidContextKey) {
		t.Errorf("dotted key id: %v", err)
	}
	for _, ttl := range []time.Duration{0, -time.Second, MaxContextTTL + time.Second} {
		if _, err := MintDBContext(testKey, "u", 1, ttl, now); err == nil {
			t.Errorf("ttl %v accepted", ttl)
		}
	}
	if _, err := MintDBContext(testKey, "a.b", 1, time.Minute, now); err == nil {
		t.Error("user id with a dot accepted")
	}
}

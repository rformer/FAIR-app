package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Service-account tokens (F-001 T-33; AC-37). The iam API issues client
// secrets; the gateway's token endpoint exchanges a secret, or an mTLS
// certificate, for a short-lived access token. The database keeps only
// HMAC-SHA-256 under the token pepper (FAIR_TOKEN_PEPPER_FILE), which iam
// and the gateway hold and the database never sees.
const (
	SecretPrefix = "fsa_" // client secrets
	AccessPrefix = "fat_" // access tokens
	// MinTokenPepperLen is the shortest token pepper accepted.
	MinTokenPepperLen = 32
)

// ErrTokenPepper means the token pepper is missing or too short.
var ErrTokenPepper = errors.New("authn: the token pepper must be at least 32 bytes")

// NewToken returns prefix plus 256 random bits.
func NewToken(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// TokenHMAC is what the database stores for a client secret or access
// token. The prefix separates the two kinds.
func TokenHMAC(pepper []byte, token string) ([]byte, error) {
	if len(pepper) < MinTokenPepperLen {
		return nil, ErrTokenPepper
	}
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte("fair-sa-token\x00" + token))
	return m.Sum(nil), nil
}

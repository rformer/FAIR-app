package authz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MaxContextTTL is the longest a database context token may live (design §4:
// 5 minutes). The database refuses tokens that claim more than 10 minutes.
const MaxContextTTL = 5 * time.Minute

// ContextKey is an HMAC key for database context tokens. The same key is held
// in authz.ctx_key (ADR-007); ID selects it during rotation.
type ContextKey struct {
	ID     string
	Secret []byte
}

var keyIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ErrInvalidContextKey is returned for unusable keys.
var ErrInvalidContextKey = errors.New("authz: invalid context key")

// MintDBContext returns the value services SET LOCAL as authz.ctx at the
// start of each transaction (ADR-007):
//
//	v1.<key_id>.<user_id>.<scope_version>.<expiry_unix>.<nonce>.<hmac>
//
// The HMAC is HMAC-SHA-256 (FIPS 140 module) over everything before the last
// dot, hex encoded. RLS returns rows only while the token is unexpired and
// scopeVersion is the user's current scope version.
func MintDBContext(k ContextKey, userID string, scopeVersion int64, ttl time.Duration, now time.Time) (string, error) {
	if !keyIDRE.MatchString(k.ID) || len(k.Secret) < 32 {
		return "", fmt.Errorf("%w: id must match %s and the secret must be at least 32 bytes", ErrInvalidContextKey, keyIDRE)
	}
	if ttl <= 0 || ttl > MaxContextTTL {
		return "", fmt.Errorf("authz: context TTL %v must be in (0, %v]", ttl, MaxContextTTL)
	}
	if strings.Contains(userID, ".") || userID == "" {
		return "", errors.New("authz: invalid user id")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body := strings.Join([]string{
		"v1", k.ID, userID, fmt.Sprint(scopeVersion), fmt.Sprint(now.Add(ttl).Unix()), hex.EncodeToString(nonce),
	}, ".")
	mac := hmac.New(sha256.New, k.Secret)
	mac.Write([]byte(body))
	return body + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

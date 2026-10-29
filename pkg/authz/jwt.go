package authz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Internal JWT (F-001 T-14, design §4; pulled forward with F-015 T-31). For
// each request the gateway mints an ES256 JWT, valid at most 5 minutes, for
// the service it forwards to, alongside the DB context token
// (MintDBContext). The JWT's "dbc" claim is the SHA-256 of that token, so
// the two cannot be recombined across requests. Services verify it with
// VerifyJWT; only ES256 is accepted, with a known key ID.

// MaxJWTTTL is the longest an internal JWT may live.
const MaxJWTTTL = 5 * time.Minute

// JWTIssuer is the internal JWTs' issuer.
const JWTIssuer = "fair-gateway"

// jwtLeeway tolerates clock skew between gateway and services.
const jwtLeeway = 30 * time.Second

// Claims are an internal JWT's claims.
type Claims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"` // the service, e.g. "posture"
	Subject      string `json:"sub"` // user id
	ScopeVersion int64  `json:"sv"`
	AuthTime     int64  `json:"auth_time"` // unix seconds of the IdP authentication (step-up, F-015 T-24)
	IssuedAt     int64  `json:"iat"`
	Expiry       int64  `json:"exp"`
	ID           string `json:"jti"`
	DBContext    string `json:"dbc"` // hex SHA-256 of the DB context token
	// NetworkChanged: the session's client left the network recorded at
	// login (F-001 T-20, design §5.8); BUs requiring re-authentication on a
	// network change refuse it.
	NetworkChanged bool `json:"nch,omitempty"`
}

// Errors.
var (
	ErrInvalidJWT = errors.New("authz: invalid internal JWT")
)

// KeyProvider holds the internal JWT keys: one signing key (gateway) and
// every key still valid for verification (rotation). The local provider
// reads PEM files; KMS and Vault providers implement the same interface
// (F-001 T-41).
type KeyProvider interface {
	SigningKey() (kid string, key *ecdsa.PrivateKey, err error)
	VerificationKey(kid string) (*ecdsa.PublicKey, error)
}

// DBContextHash is the "dbc" claim for a DB context token.
func DBContextHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

var b64 = base64.RawURLEncoding

// MintJWT signs claims for audience with the provider's signing key. The
// caller sets Subject, ScopeVersion, AuthTime and DBContext; issuer, times
// and ID are filled here.
func MintJWT(kp KeyProvider, c Claims, audience string, ttl time.Duration, now time.Time) (string, error) {
	if ttl <= 0 || ttl > MaxJWTTTL {
		return "", fmt.Errorf("authz: JWT TTL %v must be in (0, %v]", ttl, MaxJWTTTL)
	}
	if c.Subject == "" || audience == "" || c.DBContext == "" {
		return "", errors.New("authz: subject, audience and DB context hash are required")
	}
	kid, key, err := kp.SigningKey()
	if err != nil {
		return "", err
	}
	if key.Curve != elliptic.P256() {
		return "", errors.New("authz: JWT signing key must be ECDSA P-256")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	c.Issuer, c.Audience, c.IssuedAt, c.Expiry, c.ID = JWTIssuer, audience, now.Unix(), now.Add(ttl).Unix(), hex.EncodeToString(jti)
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64) // JWS ES256: R || S, 32 bytes each
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}

// VerifyJWT checks an internal JWT for audience and returns its claims. It
// accepts only ES256 with a known key, the gateway issuer, the audience, a
// lifetime of at most MaxJWTTTL and an unexpired token (30 s leeway).
func VerifyJWT(kp KeyProvider, token, audience string, now time.Time) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("%w: malformed", ErrInvalidJWT)
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("%w: header", ErrInvalidJWT)
	}
	var hdr struct {
		Alg, Typ, Kid string
	}
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr.Alg != "ES256" || hdr.Kid == "" {
		return c, fmt.Errorf("%w: only ES256 with a key id is accepted", ErrInvalidJWT)
	}
	pub, err := kp.VerificationKey(hdr.Kid)
	if err != nil {
		return c, fmt.Errorf("%w: key %q: %w", ErrInvalidJWT, hdr.Kid, err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return c, fmt.Errorf("%w: signature", ErrInvalidJWT)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return c, fmt.Errorf("%w: signature does not verify", ErrInvalidJWT)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("%w: payload", ErrInvalidJWT)
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return c, fmt.Errorf("%w: claims", ErrInvalidJWT)
	}
	switch {
	case c.Issuer != JWTIssuer:
		return c, fmt.Errorf("%w: issuer", ErrInvalidJWT)
	case c.Audience != audience:
		return c, fmt.Errorf("%w: audience %q", ErrInvalidJWT, c.Audience)
	case c.Subject == "" || c.DBContext == "":
		return c, fmt.Errorf("%w: subject or DB context missing", ErrInvalidJWT)
	case c.Expiry-c.IssuedAt > int64(MaxJWTTTL/time.Second) || c.Expiry <= c.IssuedAt:
		return c, fmt.Errorf("%w: lifetime", ErrInvalidJWT)
	case now.Unix() >= c.Expiry+int64(jwtLeeway/time.Second):
		return c, fmt.Errorf("%w: expired", ErrInvalidJWT)
	case now.Unix()+int64(jwtLeeway/time.Second) < c.IssuedAt:
		return c, fmt.Errorf("%w: issued in the future", ErrInvalidJWT)
	}
	return c, nil
}

// LocalKeys is the local-file key provider: every *.pem file in a directory
// is a key named by its file name (without .pem). The newest file (by name,
// e.g. "2026-10-28.pem") signs; all verify, so rotation adds a new file and
// removes the old one after the longest TTL. A directory may hold only
// public keys (services that verify only).
type LocalKeys struct {
	signKID string
	sign    *ecdsa.PrivateKey
	verify  map[string]*ecdsa.PublicKey
}

// LoadLocalKeys reads the keys in dir.
func LoadLocalKeys(dir string) (*LocalKeys, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	lk := &LocalKeys{verify: map[string]*ecdsa.PublicKey{}}
	for _, f := range files {
		kid := strings.TrimSuffix(filepath.Base(f), ".pem")
		if !keyIDRE.MatchString(kid) {
			return nil, fmt.Errorf("authz: key file %s: name must match %s", f, keyIDRE)
		}
		b, err := os.ReadFile(f) // #nosec G304 -- mounted key directory
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("authz: %s is not PEM", f)
		}
		switch blk.Type {
		case "EC PRIVATE KEY", "PRIVATE KEY":
			k, err := parsePrivate(blk)
			if err != nil {
				return nil, fmt.Errorf("authz: %s: %w", f, err)
			}
			lk.signKID, lk.sign = kid, k
			lk.verify[kid] = &k.PublicKey
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(blk.Bytes)
			ek, ok := k.(*ecdsa.PublicKey)
			if err != nil || !ok || ek.Curve != elliptic.P256() {
				return nil, fmt.Errorf("authz: %s: want an ECDSA P-256 public key", f)
			}
			lk.verify[kid] = ek
		default:
			return nil, fmt.Errorf("authz: %s: unexpected PEM %s", f, blk.Type)
		}
	}
	if len(lk.verify) == 0 {
		return nil, fmt.Errorf("authz: no JWT keys in %s", dir)
	}
	return lk, nil
}

func parsePrivate(blk *pem.Block) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		if k.Curve != elliptic.P256() {
			return nil, errors.New("want ECDSA P-256")
		}
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("want ECDSA P-256")
	}
	return ek, nil
}

// SigningKey implements KeyProvider.
func (lk *LocalKeys) SigningKey() (string, *ecdsa.PrivateKey, error) {
	if lk.sign == nil {
		return "", nil, errors.New("authz: no JWT signing key (verification-only key directory)")
	}
	return lk.signKID, lk.sign, nil
}

// VerificationKey implements KeyProvider.
func (lk *LocalKeys) VerificationKey(kid string) (*ecdsa.PublicKey, error) {
	k, ok := lk.verify[kid]
	if !ok {
		return nil, errors.New("unknown key id")
	}
	return k, nil
}

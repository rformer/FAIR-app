// Package authn hands authenticated logins from the iam service to the
// gateway (F-001 T-15; design §5.1). The iam service validates the IdP's
// response (SAML: internal/authn/saml; OIDC: T-16) and answers the gateway
// with a login ticket in the TicketHeader response header: a compact JWS
// (ES256) signed with iam's key, valid for 60 seconds. The gateway honours
// the header only on the authentication routes it forwards, verifies the
// ticket with iam's public key, records its ID so it is redeemed once,
// creates the session and sets the cookie. The ticket never reaches the
// browser, and only iam can issue one.
package authn

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

// TicketHeader carries a login ticket from iam to the gateway.
const TicketHeader = "X-Fair-Login-Ticket"

// TicketTTL is a ticket's lifetime.
const TicketTTL = 60 * time.Second

const (
	ticketType     = "fair-login+jwt"
	ticketIssuer   = "fair-iam"
	ticketAudience = "fair-gateway"
)

// ErrTicket means the ticket is malformed, forged, expired or not for us.
var ErrTicket = errors.New("authn: invalid login ticket")

// Ticket is an authenticated login.
type Ticket struct {
	ID         string         `json:"jti"`
	Issuer     string         `json:"iss"`
	Audience   string         `json:"aud"`
	UserID     string         `json:"sub"`
	AuthMethod string         `json:"amr"` // saml, oidc
	IDPID      string         `json:"idp"`
	MFA        map[string]any `json:"mfa,omitempty"` // the evidence the IdP sent (T-18 applies the rule)
	AuthTime   int64          `json:"auth_time"`     // the IdP's authentication time (F-015 T-24b)
	ReturnTo   string         `json:"return_to"`     // a local path
	IssuedAt   int64          `json:"iat"`
	Expiry     int64          `json:"exp"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

var b64 = base64.RawURLEncoding

// IssueTicket signs t (ID, issuer, audience and times are set here).
func IssueTicket(kp authz.KeyProvider, t Ticket, now time.Time) (string, error) {
	kid, key, err := kp.SigningKey()
	if err != nil {
		return "", err
	}
	if t.UserID == "" || t.AuthMethod == "" {
		return "", errors.New("authn: a ticket needs a user and an authentication method")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	id[6], id[8] = (id[6]&0x0f)|0x40, (id[8]&0x3f)|0x80
	t.ID = fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
	t.Issuer, t.Audience, t.IssuedAt, t.Expiry = ticketIssuer, ticketAudience, now.Unix(), now.Add(TicketTTL).Unix()
	h, _ := json.Marshal(header{Alg: "ES256", Typ: ticketType, Kid: kid})
	p, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}

// VerifyTicket checks a ticket's signature, type, issuer, audience and
// times. It does not record the ID: the caller redeems it once.
func VerifyTicket(kp authz.KeyProvider, tok string, now time.Time) (Ticket, error) {
	var t Ticket
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 8192 {
		return t, fmt.Errorf("%w: malformed", ErrTicket)
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(sig) != 64 {
		return t, fmt.Errorf("%w: malformed", ErrTicket)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "ES256" || h.Typ != ticketType {
		return t, fmt.Errorf("%w: not an ES256 login ticket", ErrTicket)
	}
	pub, err := kp.VerificationKey(h.Kid)
	if err != nil {
		return t, fmt.Errorf("%w: unknown key", ErrTicket)
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return t, fmt.Errorf("%w: bad signature", ErrTicket)
	}
	if err := json.Unmarshal(pb, &t); err != nil {
		return Ticket{}, fmt.Errorf("%w: malformed claims", ErrTicket)
	}
	switch {
	case t.Issuer != ticketIssuer || t.Audience != ticketAudience:
		return Ticket{}, fmt.Errorf("%w: wrong issuer or audience", ErrTicket)
	case t.Expiry-t.IssuedAt > int64(TicketTTL/time.Second):
		return Ticket{}, fmt.Errorf("%w: lifetime too long", ErrTicket)
	case now.Unix() >= t.Expiry || now.Add(5*time.Second).Unix() < t.IssuedAt:
		return Ticket{}, fmt.Errorf("%w: expired or not yet valid", ErrTicket)
	case t.ID == "" || t.UserID == "":
		return Ticket{}, fmt.Errorf("%w: no id or subject", ErrTicket)
	}
	return t, nil
}

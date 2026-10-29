// Package oidc is the platform's OpenID Connect relying party (F-001 T-16;
// AC-01, AC-04; design §5.1): authorization code with PKCE (S256), state
// and nonce. ID tokens are verified by coreos/go-oidc against the IdP's
// JWKS (fetched and cached from jwks_uri, or configured inline for
// air-gapped installs) with FIPS-only algorithms (RS/PS/ES 256-512; no HMAC,
// no "none"); around it this package checks the nonce, azp when the token
// has several audiences, iat and auth_time within ±2 minutes, and that the
// subject claim is present. State, nonce and verifier are stored server-side
// and consumed once. The IdP's endpoints come from its configuration, never
// from discovery at login time.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// Limits.
const (
	StateTTL = 10 * time.Minute
	Skew     = 2 * time.Minute
)

// SigningAlgs are the ID token algorithms accepted (FIPS 140).
var SigningAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// Errors.
var (
	// ErrInvalid: the login is refused; the wrapped error says why.
	ErrInvalid = errors.New("oidc: login refused")
	// ErrUnknownState: no started login with that state (Store.ConsumeState).
	ErrUnknownState = errors.New("oidc: unknown state")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// IDP is a configured OIDC identity provider.
type IDP struct {
	ID           string
	Issuer       string
	AuthURL      string
	TokenURL     string
	JWKSURL      string          // or
	JWKS         json.RawMessage // inline keys (air-gapped)
	ClientID     string
	ClientSecret string
	Scopes       []string
	SubjectClaim string // the claim that is the user's external id: sub (default), oid, email, ...
}

// Started is a login in progress.
type Started struct {
	State, Nonce, Verifier, ReturnTo string
}

// Store keeps started logins (the database: shared by every replica).
type Store interface {
	SaveState(ctx context.Context, idpID string, s Started, expires time.Time) error
	// ConsumeState returns and deletes the started login; ErrUnknownState
	// when there is none (or it expired, or was used).
	ConsumeState(ctx context.Context, idpID, state string) (Started, error)
}

// RP is this relying party.
type RP struct {
	RedirectURL func(idpID string) string // https://<origin>/api/v1/auth/oidc/<idp>/callback
	Store       Store
	HTTP        *http.Client // to the IdP; default: TLS 1.2+, 10 s timeout
	Now         func() time.Time
	keys        keyCache
}

// Login is a verified ID token.
type Login struct {
	ExternalID string // the subject claim's value
	Subject    string
	Email      string
	// EmailVerified is the email_verified claim (nil when absent; some IdPs
	// send it as a string).
	EmailVerified *bool
	Name          string // the name claim
	AMR           []string
	ACR           string
	AuthTime      *time.Time
	ReturnTo      string
}

func (rp *RP) now() time.Time {
	if rp.Now != nil {
		return rp.Now()
	}
	return time.Now()
}

func (rp *RP) client() *http.Client {
	if rp.HTTP != nil {
		return rp.HTTP
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 10 * time.Second, Transport: t}
}

func (rp *RP) oauth(idp IDP) *oauth2.Config {
	scopes := idp.Scopes
	if !slices.Contains(scopes, gooidc.ScopeOpenID) {
		scopes = append([]string{gooidc.ScopeOpenID}, scopes...)
	}
	return &oauth2.Config{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURL: rp.RedirectURL(idp.ID), Scopes: scopes,
		Endpoint: oauth2.Endpoint{AuthURL: idp.AuthURL, TokenURL: idp.TokenURL, AuthStyle: oauth2.AuthStyleInHeader}}
}

func random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Start begins a login: the URL to send the browser to. returnTo must
// already be a local path (the caller checks it).
func (rp *RP) Start(ctx context.Context, idp IDP, returnTo string) (string, error) {
	s := Started{Verifier: oauth2.GenerateVerifier(), ReturnTo: returnTo}
	var err error
	if s.State, err = random(); err != nil {
		return "", err
	}
	if s.Nonce, err = random(); err != nil {
		return "", err
	}
	if err := rp.Store.SaveState(ctx, idp.ID, s, rp.now().Add(StateTTL)); err != nil {
		return "", err
	}
	return rp.oauth(idp).AuthCodeURL(s.State, gooidc.Nonce(s.Nonce), oauth2.S256ChallengeOption(s.Verifier)), nil
}

// Callback completes a login from the redirect's query: the state is
// consumed, the code exchanged with the PKCE verifier, and the ID token
// verified.
func (rp *RP) Callback(ctx context.Context, idp IDP, state, code, idpError string) (Login, error) {
	if state == "" {
		return Login{}, invalid("no state")
	}
	started, err := rp.Store.ConsumeState(ctx, idp.ID, state)
	if errors.Is(err, ErrUnknownState) {
		return Login{}, invalid("unknown, used or expired state")
	}
	if err != nil {
		return Login{}, err
	}
	if idpError != "" {
		return Login{}, invalid("the IdP returned %q", idpError)
	}
	if code == "" {
		return Login{}, invalid("no code")
	}
	hctx := context.WithValue(ctx, oauth2.HTTPClient, rp.client())
	tok, err := rp.oauth(idp).Exchange(hctx, code, oauth2.VerifierOption(started.Verifier))
	if err != nil {
		return Login{}, invalid("code exchange: %v", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Login{}, invalid("no id_token")
	}
	keys, err := rp.keySet(hctx, idp)
	if err != nil {
		return Login{}, err
	}
	now := rp.now()
	v := gooidc.NewVerifier(idp.Issuer, keys, &gooidc.Config{ClientID: idp.ClientID, SupportedSigningAlgs: SigningAlgs,
		Now: func() time.Time { return now.Add(-Skew) }}) // expiry with the skew in the token's favour
	idt, err := v.Verify(gooidc.ClientContext(ctx, rp.client()), raw)
	if err != nil {
		return Login{}, invalid("ID token: %v", err)
	}
	if idt.Nonce != started.Nonce {
		return Login{}, invalid("nonce mismatch")
	}
	var c struct {
		AZP      string   `json:"azp"`
		Email    string   `json:"email"`
		Verified any      `json:"email_verified"`
		Name     string   `json:"name"`
		AMR      []string `json:"amr"`
		ACR      string   `json:"acr"`
		AuthTime *int64   `json:"auth_time"`
	}
	if err := idt.Claims(&c); err != nil {
		return Login{}, invalid("claims: %v", err)
	}
	if len(idt.Audience) > 1 && c.AZP != idp.ClientID {
		return Login{}, invalid("several audiences and azp %q", c.AZP)
	}
	if c.AZP != "" && c.AZP != idp.ClientID {
		return Login{}, invalid("azp %q", c.AZP)
	}
	if idt.IssuedAt.After(now.Add(Skew)) {
		return Login{}, invalid("issued in the future")
	}
	login := Login{Subject: idt.Subject, Email: c.Email, Name: c.Name, AMR: c.AMR, ACR: c.ACR, ReturnTo: started.ReturnTo}
	switch v := c.Verified.(type) {
	case bool:
		login.EmailVerified = &v
	case string:
		b := strings.EqualFold(v, "true")
		login.EmailVerified = &b
	}
	if c.AuthTime != nil {
		at := time.Unix(*c.AuthTime, 0)
		if at.After(now.Add(Skew)) {
			return Login{}, invalid("auth_time in the future")
		}
		login.AuthTime = &at
	}
	claim := idp.SubjectClaim
	if claim == "" {
		claim = "sub"
	}
	var all map[string]any
	if err := idt.Claims(&all); err != nil {
		return Login{}, invalid("claims: %v", err)
	}
	ext, _ := all[claim].(string)
	if ext == "" {
		return Login{}, invalid("no %q claim", claim)
	}
	login.ExternalID = ext
	return login, nil
}

// keySet is the IdP's keys: inline (air-gapped) or its JWKS URI, cached
// per URI so keys are fetched once and refreshed on rotation by go-oidc.
func (rp *RP) keySet(ctx context.Context, idp IDP) (gooidc.KeySet, error) {
	if len(idp.JWKS) > 0 {
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(idp.JWKS, &set); err != nil {
			return nil, fmt.Errorf("oidc: IdP %s inline JWKS: %w", idp.ID, err)
		}
		s := &gooidc.StaticKeySet{}
		for _, k := range set.Keys {
			if k.IsPublic() && (k.Use == "" || k.Use == "sig") {
				s.PublicKeys = append(s.PublicKeys, k.Key)
			}
		}
		if len(s.PublicKeys) == 0 {
			return nil, fmt.Errorf("oidc: IdP %s inline JWKS has no public signing key", idp.ID)
		}
		return s, nil
	}
	if idp.JWKSURL == "" {
		return nil, fmt.Errorf("oidc: IdP %s has neither jwks_uri nor jwks", idp.ID)
	}
	return rp.keys.get(gooidc.ClientContext(ctx, rp.client()), idp.JWKSURL), nil
}

// Package oidctest is a test OpenID Connect provider (F-001 T-16): a token
// endpoint that checks the client's credentials and PKCE, a JWKS endpoint,
// and ID tokens whose claims and signature tests change as an attacker
// would. Test use only.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Provider is a running test IdP.
type Provider struct {
	Server   *httptest.Server
	Issuer   string
	ClientID string
	Secret   string
	Alg      string // signing algorithm of ID tokens: RS256 (default), PS256, ES256, HS256, none
	// Claims changes each ID token's claims before signing (nil value: delete).
	Claims  func(c map[string]any)
	Foreign bool // sign with a key the JWKS does not publish

	rsaKey, foreign *rsa.PrivateKey
	ecKey           *ecdsa.PrivateKey
	mu              sync.Mutex
	codes           map[string]grant
}

type grant struct {
	nonce, challenge, redirect, subject string
	extra                               map[string]any
}

// New starts a provider for one client.
func New(clientID, secret string) (*Provider, error) {
	p := &Provider{ClientID: clientID, Secret: secret, Alg: "RS256", codes: map[string]grant{}}
	var err error
	if p.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	}
	if p.foreign, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	}
	if p.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.JWKS())
	})
	p.Server = httptest.NewServer(mux)
	p.Issuer = p.Server.URL
	return p, nil
}

// Close stops the provider.
func (p *Provider) Close() { p.Server.Close() }

// AuthURL is the authorization endpoint (simulated by Authorize).
func (p *Provider) AuthURL() string { return p.Issuer + "/authorize" }

// TokenURL is the token endpoint.
func (p *Provider) TokenURL() string { return p.Issuer + "/token" }

// JWKSURL is the key set endpoint.
func (p *Provider) JWKSURL() string { return p.Issuer + "/jwks" }

// JWKS is the published key set.
func (p *Provider) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.rsaKey.PublicKey, KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"},
		{Key: &p.ecKey.PublicKey, KeyID: "ec-1", Algorithm: "ES256", Use: "sig"},
	}}
}

// Authorize plays the user signing in at the authorization URL: it returns
// the code and state the IdP redirects back with.
func (p *Provider) Authorize(authURL, subject string, extra map[string]any) (code, state string, err error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code = base64.RawURLEncoding.EncodeToString(b)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), subject: subject, extra: extra}
	return code, q.Get("state"), nil
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != url.QueryEscape(p.ClientID) || secret != url.QueryEscape(p.Secret) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	p.mu.Lock()
	g, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code")) // codes are single use
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	now := time.Now()
	claims := map[string]any{"iss": p.Issuer, "sub": g.subject, "aud": p.ClientID, "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "nonce": g.nonce, "auth_time": now.Add(-30 * time.Second).Unix(), "amr": []string{"pwd", "mfa"},
		"email": g.subject}
	for k, v := range g.extra {
		claims[k] = v
	}
	if p.Claims != nil {
		p.Claims(claims)
	}
	for k, v := range claims {
		if v == nil {
			delete(claims, k)
		}
	}
	idt, err := p.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idt})
}

func (p *Provider) sign(claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if p.Alg == "none" {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		return h + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
	}
	var key jose.SigningKey
	kid := "rsa-1"
	switch p.Alg {
	case "ES256":
		key, kid = jose.SigningKey{Algorithm: jose.ES256, Key: p.ecKey}, "ec-1"
	case "PS256":
		key = jose.SigningKey{Algorithm: jose.PS256, Key: p.rsaKey}
	case "HS256":
		key, kid = jose.SigningKey{Algorithm: jose.HS256, Key: []byte(p.Secret)}, "hs-1"
	default:
		key = jose.SigningKey{Algorithm: jose.RS256, Key: p.rsaKey}
	}
	if p.Foreign {
		key, kid = jose.SigningKey{Algorithm: jose.RS256, Key: p.foreign}, "rsa-1" // same kid, another key
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid)
	s, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", err
	}
	obj, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/authn/oidc/oidctest"
)

// F-001 T-16 (AC-01, AC-04): the OIDC relying party against a test
// provider, and its negative corpus.

type memStore struct {
	mu sync.Mutex
	m  map[string]Started
}

func (s *memStore) SaveState(_ context.Context, idp string, st Started, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[idp+"/"+st.State] = st
	return nil
}

func (s *memStore) ConsumeState(_ context.Context, idp, state string) (Started, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[idp+"/"+state]
	if !ok {
		return Started{}, ErrUnknownState
	}
	delete(s.m, idp+"/"+state)
	return st, nil
}

const idpID = "22222222-2222-4222-8222-222222222222"

type fixture struct {
	p   *oidctest.Provider
	rp  *RP
	idp IDP
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := oidctest.New("fair-platform", "client-secret-0123456789-abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	f := &fixture{p: p, rp: &RP{RedirectURL: func(id string) string { return "https://fair.example.test/api/v1/auth/oidc/" + id + "/callback" },
		Store: &memStore{m: map[string]Started{}}, HTTP: p.Server.Client()}}
	f.idp = IDP{ID: idpID, Issuer: p.Issuer, AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), JWKSURL: p.JWKSURL(),
		ClientID: "fair-platform", ClientSecret: "client-secret-0123456789-abcdefghijklmnop", Scopes: []string{"email"}}
	return f
}

// login runs start → IdP → callback.
func (f *fixture) login(t *testing.T, subject string, extra map[string]any) (Login, error) {
	t.Helper()
	u, err := f.rp.Start(context.Background(), f.idp, "/posture")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "code_challenge_method=S256") || !strings.Contains(u, "nonce=") || !strings.Contains(u, "scope=openid+email") {
		t.Fatalf("authorization URL %s", u)
	}
	code, state, err := f.p.Authorize(u, subject, extra)
	if err != nil {
		t.Fatal(err)
	}
	return f.rp.Callback(context.Background(), f.idp, state, code, "")
}

func TestLoginAccepted(t *testing.T) {
	for _, alg := range []string{"RS256", "PS256", "ES256"} {
		f := newFixture(t)
		f.p.Alg = alg
		l, err := f.login(t, "user@example.test", nil)
		if err != nil || l.ExternalID != "user@example.test" || l.ReturnTo != "/posture" || l.AuthTime == nil ||
			strings.Join(l.AMR, ",") != "pwd,mfa" {
			t.Errorf("%s: %+v %v", alg, l, err)
		}
	}
	// Air-gapped: the IdP's keys configured inline, no JWKS URI.
	f := newFixture(t)
	jwks, _ := json.Marshal(f.p.JWKS())
	f.idp.JWKSURL, f.idp.JWKS = "", jwks
	if _, err := f.login(t, "user@example.test", nil); err != nil {
		t.Errorf("inline JWKS: %v", err)
	}
	// Another subject claim (e.g. Entra's oid, which SCIM provisions).
	f = newFixture(t)
	f.idp.SubjectClaim = "oid"
	if l, err := f.login(t, "pairwise-sub", map[string]any{"oid": "0f6c-entra-object-id"}); err != nil || l.ExternalID != "0f6c-entra-object-id" {
		t.Errorf("subject claim oid: %+v %v", l, err)
	}
}

// reasons pins why the security-critical cases are refused.
var reasons = map[string]string{
	"wrong nonce": "nonce mismatch", "no nonce": "nonce mismatch", "HS256 with the secret": `unexpected signature algorithm "HS256"`,
	"alg none": `unexpected signature algorithm "none"`, "signed by an unknown key": "failed to verify signature",
	"several audiences, no azp": "several audiences", "azp of another client": `azp "other"`, "wrong audience": "expected audience",
	"wrong issuer": "different provider", "expired beyond the skew": "token is expired", "wrong client secret": "401",
}

func TestNegativeCorpus(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		setup func(f *fixture)
		extra map[string]any
	}{
		"wrong nonce":               {func(f *fixture) { f.p.Claims = func(c map[string]any) { c["nonce"] = "attacker" } }, nil},
		"no nonce":                  {func(f *fixture) { f.p.Claims = func(c map[string]any) { c["nonce"] = nil } }, nil},
		"wrong audience":            {nil, map[string]any{"aud": "another-client"}},
		"several audiences, no azp": {nil, map[string]any{"aud": []string{"fair-platform", "other"}}},
		"azp of another client":     {nil, map[string]any{"azp": "other"}},
		"wrong issuer":              {nil, map[string]any{"iss": "https://evil.example.test"}},
		"expired beyond the skew":   {nil, map[string]any{"exp": now.Add(-3 * time.Minute).Unix()}},
		"issued in the future":      {nil, map[string]any{"iat": now.Add(5 * time.Minute).Unix()}},
		"auth_time in the future":   {nil, map[string]any{"auth_time": now.Add(5 * time.Minute).Unix()}},
		"HS256 with the secret":     {func(f *fixture) { f.p.Alg = "HS256" }, nil},
		"alg none":                  {func(f *fixture) { f.p.Alg = "none" }, nil},
		"signed by an unknown key":  {func(f *fixture) { f.p.Foreign = true }, nil},
		"no subject claim":          {func(f *fixture) { f.idp.SubjectClaim = "oid" }, nil},
		"wrong client secret":       {func(f *fixture) { f.idp.ClientSecret = "guess" }, nil},
		"inline JWKS without the key": {func(f *fixture) {
			f.idp.JWKSURL, f.idp.JWKS = "", json.RawMessage(`{"keys":[]}`)
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			_, err := f.login(t, "user@example.test", c.extra)
			if err == nil {
				t.Fatal("accepted")
			}
			if want := reasons[name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("refused for another reason than %q: %v", want, err)
			}
			t.Log(err)
		})
	}
}

func TestStateAndCode(t *testing.T) {
	f := newFixture(t)
	u, _ := f.rp.Start(context.Background(), f.idp, "/")
	code, state, _ := f.p.Authorize(u, "user@example.test", nil)
	// The IdP reports an error: refused, and the state is spent.
	if _, err := f.rp.Callback(context.Background(), f.idp, state, "", "access_denied"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("IdP error: %v", err)
	}
	if _, err := f.rp.Callback(context.Background(), f.idp, state, code, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state reused after an error: %v", err)
	}
	// Unknown or missing state, and a state used twice.
	for _, s := range []string{"", "forged-state-0123456789012345678901234567"} {
		if _, err := f.rp.Callback(context.Background(), f.idp, s, code, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("state %q: %v", s, err)
		}
	}
	u, _ = f.rp.Start(context.Background(), f.idp, "/")
	code, state, _ = f.p.Authorize(u, "user@example.test", nil)
	if _, err := f.rp.Callback(context.Background(), f.idp, state, code, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rp.Callback(context.Background(), f.idp, state, code, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("callback replayed: %v", err)
	}
	// A code issued for another login (another PKCE challenge) cannot complete this one.
	u1, _ := f.rp.Start(context.Background(), f.idp, "/")
	u2, _ := f.rp.Start(context.Background(), f.idp, "/")
	code1, _, _ := f.p.Authorize(u1, "user@example.test", nil)
	_, state2, _ := f.p.Authorize(u2, "user@example.test", nil)
	if _, err := f.rp.Callback(context.Background(), f.idp, state2, code1, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("code swapped between logins: %v", err)
	}
}

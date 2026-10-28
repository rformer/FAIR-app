package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

type memStore struct {
	mu   sync.Mutex
	rows map[string]*struct {
		hash string
		resp *StoredResponse
	}
}

func (m *memStore) Begin(_ context.Context, user, key, hash string) (*StoredResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := user + "/" + key
	r, ok := m.rows[k]
	switch {
	case !ok:
		m.rows[k] = &struct {
			hash string
			resp *StoredResponse
		}{hash: hash}
		return nil, nil
	case r.hash != hash:
		return nil, ErrIdempotencyMismatch
	case r.resp == nil:
		return nil, ErrIdempotencyInProgress
	}
	return r.resp, nil
}

func (m *memStore) Complete(_ context.Context, user, key string, resp StoredResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[user+"/"+key].resp = &resp
	return nil
}

func (m *memStore) Abandon(_ context.Context, user, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, user+"/"+key)
	return nil
}

func jwtKeys(t *testing.T) *authz.LocalKeys {
	t.Helper()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "k1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	lk, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	return lk
}

func TestAuthenticate(t *testing.T) {
	kp := jwtKeys(t)
	var got authz.Principal
	h := Authenticate(kp, "posture", nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r.Context())
	}))
	dbc := "v1.k1.u-1.3.9999999999.n.mac"
	tok, err := authz.MintJWT(kp, authz.Claims{Subject: "u-1", ScopeVersion: 3, AuthTime: time.Now().Unix(), DBContext: authz.DBContextHash(dbc)}, "posture", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	do := func(auth, ctxTok string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if ctxTok != "" {
			req.Header.Set(DBContextHeader, ctxTok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("Bearer "+tok, dbc); code != http.StatusOK || got.UserID != "u-1" || got.ScopeVersion != 3 || got.DBToken != dbc || got.AuthTime.IsZero() {
		t.Fatalf("valid request: %d %+v", code, got)
	}
	other, _ := authz.MintJWT(kp, authz.Claims{Subject: "u-1", DBContext: authz.DBContextHash(dbc)}, "iam", time.Minute, time.Now())
	for name, c := range map[string][2]string{
		"no token":                  {"", dbc},
		"no DB context":             {"Bearer " + tok, ""},
		"another DB context":        {"Bearer " + tok, dbc + "x"},
		"token for another service": {"Bearer " + other, dbc},
		"not bearer":                {"Basic " + tok, dbc},
	} {
		if code := do(c[0], c[1]); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
}

func TestIdempotent(t *testing.T) {
	var runs atomic.Int32
	h := Idempotent(&memStore{rows: map[string]*struct {
		hash string
		resp *StoredResponse
	}{}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := runs.Add(1)
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"run":%d}`, n)
	}))
	do := func(method, path, user, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(WithPrincipal(context.Background(), authz.Principal{UserID: user}), method, path, strings.NewReader(body))
		if key != "" {
			req.Header.Set(IdempotencyHeader, key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do(http.MethodPost, "/a", "u", "", "{}"); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing key: %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/a", "u", "", ""); rec.Code != http.StatusCreated {
		t.Fatalf("GET needs no key: %d", rec.Code)
	}
	first := do(http.MethodPost, "/a", "u", "key-00000001", `{"v":1}`)
	again := do(http.MethodPost, "/a", "u", "key-00000001", `{"v":1}`)
	if first.Code != http.StatusCreated || again.Code != http.StatusCreated || again.Body.String() != first.Body.String() ||
		again.Header().Get("Idempotent-Replayed") != "true" || runs.Load() != 2 {
		t.Fatalf("replay: %d %s / %d %s, %d runs", first.Code, first.Body, again.Code, again.Body, runs.Load())
	}
	if rec := do(http.MethodPost, "/a", "u", "key-00000001", `{"v":2}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("same key, other request: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/a", "other-user", "key-00000001", `{"v":1}`); rec.Code != http.StatusCreated || runs.Load() != 3 {
		t.Fatalf("keys are per user: %d", rec.Code)
	}
	// A server error frees the key: the retry runs.
	do(http.MethodPost, "/fail", "u", "key-00000002", "{}")
	do(http.MethodPost, "/fail", "u", "key-00000002", "{}")
	if runs.Load() != 5 {
		t.Fatalf("retry after a server error did not run: %d runs", runs.Load())
	}
}

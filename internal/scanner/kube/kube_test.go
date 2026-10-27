package kube

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is a TLS API server that records every request.
type fakeAPI struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string
}

func newFakeAPI(t *testing.T, h http.HandlerFunc) (*fakeAPI, *Client, string) {
	t.Helper()
	f := &fakeAPI{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+r.Header.Get("Authorization"))
		f.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Host: f.srv.URL, TokenFile: tok, CAFile: filepath.Join(dir, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	return f, c, tok
}

func (f *fakeAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func TestListPaginatesWithGETOnly(t *testing.T) {
	f, c, tok := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continue") == "" {
			_, _ = fmt.Fprint(w, `{"metadata":{"resourceVersion":"10","continue":"p2"},"items":[{"metadata":{"name":"a","namespace":"fair-platform","labels":{"x":"1"}}}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"metadata":{"resourceVersion":"11"},"items":[{"metadata":{"name":"b","namespace":"fair-platform"},"spec":{"k":1}}]}`)
	})
	objs, rv, err := c.List(context.Background(), Pods, "fair-platform")
	if err != nil || len(objs) != 2 || rv != "11" || objs[0].Metadata.Labels["x"] != "1" || !strings.Contains(string(objs[1].Raw), `"spec"`) {
		t.Fatalf("list: %+v %s %v", objs, rv, err)
	}
	// The token is re-read for every request (projected tokens rotate).
	if err := os.WriteFile(tok, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.List(context.Background(), ClusterRoles, ""); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	want := []string{
		"GET /api/v1/namespaces/fair-platform/pods?limit=500 Bearer tok-1",
		"GET /api/v1/namespaces/fair-platform/pods?continue=p2&limit=500 Bearer tok-1",
		"GET /apis/rbac.authorization.k8s.io/v1/clusterroles?limit=500 Bearer tok-2",
	}
	if strings.Join(reqs[:3], "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(reqs, "\n"))
	}
}

func TestSecretsRefusedBeforeAnyRequest(t *testing.T) {
	f, c, _ := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, `{"items":[]}`) })
	secrets := Resource{Version: "v1", Plural: "secrets", Namespaced: true}
	if _, _, err := c.List(context.Background(), secrets, "fair-platform"); !errors.Is(err, ErrSecretsRefused) {
		t.Fatalf("list secrets: %v", err)
	}
	if err := c.Watch(context.Background(), secrets, "", "", func(Event) error { return nil }); !errors.Is(err, ErrSecretsRefused) {
		t.Fatalf("watch secrets: %v", err)
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("%d requests made", n)
	}
}

func TestErrorsMapped(t *testing.T) {
	_, c, _ := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "nodes"):
			http.Error(w, `{"reason":"Forbidden"}`, http.StatusForbidden)
		case strings.Contains(r.URL.Path, "externalsecrets"):
			http.NotFound(w, r)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	})
	ctx := context.Background()
	if _, _, err := c.List(ctx, Nodes, ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("403: %v", err)
	}
	if _, _, err := c.List(ctx, ExternalSecrets, "fair-platform"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	if _, _, err := c.List(ctx, Pods, ""); err == nil || errors.Is(err, ErrForbidden) {
		t.Errorf("500: %v", err)
	}
}

func TestWatchStreamsEvents(t *testing.T) {
	_, c, _ := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "1" || r.URL.Query().Get("resourceVersion") != "10" {
			http.Error(w, "bad watch", http.StatusBadRequest)
			return
		}
		enc := json.NewEncoder(w)
		_ = enc.Encode(map[string]any{"type": "ADDED", "object": map[string]any{"metadata": map[string]any{"name": "np1"}}})
		_ = enc.Encode(map[string]any{"type": "DELETED", "object": map[string]any{"metadata": map[string]any{"name": "np1"}}})
	})
	var got []string
	err := c.Watch(context.Background(), NetworkPolicies, "fair-platform", "10", func(e Event) error {
		got = append(got, e.Type+":"+e.Object.Metadata.Name)
		return nil
	})
	if err != nil || strings.Join(got, ",") != "ADDED:np1,DELETED:np1" {
		t.Fatalf("watch: %v %v", got, err)
	}
}

func TestRequiresHTTPSAndCA(t *testing.T) {
	if _, err := New(Config{Host: "http://10.0.0.1:443", CAFile: "x"}); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, err := New(Config{Host: "https://10.0.0.1:443", CAFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing CA accepted")
	}
}

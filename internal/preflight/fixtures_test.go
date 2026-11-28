package preflight

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

// The distribution fixtures of F-015 T-28 (internal/scanner/checks/testdata),
// read as the checks' own test reads them: the platform RBAC of
// deploy/k8s/posture-scanner.yaml, then the fixture (an object annotated
// fixture/delete removes the object of that kind and name; FixtureCluster
// names the APIs the cluster does not serve), and for a pass fixture the
// reference gateway and posture workloads of deploy/k8s.

const root = "../.."

var distributions = []struct{ name, psaDefault string }{{"kind", ""}, {"openshift", ""}, {"rke2", "restricted"}}

// The fixtures' release digests.
var fixtureImages = map[string]string{
	"iam":             "ghcr.io/rformer/fair-iam@sha256:1111111111111111111111111111111111111111111111111111111111111111",
	"posture-scanner": "ghcr.io/rformer/fair-posture-scanner@sha256:2222222222222222222222222222222222222222222222222222222222222222",
	"gateway":         "ghcr.io/rformer/fair-gateway@sha256:3333333333333333333333333333333333333333333333333333333333333333",
	"posture":         "ghcr.io/rformer/fair-posture@sha256:4444444444444444444444444444444444444444444444444444444444444444",
}

func yamlFile(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(file) // #nosec G304 -- test fixtures
	if err != nil {
		t.Fatal(err)
	}
	docs, err := objreader.DecodeYAML(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return docs
}

// fixture is a distribution fixture: what the cluster serves with the
// platform applied, split into the cluster before install and the
// release's objects.
type fixture struct {
	all       []map[string]any // the objects as given (workloads not yet applied)
	notServed []kube.Resource
}

func loadFixture(t *testing.T, distro, variant string) fixture {
	t.Helper()
	type key struct{ kind, ns, name string }
	docs := map[key]map[string]any{}
	var order []key
	add := func(d map[string]any) {
		md, _ := d["metadata"].(map[string]any)
		k := key{fmt.Sprint(d["kind"]), fmt.Sprint(md["namespace"]), fmt.Sprint(md["name"])}
		if ann, _ := md["annotations"].(map[string]any); ann["fixture/delete"] == "true" {
			delete(docs, k)
			return
		}
		if _, ok := docs[k]; !ok {
			order = append(order, k)
		}
		docs[k] = d
	}
	for _, d := range yamlFile(t, filepath.Join(root, "deploy/k8s/posture-scanner.yaml")) {
		if slices.Contains(releasemanifest.RBACKinds, fmt.Sprint(d["kind"])) {
			add(d)
		}
	}
	for _, d := range yamlFile(t, filepath.Join(root, "internal/scanner/checks/testdata", distro, variant+".yaml")) {
		add(d)
	}
	if variant == "pass" {
		for _, d := range referenceWorkloads(t) {
			add(d)
		}
	}
	var f fixture
	for _, k := range order {
		d, ok := docs[k]
		if !ok {
			continue
		}
		if k.kind == "FixtureCluster" {
			for _, p := range strings.Fields(fmt.Sprint(d["notServed"])) {
				for _, r := range objreader.Resources {
					if r.Plural == p {
						f.notServed = append(f.notServed, r)
					}
				}
			}
			continue
		}
		f.all = append(f.all, d)
	}
	return f
}

// referenceWorkloads are deploy/k8s/gateway.yaml's and posture.yaml's
// Deployments (images by the fixtures' digests), Services (answering with
// good TLS) and NetworkPolicies, as rendered: objreader.Applied runs them.
func referenceWorkloads(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, c := range []string{"gateway", "posture"} {
		for _, d := range yamlFile(t, filepath.Join(root, "deploy/k8s", c+".yaml")) {
			md, _ := d["metadata"].(map[string]any)
			switch d["kind"] {
			case "NetworkPolicy":
				out = append(out, d)
			case "Service":
				md["annotations"] = map[string]any{"fixture/tls": "good"}
				out = append(out, d)
			case "Deployment":
				spec, _ := dig(d, "spec", "template", "spec").(map[string]any)
				for _, x := range spec["containers"].([]any) {
					ctr := x.(map[string]any)
					img := strings.Replace(fmt.Sprint(ctr["image"]), "ghcr.io/rformer/fair-"+c+":REPLACE_WITH_DIGEST", fixtureImages[c], 1)
					if img == ctr["image"] {
						t.Fatalf("%s: container %v is not the release's image placeholder", c, ctr["name"])
					}
					ctr["image"] = img
				}
				out = append(out, d)
			}
		}
	}
	return out
}

// platform reports whether a fixture object is the release's (created by
// the install): anything in or naming a fair-* namespace, and the
// platform's cluster-scoped RBAC.
func platform(o map[string]any) bool {
	ns := str(o, "metadata", "namespace")
	name := str(o, "metadata", "name")
	switch {
	case strings.HasPrefix(ns, "fair-"):
		return true
	case o["kind"] == "Namespace":
		return strings.HasPrefix(name, "fair-")
	case slices.Contains(releasemanifest.RBACKinds, fmt.Sprint(o["kind"])):
		return strings.HasPrefix(name, "fair-")
	}
	return false
}

func str(v any, path ...string) string {
	s, _ := dig(v, path...).(string)
	return s
}

// set serves objects as a cluster does.
func set(t *testing.T, objs []map[string]any, notServed []kube.Resource) *objreader.Set {
	t.Helper()
	s := objreader.New()
	s.NotServed(notServed...)
	for _, o := range objs {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// --- a recording API server --------------------------------------------------

// apiServer serves a set as the Kubernetes API does (lists by group,
// version, resource and namespace; watches as empty streams; 404 for what
// is not served; Secrets 403) and records every request.
type apiServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string // "METHOD path?query"
}

func newAPIServer(t *testing.T, s *objreader.Set) *apiServer {
	t.Helper()
	a := &apiServer{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.reqs = append(a.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		a.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "read-only test server", http.StatusMethodNotAllowed)
			return
		}
		res, ns, ok := resourceOf(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("watch") != "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		objs, _, err := s.List(r.Context(), res, ns)
		switch {
		case errors.Is(err, kube.ErrSecretsRefused):
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case errors.Is(err, kube.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items := make([]json.RawMessage, 0, len(objs))
		for _, o := range objs {
			items = append(items, o.Raw)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "1"}, "items": items})
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// resourceOf parses /api/v1[/namespaces/NS]/PLURAL and
// /apis/GROUP/VERSION[/namespaces/NS]/PLURAL.
func resourceOf(path string) (kube.Resource, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var group, version string
	switch {
	case len(parts) >= 3 && parts[0] == "api":
		version, parts = parts[1], parts[2:]
	case len(parts) >= 4 && parts[0] == "apis":
		group, version, parts = parts[1], parts[2], parts[3:]
	default:
		return kube.Resource{}, "", false
	}
	ns := ""
	if len(parts) == 3 && parts[0] == "namespaces" {
		ns, parts = parts[1], parts[2:]
	}
	if len(parts) != 1 {
		return kube.Resource{}, "", false
	}
	if group == "" && parts[0] == "secrets" {
		return kube.Resource{Version: version, Plural: "secrets", Namespaced: true}, ns, true
	}
	for _, r := range objreader.Resources {
		if r.Group == group && r.Version == version && r.Plural == parts[0] {
			return r, ns, true
		}
	}
	return kube.Resource{}, "", false
}

// client is the administrator's read-only kube client to the server.
func (a *apiServer) client(t *testing.T) *kube.Client {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.srv.Certificate().Raw})
	c, err := kube.New(kube.Config{Host: a.srv.URL, CAData: ca, Token: "preflight-test", UserAgent: "fairctl"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// requests returns the recorded requests.
func (a *apiServer) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reqs)
}

// readOnly fails unless every request was a GET list or watch, none of
// Secrets.
func (a *apiServer) readOnly(t *testing.T) {
	t.Helper()
	reqs := a.requests()
	if len(reqs) == 0 {
		t.Fatal("the run made no request: the cluster was not read")
	}
	for _, r := range reqs {
		method, target, _ := strings.Cut(r, " ")
		p, _, _ := strings.Cut(target, "?")
		if method != http.MethodGet || strings.HasSuffix(p, "/secrets") {
			t.Errorf("a request that is not a read: %s", r)
		}
		if _, _, ok := resourceOf(p); !ok {
			t.Errorf("a request for no list or watch: %s", r)
		}
	}
}

// --- test TLS endpoints (as the checks' fixtures) ----------------------------

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "endpoint"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, DNSNames: []string{"endpoint"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve starts an endpoint behaving as a fixture/tls annotation says.
func serve(t *testing.T, behaviour string) string {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	var cert tls.Certificate
	switch behaviour {
	case "good":
		cert = selfSigned(t, time.Now().Add(365*24*time.Hour))
	case "expiring":
		cert = selfSigned(t, time.Now().Add(10*24*time.Hour))
	case "expired":
		cert = selfSigned(t, time.Now().Add(-time.Hour))
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				switch behaviour {
				case "plaintext":
					_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				case "tls10", "weak":
					rawServer(c, behaviour)
				default:
					s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					_ = s.HandshakeContext(context.Background())
				}
			}(c)
		}
	}()
	return lis.Addr().String()
}

// rawServer answers a ClientHello for the offered version and first suite:
// "tls10" accepts TLS 1.0 hellos, "weak" TLS 1.2 hellos whatever their
// suites; anything else gets an alert.
func rawServer(c net.Conn, behaviour string) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(c, body); err != nil || body[0] != 1 {
		return
	}
	h := body[4:]
	version := binary.BigEndian.Uint16(h[0:2])
	sid := int(h[34])
	suite := binary.BigEndian.Uint16(h[35+sid+2 : 35+sid+4])
	accept := (behaviour == "tls10" && version == tls.VersionTLS10) || (behaviour == "weak" && version == tls.VersionTLS12)
	if !accept {
		_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46})
		return
	}
	sh := binary.BigEndian.AppendUint16(nil, version)
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0)
	sh = binary.BigEndian.AppendUint16(sh, suite)
	sh = append(sh, 0, 0, 0)
	hs := append([]byte{2, 0, 0, byte(len(sh))}, sh...)                                             // #nosec G115 -- a 40-byte ServerHello
	rec := append([]byte{0x16, 0x03, 0x03}, binary.BigEndian.AppendUint16(nil, uint16(len(hs)))...) // #nosec G115 -- small
	_, _ = c.Write(append(rec, hs...))
}

// routes sends each Service address of the objects to an endpoint behaving
// as its fixture/tls annotation says.
func routes(t *testing.T, objs []map[string]any) func(ctx context.Context, addr string) (net.Conn, error) {
	t.Helper()
	m := map[string]string{}
	for _, o := range objs {
		if o["kind"] != "Service" {
			continue
		}
		ports, _ := dig(o, "spec", "ports").([]any)
		for _, p := range ports {
			port := fmt.Sprint(dig(p, "port"))
			m[fmt.Sprintf("%s.%s.svc:%s", str(o, "metadata", "name"), str(o, "metadata", "namespace"), port)] =
				serve(t, str(o, "metadata", "annotations", "fixture/tls"))
		}
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		to, ok := m[addr]
		if !ok {
			return nil, fmt.Errorf("no route to %s", addr)
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", to)
	}
}

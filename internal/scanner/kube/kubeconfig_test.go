package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary doubles as an exec credential plugin.
func TestMain(m *testing.M) {
	if mode := os.Getenv("FAIR_KUBE_EXEC_HELPER"); mode != "" {
		os.Exit(execHelper(mode))
	}
	os.Exit(m.Run())
}

func execHelper(mode string) int {
	if f := os.Getenv("FAIR_KUBE_EXEC_RECORD"); f != "" {
		fh, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- the test helper's record file
		if err == nil {
			_, _ = fmt.Fprintln(fh, os.Getenv("KUBERNETES_EXEC_INFO"))
			_ = fh.Close()
		}
	}
	status := map[string]any{}
	switch mode {
	case "token":
		status["token"] = "exec-token"
		status["expirationTimestamp"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	case "cert":
		status["clientCertificateData"] = os.Getenv("FAIR_KUBE_EXEC_CERT")
		status["clientKeyData"] = os.Getenv("FAIR_KUBE_EXEC_KEY")
	case "fail":
		_, _ = fmt.Fprintln(os.Stderr, "\x1b[31msign-in expired\x1b[0m")
		return 1
	case "empty":
	}
	b, _ := json.Marshal(map[string]any{"apiVersion": ExecV1, "kind": "ExecCredential", "status": status})
	_, _ = os.Stdout.Write(b)
	return 0
}

type pki struct {
	caPEM                     []byte
	serverCert                tls.Certificate
	clientCertPEM, clientKey  []byte
	otherCertPEM, otherKeyPEM []byte
	pool                      *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, signer *x509.Certificate, signerKey *ecdsa.PrivateKey) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"kubernetes.test"}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	}
	p := &pki{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	sc, sk := issue(2, "kubernetes", x509.ExtKeyUsageServerAuth, ca, caKey)
	if p.serverCert, err = tls.X509KeyPair(sc, sk); err != nil {
		t.Fatal(err)
	}
	p.clientCertPEM, p.clientKey = issue(3, "admin", x509.ExtKeyUsageClientAuth, ca, caKey)
	// A client certificate from another CA: the server refuses it.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "other CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)
	other, _ := x509.ParseCertificate(otherDER)
	p.otherCertPEM, p.otherKeyPEM = issue(10, "admin", x509.ExtKeyUsageClientAuth, other, otherKey)
	return p
}

// apiServer answers lists for a client presenting the CA's client
// certificate or one of the tokens, and records how each authenticated.
type apiServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	auth   []string
	tokens map[string]bool
}

func newAPIServer(t *testing.T, p *pki, maxVersion uint16) *apiServer {
	t.Helper()
	a := &apiServer{tokens: map[string]bool{"static-token": true, "file-token": true, "exec-token": true}}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			who = "cert:" + r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			if !a.tokens[tok] {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			who = "token:" + tok
		}
		a.mu.Lock()
		a.auth = append(a.auth, r.Method+" "+who)
		a.mu.Unlock()
		if who == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"metadata":{"resourceVersion":"1"},"items":[{"metadata":{"name":"default"}}]}`)
	}))
	a.srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.serverCert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: p.pool, // #nosec G402 -- the test server offers old versions so that the client's floor refuses them
		MinVersion: tls.VersionTLS10, MaxVersion: maxVersion}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiServer) last() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.auth) == 0 {
		return ""
	}
	return a.auth[len(a.auth)-1]
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// kubeconfigYAML writes a kubeconfig as kubectl does, with one cluster and
// the given user block (indented under "user:").
func kubeconfigYAML(server, clusterExtra, user string) string {
	return `apiVersion: v1
kind: Config
# written by kubectl
clusters:
- cluster:
    server: ` + server + `
` + clusterExtra + `  name: test
contexts:
- context:
    cluster: test
    user: admin
    namespace: default
  name: test
current-context: test
preferences: {}
users:
- name: admin
  user:
` + user
}

func listOnce(t *testing.T, c Config) error {
	t.Helper()
	cl, err := New(c)
	if err != nil {
		return err
	}
	_, _, err = cl.List(context.Background(), Namespaces, "")
	return err
}

// F-014 T-12 (design §2): the administrator's kubeconfig, every kind of
// credential, against a TLS API server; insecure settings refused.
func TestKubeconfig(t *testing.T) {
	p := newPKI(t)
	a := newAPIServer(t, p, tls.VersionTLS13)
	dir := t.TempDir()
	caFile := write(t, dir, "ca.crt", p.caPEM)
	caData := "    certificate-authority-data: " + b64(p.caPEM) + "\n"
	load := func(t *testing.T, doc string) (Config, error) {
		t.Helper()
		return FromKubeconfig(KubeconfigOptions{Paths: []string{write(t, t.TempDir(), "config", []byte(doc))}})
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("client certificate data", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, "    client-certificate-data: "+b64(p.clientCertPEM)+"\n    client-key-data: "+b64(p.clientKey)+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err != nil || a.last() != "GET cert:admin" {
			t.Fatalf("%v %q", err, a.last())
		}
	})
	t.Run("client certificate files, CA file, relative paths", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "admin.crt", p.clientCertPEM)
		write(t, d, "admin.key", p.clientKey)
		write(t, d, "ca.crt", p.caPEM)
		doc := kubeconfigYAML(a.srv.URL, "    certificate-authority: ca.crt\n", "    client-certificate: admin.crt\n    client-key: \"admin.key\"\n")
		c, err := FromKubeconfig(KubeconfigOptions{Paths: []string{write(t, d, "config", []byte(doc))}})
		if err != nil {
			t.Fatal(err)
		}
		if c.CAFile != filepath.Join(d, "ca.crt") {
			t.Fatalf("CA file %q", c.CAFile)
		}
		if err := listOnce(t, c); err != nil || a.last() != "GET cert:admin" {
			t.Fatalf("%v %q", err, a.last())
		}
	})
	t.Run("client certificate of another CA refused by the server", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, "    client-certificate-data: "+b64(p.otherCertPEM)+"\n    client-key-data: "+b64(p.otherKeyPEM)+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err == nil {
			t.Fatal("a certificate from another CA was accepted")
		}
	})
	t.Run("bearer token", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, "    token: 'static-token'\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err != nil || a.last() != "GET token:static-token" {
			t.Fatalf("%v %q", err, a.last())
		}
	})
	t.Run("token file", func(t *testing.T) {
		tf := write(t, t.TempDir(), "token", []byte("file-token\n"))
		c, err := load(t, kubeconfigYAML(a.srv.URL, "    certificate-authority: "+caFile+"\n", "    tokenFile: "+tf+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err != nil || a.last() != "GET token:file-token" {
			t.Fatalf("%v %q", err, a.last())
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, "    token: nope\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); !errors.Is(err, ErrForbidden) {
			t.Fatalf("got %v", err)
		}
	})
	execUser := func(mode, record string, extraEnv ...string) string {
		s := "    exec:\n      apiVersion: " + ExecV1 + "\n      command: " + jsonQuote(exe) + "\n      args:\n      - -test.run=^$\n" +
			"      interactiveMode: IfAvailable\n      provideClusterInfo: true\n      env:\n      - name: FAIR_KUBE_EXEC_HELPER\n        value: " + mode + "\n" +
			"      - name: FAIR_KUBE_EXEC_RECORD\n        value: " + jsonQuote(record) + "\n"
		for i := 0; i+1 < len(extraEnv); i += 2 {
			s += "      - name: " + extraEnv[i] + "\n        value: " + jsonQuote(extraEnv[i+1]) + "\n"
		}
		return s
	}
	t.Run("exec plugin token", func(t *testing.T) {
		record := filepath.Join(t.TempDir(), "record")
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, execUser("token", record)))
		if err != nil {
			t.Fatal(err)
		}
		cl, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, _, err := cl.List(context.Background(), Namespaces, ""); err != nil || a.last() != "GET token:exec-token" {
				t.Fatalf("%v %q", err, a.last())
			}
		}
		b, _ := os.ReadFile(record) // #nosec G304 -- a test file
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) != 1 {
			t.Fatalf("plugin ran %d times; the token is cached until it expires", len(lines))
		}
		var info struct {
			APIVersion, Kind string
			Spec             struct {
				Interactive bool
				Cluster     ExecCluster
			}
		}
		if err := json.Unmarshal([]byte(lines[0]), &info); err != nil {
			t.Fatal(err)
		}
		if info.APIVersion != ExecV1 || info.Kind != "ExecCredential" || info.Spec.Interactive || info.Spec.Cluster.Server != a.srv.URL ||
			string(info.Spec.Cluster.CertificateAuthorityData) != string(p.caPEM) {
			t.Fatalf("KUBERNETES_EXEC_INFO %s", lines[0])
		}
	})
	t.Run("exec plugin token refused then asked again", func(t *testing.T) {
		record := filepath.Join(t.TempDir(), "record")
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, execUser("token", record)))
		if err != nil {
			t.Fatal(err)
		}
		cl, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		a.mu.Lock()
		a.tokens["exec-token"] = false
		a.mu.Unlock()
		defer func() { a.mu.Lock(); a.tokens["exec-token"] = true; a.mu.Unlock() }()
		if _, _, err := cl.List(context.Background(), Namespaces, ""); !errors.Is(err, ErrForbidden) {
			t.Fatalf("got %v", err)
		}
		b, _ := os.ReadFile(record) // #nosec G304 -- a test file
		if n := len(strings.Split(strings.TrimSpace(string(b)), "\n")); n != 2 {
			t.Fatalf("plugin ran %d times, want 2 (once more after a 401)", n)
		}
	})
	t.Run("exec plugin client certificate", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, caData, execUser("cert", filepath.Join(t.TempDir(), "r"),
			"FAIR_KUBE_EXEC_CERT", string(p.clientCertPEM), "FAIR_KUBE_EXEC_KEY", string(p.clientKey))))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err != nil || a.last() != "GET cert:admin" {
			t.Fatalf("%v %q", err, a.last())
		}
	})
	t.Run("exec plugin failures", func(t *testing.T) {
		for mode, want := range map[string]string{"fail": "sign-in expired", "empty": "neither a token nor a client certificate"} {
			c, err := load(t, kubeconfigYAML(a.srv.URL, caData, execUser(mode, filepath.Join(t.TempDir(), "r"))))
			if err != nil {
				t.Fatal(err)
			}
			err = listOnce(t, c)
			if err == nil || !strings.Contains(err.Error(), want) || strings.ContainsRune(err.Error(), 0x1b) {
				t.Errorf("%s: %v", mode, err)
			}
		}
	})
	t.Run("TLS 1.2 floor", func(t *testing.T) {
		old := newAPIServer(t, p, tls.VersionTLS11)
		c, err := load(t, kubeconfigYAML(old.srv.URL, caData, "    token: static-token\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err == nil {
			t.Fatal("TLS 1.1 accepted")
		}
	})
	t.Run("unknown CA refused", func(t *testing.T) {
		c, err := load(t, kubeconfigYAML(a.srv.URL, "", "    token: static-token\n")) // system roots
		if err != nil || !c.SystemRoots {
			t.Fatalf("%+v %v", c, err)
		}
		if err := listOnce(t, c); err == nil {
			t.Fatal("a server outside the system roots was accepted")
		}
	})
	t.Run("tls-server-name", func(t *testing.T) {
		host := strings.Replace(a.srv.URL, "127.0.0.1", "localhost", 1)
		c, err := load(t, kubeconfigYAML(host, caData+"    tls-server-name: kubernetes.test\n", "    token: static-token\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := listOnce(t, c); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refused settings", func(t *testing.T) {
		cases := map[string]struct{ cluster, user, want string }{
			"insecure":        {caData + "    insecure-skip-tls-verify: true\n", "    token: x\n", "insecure-skip-tls-verify is refused"},
			"insecure no CA":  {"    insecure-skip-tls-verify: true\n", "    token: x\n", "insecure-skip-tls-verify is refused"},
			"proxy":           {caData + "    proxy-url: http://proxy:3128\n", "    token: x\n", "proxy-url"},
			"basic":           {caData, "    username: admin\n    password: pw\n", "basic authentication is refused"},
			"impersonation":   {caData, "    token: x\n    as: someone\n", "impersonation"},
			"auth provider":   {caData, "    auth-provider:\n      name: oidc\n", "auth-provider"},
			"no credentials":  {caData, "    extensions: []\n", "no credentials"},
			"key without":     {caData, "    client-key-data: " + b64(p.clientKey) + "\n", "needs its key"},
			"exec v1alpha1":   {caData, "    exec:\n      apiVersion: client.authentication.k8s.io/v1alpha1\n      command: x\n", "apiVersion"},
			"exec terminal":   {caData, "    exec:\n      apiVersion: " + ExecV1 + "\n      command: x\n      interactiveMode: Always\n", "terminal"},
			"token and file":  {caData, "    token: x\n    tokenFile: /t\n", "both token and tokenFile"},
			"CA data and fil": {caData + "    certificate-authority: /ca\n", "    token: x\n", "both certificate-authority"},
		}
		for name, tc := range cases {
			_, err := load(t, kubeconfigYAML(a.srv.URL, tc.cluster, tc.user))
			if err == nil || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Errorf("%s: %v", name, err)
			}
			if err != nil && strings.Contains(err.Error(), "pw") && name == "basic" {
				t.Errorf("%s: the error repeats the password: %v", name, err)
			}
		}
		if _, err := load(t, kubeconfigYAML("http://127.0.0.1:6443", "", "    token: x\n")); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("http server: %v", err)
		}
	})
	t.Run("contexts and merged files", func(t *testing.T) {
		d := t.TempDir()
		first := write(t, d, "first", []byte(`apiVersion: v1
kind: Config
current-context: staging
clusters:
- name: prod
  cluster:
    server: https://prod.example:6443
    certificate-authority-data: `+b64(p.caPEM)+`
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
users:
- name: prod
  user:
    token: prod-token
`))
		second := write(t, d, "second.json", []byte(`{"apiVersion":"v1","kind":"Config","current-context":"prod",
  "clusters":[{"name":"staging","cluster":{"server":"https://staging.example:6443","certificate-authority-data":"`+b64(p.caPEM)+`"}},
              {"name":"prod","cluster":{"server":"https://shadowed.example"}}],
  "contexts":[{"name":"staging","context":{"cluster":"staging","user":"staging"}}],
  "users":[{"name":"staging","user":{"token":"staging-token"}}]}`))
		paths := KubeconfigPaths(func(k string) string {
			if k == "KUBECONFIG" {
				return first + string(filepath.ListSeparator) + filepath.Join(d, "missing") + string(filepath.ListSeparator) + second
			}
			return ""
		})
		c, err := FromKubeconfig(KubeconfigOptions{Paths: paths})
		if err != nil || c.Host != "https://staging.example:6443" || c.Token != "staging-token" {
			t.Fatalf("current context (first file's): %+v %v", c, err)
		}
		c, err = FromKubeconfig(KubeconfigOptions{Paths: paths, Context: "prod"})
		if err != nil || c.Host != "https://prod.example:6443" || c.Token != "prod-token" {
			t.Fatalf("-context prod (first file's cluster wins): %+v %v", c, err)
		}
		if _, err := FromKubeconfig(KubeconfigOptions{Paths: paths, Context: "dev"}); err == nil || !strings.Contains(err.Error(), `no context "dev"`) {
			t.Fatalf("unknown context: %v", err)
		}
		if _, err := FromKubeconfig(KubeconfigOptions{Paths: []string{filepath.Join(d, "missing")}}); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("no file: %v", err)
		}
		home := KubeconfigPaths(func(k string) string {
			if k == "HOME" {
				return "/home/admin"
			}
			return ""
		})
		if !reflect.DeepEqual(home, []string{filepath.Join("/home/admin", ".kube", "config")}) {
			t.Fatalf("default path %v", home)
		}
	})
}

func jsonQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

// The YAML subset kubeconfigs are written in, and what it refuses.
func TestKubeconfigYAML(t *testing.T) {
	doc := `---
apiVersion: v1 # trailing comment
clusters:
- cluster:
    server: "https://10.0.0.1:6443"
    extensions:
    - extension:
        last-update: Mon, 01 Jan 2026 10:00:00 UTC
        provider: minikube.sigs.k8s.io
      name: cluster_info
  name: 'it''s'
users:
  - name: a
    user:
      exec:
        args: [eks, get-token, "--cluster-name", 'x']
        env: null
        command: aws
        list:
        - - nested
          - "two\tescaped \u00e9"
        empty: []
        hash: "a#b" # comment
        url: http://x/#frag
`
	v, err := parseYAML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"apiVersion": "v1",
		"clusters": []any{map[string]any{
			"cluster": map[string]any{"server": "https://10.0.0.1:6443", "extensions": []any{map[string]any{
				"extension": map[string]any{"last-update": "Mon, 01 Jan 2026 10:00:00 UTC", "provider": "minikube.sigs.k8s.io"},
				"name":      "cluster_info"}}},
			"name": "it's"}},
		"users": []any{map[string]any{"name": "a", "user": map[string]any{"exec": map[string]any{
			"args": []any{"eks", "get-token", "--cluster-name", "x"}, "env": nil, "command": "aws",
			"list": []any{[]any{"nested", "two\tescaped é"}}, "empty": []any{}, "hash": "a#b", "url": "http://x/#frag"}}}},
	}
	if !reflect.DeepEqual(v, want) {
		gb, _ := json.MarshalIndent(v, "", " ")
		t.Fatalf("parsed:\n%s", gb)
	}
	for name, bad := range map[string]string{
		"anchor":       "a: &x 1\nb: *x\n",
		"tag":          "a: !!str 1\n",
		"block scalar": "a: |\n  text\n",
		"multi-line":   "a: one\n  two\n",
		"quote":        "a: \"open\n",
		"flow map":     "a: {b: c}\n",
		"duplicate":    "a: 1\na: 2\n",
		"tab":          "a:\n\tb: 1\n",
		"documents":    "a: 1\n---\nb: 2\n",
		"indent":       "a:\n    b: 1\n  c: 2\n",
		"complex key":  "? a\n",
	} {
		if _, err := parseYAML([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The kube client uses the standard library alone (design §2).
func TestStandardLibraryOnly(t *testing.T) {
	g, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	out, err := exec.CommandContext(t.Context(), g, "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, ".").CombinedOutput() // #nosec G204 -- test
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "github.com/rformer/fair-app/internal/scanner/kube" {
		t.Fatalf("non-standard dependencies:\n%s", got)
	}
}

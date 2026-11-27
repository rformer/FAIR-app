// Package kube is posture-scanner's Kubernetes API client (F-015 T-27,
// design §6.8): read-only by construction. It issues only GET requests (list,
// with pagination, and watch), and refuses Secrets before any request is
// made; RBAC (deploy/k8s/posture-scanner.yaml) grants nothing more either.
// It uses the in-cluster service-account token, re-read before each request
// so projected-token rotation works, and verifies the API server with the
// cluster CA over TLS 1.2 or later.
//
// fairctl (F-014 T-12, design §2) reads the administrator's kubeconfig with
// FromKubeconfig: client certificates, bearer tokens, token files and exec
// credential plugins, never insecure-skip-tls-verify. The client stays
// read-only; fairctl's writes go only through the Helm SDK. The package
// uses the standard library alone (TestStandardLibraryOnly).
package kube

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Default in-cluster paths of the projected service-account token and CA.
const (
	TokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a path, not a credential
	CAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Errors.
var (
	// ErrSecretsRefused: the scanner never reads Secrets (design §6.8).
	ErrSecretsRefused = errors.New("kube: the scanner never reads Secrets")
	// ErrForbidden: RBAC denied the read (403).
	ErrForbidden = errors.New("kube: forbidden")
	// ErrNotFound: the resource type is not served (for example a CRD that
	// is not installed) or the object does not exist (404).
	ErrNotFound = errors.New("kube: not found")
)

// Resource names an API resource.
type Resource struct {
	Group      string // "" for the core group
	Version    string
	Plural     string
	Namespaced bool
}

func (r Resource) String() string {
	if r.Group == "" {
		return r.Version + "/" + r.Plural
	}
	return r.Group + "/" + r.Version + "/" + r.Plural
}

// Common resources the checks read.
var (
	Namespaces                      = Resource{Version: "v1", Plural: "namespaces"}
	Nodes                           = Resource{Version: "v1", Plural: "nodes"}
	Pods                            = Resource{Version: "v1", Plural: "pods", Namespaced: true}
	Services                        = Resource{Version: "v1", Plural: "services", Namespaced: true}
	PersistentVolumeClaims          = Resource{Version: "v1", Plural: "persistentvolumeclaims", Namespaced: true}
	ServiceAccounts                 = Resource{Version: "v1", Plural: "serviceaccounts", Namespaced: true}
	Deployments                     = Resource{Group: "apps", Version: "v1", Plural: "deployments", Namespaced: true}
	StatefulSets                    = Resource{Group: "apps", Version: "v1", Plural: "statefulsets", Namespaced: true}
	DaemonSets                      = Resource{Group: "apps", Version: "v1", Plural: "daemonsets", Namespaced: true}
	NetworkPolicies                 = Resource{Group: "networking.k8s.io", Version: "v1", Plural: "networkpolicies", Namespaced: true}
	Roles                           = Resource{Group: "rbac.authorization.k8s.io", Version: "v1", Plural: "roles", Namespaced: true}
	RoleBindings                    = Resource{Group: "rbac.authorization.k8s.io", Version: "v1", Plural: "rolebindings", Namespaced: true}
	ClusterRoles                    = Resource{Group: "rbac.authorization.k8s.io", Version: "v1", Plural: "clusterroles"}
	ClusterRoleBindings             = Resource{Group: "rbac.authorization.k8s.io", Version: "v1", Plural: "clusterrolebindings"}
	StorageClasses                  = Resource{Group: "storage.k8s.io", Version: "v1", Plural: "storageclasses"}
	ValidatingAdmissionPolicies     = Resource{Group: "admissionregistration.k8s.io", Version: "v1", Plural: "validatingadmissionpolicies"}
	ValidatingWebhookConfigurations = Resource{Group: "admissionregistration.k8s.io", Version: "v1", Plural: "validatingwebhookconfigurations"}
	ExternalSecrets                 = Resource{Group: "external-secrets.io", Version: "v1beta1", Plural: "externalsecrets", Namespaced: true}
)

// Object is an API object: its metadata, and the whole object as JSON for
// the checks to decode what they need.
type Object struct {
	Metadata Metadata        `json:"metadata"`
	Raw      json.RawMessage `json:"-"`
}

// Metadata is the part of ObjectMeta the scanner uses.
type Metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// Event is one watch event.
type Event struct {
	Type   string // ADDED, MODIFIED, DELETED, BOOKMARK or ERROR
	Object Object
}

// Config locates the API server and credentials. In-cluster clients set
// TokenFile and CAFile; FromKubeconfig may set the others.
type Config struct {
	Host      string // https://host:port
	TokenFile string // a bearer token file, re-read before each request
	CAFile    string
	Timeout   time.Duration // per list request; default 30 s
	UserAgent string        // default fair-posture-scanner (fleetctl names itself)

	CAData      []byte // PEM, instead of CAFile
	SystemRoots bool   // with neither CAFile nor CAData: verify with the system roots (a kubeconfig naming no CA)
	ServerName  string // the name to verify the server's certificate for, when it differs from the host

	Token      string           // a bearer token
	ClientCert *tls.Certificate // a client certificate and its key
	Exec       *ExecConfig      // an exec credential plugin (token or client certificate)
}

// InCluster returns the in-cluster configuration.
func InCluster() (Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, errors.New("kube: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	return Config{Host: "https://" + net.JoinHostPort(host, port), TokenFile: TokenFile, CAFile: CAFile}, nil
}

// Client is a read-only API client.
type Client struct {
	host    *url.URL
	creds   credentials
	http    *http.Client
	watcher *http.Client // no overall timeout: watches stream
	timeout time.Duration
	agent   string
}

// credentials supply a request's bearer token and the TLS client
// certificate.
type credentials struct {
	tokenFile string
	token     string
	cert      *tls.Certificate
	exec      *execCredentials
}

func (c *credentials) bearer(ctx context.Context) (string, error) {
	switch {
	case c.tokenFile != "":
		tok, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return "", fmt.Errorf("kube: token file: %w", err)
		}
		return strings.TrimSpace(string(tok)), nil
	case c.token != "":
		return c.token, nil
	case c.exec != nil:
		cr, err := c.exec.get(ctx)
		if err != nil {
			return "", err
		}
		return cr.token, nil
	}
	return "", nil
}

func (c *credentials) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c.cert != nil {
		return c.cert, nil
	}
	if c.exec != nil {
		ctx, cancel := context.WithTimeout(context.Background(), c.exec.cfg.timeout())
		defer cancel()
		cr, err := c.exec.get(ctx)
		if err != nil {
			return nil, err
		}
		if cr.cert != nil {
			return cr.cert, nil
		}
	}
	return &tls.Certificate{}, nil // none: the server may still accept a token
}

// New returns a Client for c.
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("kube: API server %q must be an https URL", c.Host)
	}
	var pool *x509.CertPool // nil: the system roots
	switch {
	case c.CAFile != "" || len(c.CAData) > 0:
		ca, name := c.CAData, "the certificate authority data"
		if c.CAFile != "" {
			if len(c.CAData) > 0 {
				return nil, errors.New("kube: both a CA file and CA data")
			}
			if ca, err = os.ReadFile(c.CAFile); err != nil {
				return nil, fmt.Errorf("kube: cluster CA: %w", err)
			}
			name = c.CAFile
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("kube: no certificates in %s", name)
		}
	case !c.SystemRoots:
		return nil, errors.New("kube: cluster CA: none named")
	}
	n := 0
	for _, set := range []bool{c.TokenFile != "", c.Token != "", c.Exec != nil} {
		if set {
			n++
		}
	}
	if n > 1 {
		return nil, errors.New("kube: more than one of a token file, a token and an exec plugin")
	}
	if n == 0 && c.ClientCert == nil {
		return nil, errors.New("kube: no credentials (a token, a token file, a client certificate or an exec plugin)")
	}
	creds := credentials{tokenFile: c.TokenFile, token: c.Token, cert: c.ClientCert}
	if c.Exec != nil {
		if err := c.Exec.check(); err != nil {
			return nil, err
		}
		creds.exec = &execCredentials{cfg: *c.Exec, now: time.Now}
	}
	if c.UserAgent == "" {
		c.UserAgent = "fair-posture-scanner"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	cl := &Client{host: u, creds: creds, timeout: c.Timeout, agent: c.UserAgent}
	tlsc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: c.ServerName}
	if c.ClientCert != nil || c.Exec != nil {
		tlsc.GetClientCertificate = cl.creds.clientCertificate
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsc,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: c.Timeout,
		IdleConnTimeout:       90 * time.Second,
	}
	cl.http = &http.Client{Transport: tr, Timeout: c.Timeout}
	cl.watcher = &http.Client{Transport: tr}
	return cl, nil
}

func (c *Client) path(r Resource, namespace string) (string, error) {
	if r.Plural == "secrets" {
		return "", ErrSecretsRefused
	}
	if r.Version == "" || r.Plural == "" {
		return "", fmt.Errorf("kube: incomplete resource %+v", r)
	}
	p := "/api/" + r.Version
	if r.Group != "" {
		p = "/apis/" + r.Group + "/" + r.Version
	}
	if r.Namespaced && namespace != "" {
		p += "/namespaces/" + url.PathEscape(namespace)
	}
	return p + "/" + r.Plural, nil
}

// get issues the only kind of request this client makes.
func (c *Client) get(ctx context.Context, hc *http.Client, path string, q url.Values) (*http.Response, error) {
	resp, err := c.do(ctx, hc, path, q)
	if err == nil && resp.StatusCode == http.StatusUnauthorized && c.creds.exec != nil {
		// The plugin's credential was refused before its expiry (revoked or
		// rotated): ask the plugin again, once.
		_ = resp.Body.Close()
		c.creds.exec.forget()
		resp, err = c.do(ctx, hc, path, q)
	}
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: GET %s (%d)", ErrForbidden, path, resp.StatusCode)
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: GET %s", ErrNotFound, path)
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("kube: GET %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
}

func (c *Client) do(ctx context.Context, hc *http.Client, path string, q url.Values) (*http.Response, error) {
	tok, err := c.creds.bearer(ctx)
	if err != nil {
		return nil, err
	}
	u := *c.host
	u.Path, u.RawQuery = path, q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kube: GET %s: %w", path, err)
	}
	return resp, nil
}

// List returns every object of r in namespace ("" = all namespaces, or a
// cluster-scoped resource), following pagination, and the list's
// resourceVersion for a subsequent Watch.
func (c *Client) List(ctx context.Context, r Resource, namespace string) ([]Object, string, error) {
	path, err := c.path(r, namespace)
	if err != nil {
		return nil, "", err
	}
	var out []Object
	q := url.Values{"limit": {"500"}}
	for {
		resp, err := c.get(ctx, c.http, path, q)
		if err != nil {
			return nil, "", err
		}
		var page struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue"`
			} `json:"metadata"`
			Items []json.RawMessage `json:"items"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&page)
		_ = resp.Body.Close()
		if err != nil {
			return nil, "", fmt.Errorf("kube: list %s: %w", r, err)
		}
		for _, raw := range page.Items {
			var o Object
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, "", fmt.Errorf("kube: list %s: %w", r, err)
			}
			o.Raw = raw
			out = append(out, o)
		}
		if page.Metadata.Continue == "" {
			return out, page.Metadata.ResourceVersion, nil
		}
		q.Set("continue", page.Metadata.Continue)
	}
}

// Watch streams changes to r after resourceVersion to fn until ctx ends,
// the server closes the watch (it returns nil; list and watch again), or fn
// returns an error.
func (c *Client) Watch(ctx context.Context, r Resource, namespace, resourceVersion string, fn func(Event) error) error {
	path, err := c.path(r, namespace)
	if err != nil {
		return err
	}
	q := url.Values{"watch": {"1"}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"300"}}
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	resp, err := c.get(ctx, c.watcher, path, q)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	for {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("kube: watch %s: %w", r, err)
		}
		var o Object
		if err := json.Unmarshal(ev.Object, &o); err != nil {
			return fmt.Errorf("kube: watch %s: %w", r, err)
		}
		o.Raw = ev.Object
		if ev.Type == "ERROR" {
			return fmt.Errorf("kube: watch %s: %s", r, ev.Object) // e.g. 410 Gone: list again
		}
		if err := fn(Event{Type: ev.Type, Object: o}); err != nil {
			return err
		}
	}
}

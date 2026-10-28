// Package kube is posture-scanner's Kubernetes API client (F-015 T-27,
// design §6.8): read-only by construction. It issues only GET requests (list,
// with pagination, and watch), and refuses Secrets before any request is
// made; RBAC (deploy/k8s/posture-scanner.yaml) grants nothing more either.
// It uses the in-cluster service-account token, re-read before each request
// so projected-token rotation works, and verifies the API server with the
// cluster CA over TLS 1.2 or later.
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

// Config locates the API server and credentials.
type Config struct {
	Host      string // https://host:port
	TokenFile string
	CAFile    string
	Timeout   time.Duration // per list request; default 30 s
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
	token   string // file
	http    *http.Client
	watcher *http.Client // no overall timeout: watches stream
	timeout time.Duration
}

// New returns a Client for c.
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("kube: API server %q must be an https URL", c.Host)
	}
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("kube: cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("kube: no certificates in %s", c.CAFile)
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: c.Timeout,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{host: u, token: c.TokenFile, http: &http.Client{Transport: tr, Timeout: c.Timeout},
		watcher: &http.Client{Transport: tr}, timeout: c.Timeout}, nil
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
	tok, err := os.ReadFile(c.token)
	if err != nil {
		return nil, fmt.Errorf("kube: service-account token: %w", err)
	}
	u := *c.host
	u.Path, u.RawQuery = path, q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fair-posture-scanner")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kube: GET %s: %w", path, err)
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

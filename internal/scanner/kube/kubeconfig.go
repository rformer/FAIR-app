package kube

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KubeconfigOptions selects the kubeconfig files and context.
type KubeconfigOptions struct {
	// Paths are the kubeconfig files in precedence order (KUBECONFIG's
	// order); empty: KubeconfigPaths(os.Getenv).
	Paths []string
	// Context names the context; empty: the current-context.
	Context   string
	Timeout   time.Duration
	UserAgent string
}

// maxKubeconfig bounds a kubeconfig file.
const maxKubeconfig = 4 << 20

// KubeconfigPaths returns the files kubectl would read: KUBECONFIG's
// entries, or ~/.kube/config.
func KubeconfigPaths(getenv func(string) string) []string {
	if v := getenv("KUBECONFIG"); v != "" {
		var out []string
		for _, p := range filepath.SplitList(v) {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	home := getenv("HOME")
	if home == "" {
		home = getenv("USERPROFILE")
	}
	if home == "" {
		return nil
	}
	return []string{filepath.Join(home, ".kube", "config")}
}

type kcCluster struct {
	Server                   string `json:"server"`
	CertificateAuthority     string `json:"certificate-authority"`
	CertificateAuthorityData string `json:"certificate-authority-data"`
	InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify"`
	TLSServerName            string `json:"tls-server-name"`
	ProxyURL                 string `json:"proxy-url"`
	dir                      string
}

type kcUser struct {
	ClientCertificate     string          `json:"client-certificate"`
	ClientCertificateData string          `json:"client-certificate-data"`
	ClientKey             string          `json:"client-key"`
	ClientKeyData         string          `json:"client-key-data"`
	Token                 string          `json:"token"`
	TokenFile             string          `json:"tokenFile"`
	As                    string          `json:"as"`
	AsUID                 string          `json:"as-uid"`
	AsGroups              []string        `json:"as-groups"`
	AsUserExtra           json.RawMessage `json:"as-user-extra"`
	Username              string          `json:"username"`
	Password              string          `json:"password"`
	AuthProvider          json.RawMessage `json:"auth-provider"`
	Exec                  *struct {
		APIVersion string   `json:"apiVersion"`
		Command    string   `json:"command"`
		Args       []string `json:"args"`
		Env        []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"env"`
		InstallHint        string `json:"installHint"`
		ProvideClusterInfo bool   `json:"provideClusterInfo"`
		InteractiveMode    string `json:"interactiveMode"`
	} `json:"exec"`
	dir string
}

type kcContext struct {
	Cluster   string `json:"cluster"`
	User      string `json:"user"`
	Namespace string `json:"namespace"`
}

type kubeconfigFile struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	CurrentContext string `json:"current-context"`
	Clusters       []struct {
		Name    string    `json:"name"`
		Cluster kcCluster `json:"cluster"`
	} `json:"clusters"`
	Users []struct {
		Name string `json:"name"`
		User kcUser `json:"user"`
	} `json:"users"`
	Contexts []struct {
		Name    string    `json:"name"`
		Context kcContext `json:"context"`
	} `json:"contexts"`
}

// Kubeconfig is the merged configuration of one or more files: the first
// file to set a name or the current context wins, as with kubectl.
type Kubeconfig struct {
	CurrentContext string
	clusters       map[string]kcCluster
	users          map[string]kcUser
	contexts       map[string]kcContext
	files          []string
}

// LoadKubeconfig reads and merges the files (a missing file is skipped, as
// kubectl does, unless no file exists).
func LoadKubeconfig(paths []string) (*Kubeconfig, error) {
	k := &Kubeconfig{clusters: map[string]kcCluster{}, users: map[string]kcUser{}, contexts: map[string]kcContext{}}
	if len(paths) == 0 {
		return nil, errors.New("kube: no kubeconfig (set KUBECONFIG or -kubeconfig)")
	}
	for _, p := range paths {
		f, err := readKubeconfig(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		k.files = append(k.files, p)
		dir := filepath.Dir(p)
		if k.CurrentContext == "" {
			k.CurrentContext = f.CurrentContext
		}
		for _, c := range f.Clusters {
			if _, ok := k.clusters[c.Name]; !ok && c.Name != "" {
				c.Cluster.dir = dir
				k.clusters[c.Name] = c.Cluster
			}
		}
		for _, u := range f.Users {
			if _, ok := k.users[u.Name]; !ok && u.Name != "" {
				u.User.dir = dir
				k.users[u.Name] = u.User
			}
		}
		for _, c := range f.Contexts {
			if _, ok := k.contexts[c.Name]; !ok && c.Name != "" {
				k.contexts[c.Name] = c.Context
			}
		}
	}
	if len(k.files) == 0 {
		return nil, fmt.Errorf("kube: kubeconfig %s: %w", strings.Join(paths, string(filepath.ListSeparator)), os.ErrNotExist)
	}
	return k, nil
}

func readKubeconfig(p string) (*kubeconfigFile, error) {
	fh, err := os.Open(p) // #nosec G304 -- the administrator's kubeconfig
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	b, err := io.ReadAll(io.LimitReader(fh, maxKubeconfig+1))
	if err != nil {
		return nil, fmt.Errorf("kube: kubeconfig %s: %w", p, err)
	}
	if len(b) > maxKubeconfig {
		return nil, fmt.Errorf("kube: kubeconfig %s: larger than 4 MiB", p)
	}
	var doc []byte
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '{' {
		doc = t
	} else {
		v, err := parseYAML(b)
		if err != nil {
			return nil, fmt.Errorf("kube: kubeconfig %s: %w (`kubectl config view --raw --flatten -o json` writes a form fairctl reads)", p, err)
		}
		if doc, err = json.Marshal(v); err != nil {
			return nil, fmt.Errorf("kube: kubeconfig %s: %w", p, err)
		}
	}
	var f kubeconfigFile
	if err := json.Unmarshal(doc, &f); err != nil {
		return nil, fmt.Errorf("kube: kubeconfig %s: %w", p, err)
	}
	if f.Kind != "" && f.Kind != "Config" {
		return nil, fmt.Errorf("kube: kubeconfig %s: kind %q, not Config", p, f.Kind)
	}
	if f.APIVersion != "" && f.APIVersion != "v1" {
		return nil, fmt.Errorf("kube: kubeconfig %s: apiVersion %q, not v1", p, f.APIVersion)
	}
	return &f, nil
}

// Contexts returns the names of the contexts.
func (k *Kubeconfig) Contexts() []string {
	out := make([]string, 0, len(k.contexts))
	for n := range k.contexts {
		out = append(out, n)
	}
	return out
}

// FromKubeconfig returns the Config for a kubeconfig context (design §2,
// F-014 T-12): the cluster's https server, its CA (data or file; the
// system roots when it names none) and tls-server-name, and the user's
// client certificate (data or files), token, token file or exec plugin.
// It refuses insecure-skip-tls-verify, proxies, impersonation, basic
// authentication and auth providers rather than ignore them.
func FromKubeconfig(o KubeconfigOptions) (Config, error) {
	paths := o.Paths
	if len(paths) == 0 {
		paths = KubeconfigPaths(os.Getenv)
	}
	k, err := LoadKubeconfig(paths)
	if err != nil {
		return Config{}, err
	}
	return k.Config(o.Context, o.Timeout, o.UserAgent)
}

// Config resolves a context (empty: the current context).
func (k *Kubeconfig) Config(context string, timeout time.Duration, agent string) (Config, error) {
	name := context
	if name == "" {
		name = k.CurrentContext
	}
	if name == "" {
		return Config{}, errors.New("kube: kubeconfig names no current-context: choose one with -context")
	}
	ctx, ok := k.contexts[name]
	if !ok {
		return Config{}, fmt.Errorf("kube: kubeconfig has no context %q", name)
	}
	cl, ok := k.clusters[ctx.Cluster]
	if !ok {
		return Config{}, fmt.Errorf("kube: context %q: no cluster %q", name, ctx.Cluster)
	}
	u, ok := k.users[ctx.User]
	if !ok {
		return Config{}, fmt.Errorf("kube: context %q: no user %q", name, ctx.User)
	}
	where := fmt.Sprintf("kube: context %q", name)
	c := Config{Host: strings.TrimRight(cl.Server, "/"), Timeout: timeout, UserAgent: agent, ServerName: cl.TLSServerName}
	su, err := url.Parse(cl.Server)
	switch {
	case err != nil || su.Scheme != "https" || su.Host == "":
		return Config{}, fmt.Errorf("%s: cluster %q: the server must be an https URL", where, ctx.Cluster)
	case su.Path != "" && su.Path != "/":
		return Config{}, fmt.Errorf("%s: cluster %q: a server with a path is not supported", where, ctx.Cluster)
	case cl.InsecureSkipTLSVerify:
		return Config{}, fmt.Errorf("%s: cluster %q: insecure-skip-tls-verify is refused; name the cluster's CA (certificate-authority or certificate-authority-data)", where, ctx.Cluster)
	case cl.ProxyURL != "":
		return Config{}, fmt.Errorf("%s: cluster %q: proxy-url is not supported", where, ctx.Cluster)
	case cl.CertificateAuthority != "" && cl.CertificateAuthorityData != "":
		return Config{}, fmt.Errorf("%s: cluster %q: both certificate-authority and certificate-authority-data", where, ctx.Cluster)
	case cl.CertificateAuthorityData != "":
		if c.CAData, err = decodeData("certificate-authority-data", cl.CertificateAuthorityData); err != nil {
			return Config{}, fmt.Errorf("%s: cluster %q: %w", where, ctx.Cluster, err)
		}
	case cl.CertificateAuthority != "":
		c.CAFile = resolve(cl.dir, cl.CertificateAuthority)
	default:
		c.SystemRoots = true
	}

	switch {
	case u.As != "" || u.AsUID != "" || len(u.AsGroups) > 0 || isSet(u.AsUserExtra):
		return Config{}, fmt.Errorf("%s: user %q: impersonation is not supported", where, ctx.User)
	case u.Username != "" || u.Password != "":
		return Config{}, fmt.Errorf("%s: user %q: basic authentication is refused", where, ctx.User)
	case isSet(u.AuthProvider):
		return Config{}, fmt.Errorf("%s: user %q: auth-provider plugins are not supported; use an exec plugin", where, ctx.User)
	case u.Token != "" && u.TokenFile != "":
		return Config{}, fmt.Errorf("%s: user %q: both token and tokenFile", where, ctx.User)
	}
	c.Token = strings.TrimSpace(u.Token)
	if u.TokenFile != "" {
		c.TokenFile = resolve(u.dir, u.TokenFile)
	}
	cert, key, err := u.pair()
	if err != nil {
		return Config{}, fmt.Errorf("%s: user %q: %w", where, ctx.User, err)
	}
	if cert != nil {
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return Config{}, fmt.Errorf("%s: user %q: client certificate: %w", where, ctx.User, err)
		}
		c.ClientCert = &pair
	}
	if e := u.Exec; e != nil {
		x := &ExecConfig{APIVersion: e.APIVersion, Command: e.Command, Args: e.Args, InteractiveMode: e.InteractiveMode,
			ProvideClusterInfo: e.ProvideClusterInfo, InstallHint: e.InstallHint, Dir: u.dir}
		for _, v := range e.Env {
			x.Env = append(x.Env, ExecEnv{Name: v.Name, Value: v.Value})
		}
		if x.ProvideClusterInfo {
			ca := c.CAData
			if c.CAFile != "" {
				if ca, err = os.ReadFile(c.CAFile); err != nil {
					return Config{}, fmt.Errorf("%s: cluster CA: %w", where, err)
				}
			}
			x.Cluster = &ExecCluster{Server: c.Host, TLSServerName: c.ServerName, CertificateAuthorityData: ca}
		}
		if err := x.check(); err != nil {
			return Config{}, fmt.Errorf("%s: user %q: %w", where, ctx.User, err)
		}
		c.Exec = x
	}
	if c.Token == "" && c.TokenFile == "" && c.ClientCert == nil && c.Exec == nil {
		return Config{}, fmt.Errorf("%s: user %q: no credentials (a client certificate, token, tokenFile or exec plugin)", where, ctx.User)
	}
	return c, nil
}

func (u kcUser) pair() (cert, key []byte, err error) {
	load := func(field, file, data string) ([]byte, error) {
		switch {
		case file != "" && data != "":
			return nil, fmt.Errorf("both %s and %s-data", field, field)
		case data != "":
			return decodeData(field+"-data", data)
		case file != "":
			b, err := os.ReadFile(resolve(u.dir, file)) // #nosec G304 -- named by the administrator's kubeconfig
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
			return b, nil
		}
		return nil, nil
	}
	if cert, err = load("client-certificate", u.ClientCertificate, u.ClientCertificateData); err != nil {
		return nil, nil, err
	}
	if key, err = load("client-key", u.ClientKey, u.ClientKeyData); err != nil {
		return nil, nil, err
	}
	if (cert == nil) != (key == nil) {
		return nil, nil, errors.New("a client certificate needs its key and the reverse")
	}
	return cert, key, nil
}

func isSet(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t != "" && t != "null" && t != "{}" && t != "[]"
}

// resolve makes a kubeconfig's relative path relative to its file.
func resolve(dir, p string) string {
	if p == "" || filepath.IsAbs(p) || dir == "" {
		return p
	}
	return filepath.Join(dir, p)
}

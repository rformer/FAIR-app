package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Exec credential plugin API versions (client.authentication.k8s.io). v1 is
// the current one; v1beta1 has the same ExecCredential shape for what the
// client reads and is still what some cloud tools write.
const (
	ExecV1      = "client.authentication.k8s.io/v1"
	ExecV1beta1 = "client.authentication.k8s.io/v1beta1"
)

// ExecConfig is a kubeconfig user's exec credential plugin.
type ExecConfig struct {
	APIVersion         string
	Command            string
	Args               []string
	Env                []ExecEnv
	InteractiveMode    string // Never, IfAvailable or Always; Always is refused (fairctl never hands a plugin its terminal)
	ProvideClusterInfo bool
	InstallHint        string
	Dir                string       // the directory of the kubeconfig that names the plugin (relative commands resolve there)
	Cluster            *ExecCluster // passed to the plugin when ProvideClusterInfo
	Timeout            time.Duration
}

// ExecEnv is one environment variable the plugin is given.
type ExecEnv struct{ Name, Value string }

// ExecCluster is the cluster information a plugin may ask for.
type ExecCluster struct {
	Server                   string `json:"server"`
	TLSServerName            string `json:"tls-server-name,omitempty"`
	CertificateAuthorityData []byte `json:"certificate-authority-data,omitempty"`
}

func (e *ExecConfig) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return 60 * time.Second
}

func (e *ExecConfig) check() error {
	switch {
	case e.APIVersion != ExecV1 && e.APIVersion != ExecV1beta1:
		return fmt.Errorf("kube: exec plugin apiVersion %q is not %s", e.APIVersion, ExecV1)
	case strings.TrimSpace(e.Command) == "":
		return errors.New("kube: exec plugin without a command")
	case e.InteractiveMode == "Always":
		return errors.New("kube: exec plugin needs a terminal (interactiveMode Always): sign in with the plugin first, or use a plugin that runs without one")
	case e.InteractiveMode != "" && e.InteractiveMode != "Never" && e.InteractiveMode != "IfAvailable":
		return fmt.Errorf("kube: exec plugin interactiveMode %q", e.InteractiveMode)
	}
	return nil
}

// execCredential is what a plugin prints (ExecCredential status).
type execCredential struct {
	token  string
	cert   *tls.Certificate
	expiry time.Time // zero: until refused
}

// execCredentials runs the plugin and caches its credential until it
// expires or the server refuses it.
type execCredentials struct {
	cfg ExecConfig
	now func() time.Time

	mu   sync.Mutex
	have *execCredential
}

func (x *execCredentials) forget() {
	x.mu.Lock()
	x.have = nil
	x.mu.Unlock()
}

func (x *execCredentials) get(ctx context.Context) (*execCredential, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.have != nil && (x.have.expiry.IsZero() || x.now().Before(x.have.expiry.Add(-10*time.Second))) {
		return x.have, nil
	}
	cr, err := x.run(ctx)
	if err != nil {
		return nil, err
	}
	x.have = cr
	return cr, nil
}

func (x *execCredentials) run(ctx context.Context) (*execCredential, error) {
	c := x.cfg
	info := map[string]any{"apiVersion": c.APIVersion, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}}
	if c.ProvideClusterInfo && c.Cluster != nil {
		info["spec"].(map[string]any)["cluster"] = c.Cluster
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	command := c.Command
	if strings.ContainsAny(command, `/\`) && !filepath.IsAbs(command) && c.Dir != "" {
		command = filepath.Join(c.Dir, command)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, command, c.Args...) // #nosec G204 -- the administrator's own kubeconfig names the plugin, as kubectl runs it
	cmd.Env = os.Environ()
	for _, e := range c.Env {
		cmd.Env = append(cmd.Env, e.Name+"="+e.Value)
	}
	cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+string(infoJSON))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &limited{w: &stderr, n: 2048}
	if err := cmd.Run(); err != nil {
		msg := fmt.Sprintf("kube: exec plugin %s: %v", filepath.Base(c.Command), err)
		if s := firstLine(stderr.String()); s != "" {
			msg += ": " + s
		}
		if c.InstallHint != "" && errors.Is(err, exec.ErrNotFound) {
			msg += " (" + firstLine(c.InstallHint) + ")"
		}
		return nil, errors.New(msg)
	}
	var out struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     *struct {
			Token                 string `json:"token"`
			ClientCertificateData string `json:"clientCertificateData"`
			ClientKeyData         string `json:"clientKeyData"`
			ExpirationTimestamp   string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("kube: exec plugin %s: output is not an ExecCredential", filepath.Base(c.Command))
	}
	switch {
	case out.Kind != "ExecCredential":
		return nil, fmt.Errorf("kube: exec plugin %s: kind %q, not ExecCredential", filepath.Base(c.Command), out.Kind)
	case out.APIVersion != c.APIVersion:
		return nil, fmt.Errorf("kube: exec plugin %s: apiVersion %q, not the %q asked for", filepath.Base(c.Command), out.APIVersion, c.APIVersion)
	case out.Status == nil:
		return nil, fmt.Errorf("kube: exec plugin %s: no status", filepath.Base(c.Command))
	}
	cr := &execCredential{token: out.Status.Token}
	if out.Status.ExpirationTimestamp != "" {
		if cr.expiry, err = time.Parse(time.RFC3339, out.Status.ExpirationTimestamp); err != nil {
			return nil, fmt.Errorf("kube: exec plugin %s: expirationTimestamp is not RFC 3339", filepath.Base(c.Command))
		}
	}
	if (out.Status.ClientCertificateData == "") != (out.Status.ClientKeyData == "") {
		return nil, fmt.Errorf("kube: exec plugin %s: a client certificate needs its key and the reverse", filepath.Base(c.Command))
	}
	if out.Status.ClientCertificateData != "" {
		pair, err := tls.X509KeyPair([]byte(out.Status.ClientCertificateData), []byte(out.Status.ClientKeyData))
		if err != nil {
			return nil, fmt.Errorf("kube: exec plugin %s: client certificate: %w", filepath.Base(c.Command), err)
		}
		cr.cert = &pair
	}
	if cr.token == "" && cr.cert == nil {
		return nil, fmt.Errorf("kube: exec plugin %s: neither a token nor a client certificate", filepath.Base(c.Command))
	}
	return cr, nil
}

// limited keeps the first n bytes written.
type limited struct {
	w *bytes.Buffer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}

// firstLine is s's first non-empty line, printable characters only, at
// most 200 bytes.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, l)
		if l = strings.TrimSpace(l); l != "" {
			if r := []rune(l); len(r) > 200 {
				l = string(r[:200])
			}
			return l
		}
	}
	return ""
}

// decodeData decodes a kubeconfig *-data field (base64).
func decodeData(field, s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s is not base64", field)
	}
	return b, nil
}

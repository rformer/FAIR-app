package fleetctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/scanner/kube"
)

// Sources read an instance's health. Every error fails the gate (closed).
type Sources interface {
	// Flux returns the state of the instance's Flux objects.
	Flux(ctx context.Context, in Instance) (Flux, error)
	// Ready checks the instance's readiness URLs.
	Ready(ctx context.Context, in Instance) error
	// Alerts returns the SLO alerts that fired for the instance during the
	// last `over` (0: the ones firing now).
	Alerts(ctx context.Context, in Instance, over time.Duration) ([]string, error)
}

// Flux is what an instance's Flux reports.
type Flux struct {
	Source Step      // OCIRepository fair-release; Revision is the artifact's
	Since  time.Time // when the source stored that artifact (the soak's start)
	Steps  []Step    // the Kustomizations
}

// Step is one Flux object's state.
type Step struct {
	Name     string `json:"name"`
	Ready    bool   `json:"ready"`
	Revision string `json:"revision,omitempty"` // lastAppliedRevision, or the artifact's revision
	Message  string `json:"message,omitempty"`
}

// The Flux objects an instance runs (deploy/fleet/flux): the fleet's own
// steps from the fleet repository, then the release's from the artifact.
var (
	fleetSteps   = []string{"fair-addons", "fair-policy", "fair-addons-config"}
	releaseSteps = []string{"fair-namespaces", "fair-secrets", "fair-migrate", "fair-platform", "fair-observability"}
)

// Matches reports whether a Flux revision is the pinned release. Flux
// writes "<tag>@sha256:<hex>" for a tag and "sha256:<hex>" for a digest.
func (p Pin) Matches(revision string) bool {
	tag, digest, found := strings.Cut(revision, "@")
	if !found {
		tag, digest = "", revision
	}
	if tag != "" && tag != p.Tag {
		return false
	}
	if p.Digest != "" {
		return digest == p.Digest
	}
	return tag == p.Tag
}

// Problem returns why f is not the release p reconciled and ready, or "".
func (f Flux) Problem(p Pin) string {
	if !f.Source.Ready {
		return "source fair-release not ready: " + f.Source.Message
	}
	if !p.Matches(f.Source.Revision) {
		return fmt.Sprintf("source fair-release has %q, not %s", f.Source.Revision, p)
	}
	steps := map[string]Step{}
	for _, s := range f.Steps {
		steps[s.Name] = s
	}
	for _, n := range fleetSteps {
		s, ok := steps[n]
		switch {
		case !ok:
			return "no Kustomization " + n
		case !s.Ready:
			return n + " not ready: " + s.Message
		}
	}
	for _, n := range releaseSteps {
		s, ok := steps[n]
		switch {
		case !ok:
			return "no Kustomization " + n
		case !s.Ready:
			return n + " not ready: " + s.Message
		case !p.Matches(s.Revision):
			// fair-migrate on the release means its Job succeeded (wait: true).
			return fmt.Sprintf("%s applied %q, not %s", n, s.Revision, p)
		}
	}
	return ""
}

// Reconciled returns the release the platform step last applied.
func (f Flux) Reconciled() string {
	for _, s := range f.Steps {
		if s.Name == "fair-platform" {
			return s.Revision
		}
	}
	return ""
}

// Live reads health over the network: Flux through each instance's
// Kubernetes API, SLO alerts from the operations account's Prometheus, the
// readiness URLs directly. TLS 1.2 or later everywhere.
type Live struct {
	// Credentials holds <id>/token and <id>/ca.crt for each instance's API
	// server (a read-only Flux viewer's token).
	Credentials string
	Prometheus  string // query API base URL, https
	PromToken   string // optional bearer token file
	PromCA      string // optional CA file (else the system's)
	ReadyCA     string // optional CA file for the readiness URLs
	Timeout     time.Duration
}

var (
	kustomizations = kube.Resource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Plural: "kustomizations", Namespaced: true}
	ocirepos       = kube.Resource{Group: "source.toolkit.fluxcd.io", Version: "v1", Plural: "ocirepositories", Namespaced: true}
)

// Flux lists flux-system's Kustomizations and the release source.
func (l Live) Flux(ctx context.Context, in Instance) (Flux, error) {
	dir := filepath.Join(l.Credentials, in.ID)
	c, err := kube.New(kube.Config{Host: in.Health.Kubernetes, TokenFile: filepath.Join(dir, "token"),
		CAFile: filepath.Join(dir, "ca.crt"), Timeout: l.timeout(), UserAgent: "fair-fleetctl"})
	if err != nil {
		return Flux{}, err
	}
	var f Flux
	srcs, _, err := c.List(ctx, ocirepos, "flux-system")
	if err != nil {
		return Flux{}, err
	}
	found := false
	for _, o := range srcs {
		if o.Metadata.Name != "fair-release" {
			continue
		}
		st, since, err := fluxObject(o.Raw)
		if err != nil {
			return Flux{}, err
		}
		f.Source, f.Since, found = st, since, true
	}
	if !found {
		return Flux{}, errors.New("no OCIRepository flux-system/fair-release")
	}
	ks, _, err := c.List(ctx, kustomizations, "flux-system")
	if err != nil {
		return Flux{}, err
	}
	for _, o := range ks {
		st, _, err := fluxObject(o.Raw)
		if err != nil {
			return Flux{}, err
		}
		f.Steps = append(f.Steps, st)
	}
	sort.Slice(f.Steps, func(i, j int) bool { return f.Steps[i].Name < f.Steps[j].Name })
	return f, nil
}

// fluxObject reads a Flux object's readiness: Ready=True for the current
// generation and not suspended. The time is the artifact's (sources).
func fluxObject(raw []byte) (Step, time.Time, error) {
	var o struct {
		Metadata struct {
			Name       string `json:"name"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Suspend bool `json:"suspend"`
		} `json:"spec"`
		Status struct {
			ObservedGeneration  int64  `json:"observedGeneration"`
			LastAppliedRevision string `json:"lastAppliedRevision"`
			Artifact            *struct {
				Revision       string    `json:"revision"`
				LastUpdateTime time.Time `json:"lastUpdateTime"`
			} `json:"artifact"`
			Conditions []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return Step{}, time.Time{}, fmt.Errorf("flux object: %w", err)
	}
	s := Step{Name: o.Metadata.Name, Revision: o.Status.LastAppliedRevision}
	var since time.Time
	if o.Status.Artifact != nil {
		s.Revision, since = o.Status.Artifact.Revision, o.Status.Artifact.LastUpdateTime
	}
	for _, c := range o.Status.Conditions {
		if c.Type == "Ready" {
			s.Ready, s.Message = c.Status == "True", c.Message
		}
	}
	switch {
	case o.Spec.Suspend:
		s.Ready, s.Message = false, "suspended"
	case o.Status.ObservedGeneration != o.Metadata.Generation:
		s.Ready, s.Message = false, "generation not yet observed"
	}
	return s, since, nil
}

// Ready requires 200 from every readiness URL.
func (l Live) Ready(ctx context.Context, in Instance) error {
	hc, err := l.client(l.ReadyCA)
	if err != nil {
		return err
	}
	for _, u := range in.Health.Readyz {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "fair-fleetctl")
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", u, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %d", u, resp.StatusCode)
		}
	}
	return nil
}

// Alerts asks Prometheus for the SLO alerts (alerts with an slo label,
// deploy/observability/alerts) of the instance that fired at any time
// during the last `over`. Silenced alerts count: a silence mutes a page,
// it does not make an instance healthy.
func (l Live) Alerts(ctx context.Context, in Instance, over time.Duration) ([]string, error) {
	if !idRE.MatchString(in.ID) {
		return nil, fmt.Errorf("instance id %q", in.ID)
	}
	if !strings.HasPrefix(l.Prometheus, "https://") {
		return nil, errors.New("the Prometheus query URL must be https")
	}
	sel := `ALERTS{alertstate="firing",slo!="",fair_instance="` + in.ID + `"}`
	q := sel
	if over > 0 {
		q = fmt.Sprintf("max_over_time(%s[%ds])", sel, int64(math.Ceil(over.Seconds())))
	}
	hc, err := l.client(l.PromCA)
	if err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(l.Prometheus, "/") + "/api/v1/query?" + url.Values{"query": {q}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fair-fleetctl")
	if l.PromToken != "" {
		tok, err := os.ReadFile(l.PromToken)
		if err != nil {
			return nil, fmt.Errorf("prometheus token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("prometheus: %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || body.Status != "success" || body.Data.ResultType != "vector" {
		return nil, fmt.Errorf("prometheus: %d %s %s", resp.StatusCode, body.Status, body.Error)
	}
	var out []string
	for _, r := range body.Data.Result {
		a := r.Metric["alertname"]
		if j := r.Metric["job"]; j != "" {
			a += " (" + j + ")"
		}
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

func (l Live) timeout() time.Duration {
	if l.Timeout <= 0 {
		return 30 * time.Second
	}
	return l.Timeout
}

func (l Live) client(caFile string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		b, err := os.ReadFile(caFile) // #nosec G304 -- an operator-named CA file
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   l.timeout(),
		Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"

	"github.com/rformer/fair-app/internal/chartgate"
	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

const repo = "../.."

// chartPackage is an air-gap package as T-10 writes it, with the chart
// rendered from the repository's manifests (the chart gate's fixture).
func chartPackage(t *testing.T) (dir, keyFile string) {
	t.Helper()
	k := rt.NewKey(t)
	third, err := fleet.LoadThirdParty(filepath.Join(repo, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	components := []string{"iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate",
		"engine-gate", "engine", fleet.OpenBaoComponent, fleet.FairctlComponent, "postgres", "nats", "versitygw", "keycloak"}
	var imgs, extra []rt.Image
	for _, c := range components {
		imgs = append(imgs, rt.Image{Component: c, Repository: fleet.DefaultRegistry + "/fair-" + c})
	}
	for _, tp := range third.Images {
		extra = append(extra, rt.Image{Component: "mirror-" + tp.Name, Repository: fleet.DefaultRegistry + "/mirror/" + tp.Name})
	}
	rbac, err := fleet.ReleaseRBAC(fleet.RBACSources{Deploy: []string{filepath.Join(repo, "deploy/k8s")},
		Hooks: filepath.Join(repo, "deploy/k8s/hooks"), Bundled: filepath.Join(repo, "deploy/bundled")})
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	dir = filepath.Join(base, "fair-v1.2.3-airgap")
	w := rt.Build(t, dir, rt.Release{Key: k, Release: "v1.2.3", Images: imgs, Extra: extra, Amend: func(m *releasemanifest.Manifest) {
		m.RBAC = rbac
		m.EngineValidation = &releasemanifest.EngineValidation{Image: m.Images[releasemanifest.EngineComponent], SuiteVersion: "1",
			EngineVersion: "1", Architecture: "amd64", Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}
	}})
	mirror := map[string]string{}
	all := maps.Clone(w.Images)
	for _, tp := range third.Images {
		mirror[tp.Image] = w.Extra["mirror-"+tp.Name]
		all["mirror-"+tp.Name] = w.Extra["mirror-"+tp.Name]
	}
	src := filepath.Join(t.TempDir(), "chart")
	if err := fleet.RenderChart(fleet.ChartOptions{Options: fleet.Options{Release: "v1.2.3", Images: w.Images, Deploy: filepath.Join(repo, "deploy/k8s"),
		Keys: filepath.Join(repo, "deploy/k8s/keys"), Mirror: mirror}, Hooks: filepath.Join(repo, "deploy/k8s/hooks"),
		Bundled: filepath.Join(repo, "deploy/bundled")}, src); err != nil {
		t.Fatal(err)
	}
	ch, err := loader.LoadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "chart"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := chartutil.Save(ch, filepath.Join(dir, "chart")); err != nil {
		t.Fatal(err)
	}
	pm := &releaseverify.PackageManifest{Format: releaseverify.PackageFormat, Release: "v1.2.3", SourceDate: "2026-11-20T10:00:00Z",
		MinorFirstReleased: "2026-11-01", UpgradeFrom: []string{"v1.0.0"}, Files: rt.ListFiles(t, dir)}
	for _, c := range slices.Sorted(maps.Keys(all)) {
		pm.Images = append(pm.Images, releaseverify.PackageImage{Component: c, Image: all[c]})
	}
	rt.WritePackageManifest(t, dir, k, pm)
	keyFile = filepath.Join(base, "release.pub")
	if err := os.WriteFile(keyFile, rt.PublicPEM(t, k), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, keyFile
}

// cluster is a recording API server serving the chart gate's compliant
// cluster, and a kubeconfig for it.
type cluster struct {
	srv        *httptest.Server
	kubeconfig string
	mu         sync.Mutex
	methods    map[string]int
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	s := objreader.New()
	s.NotServed(kube.ExternalSecrets) // as the chart gate's compliant cluster
	if err := s.AddYAML(bytes.NewReader(chartgate.CompliantCluster)); err != nil {
		t.Fatal(err)
	}
	c := &cluster{methods: map[string]int{}}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.methods[r.Method]++
		c.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		for _, res := range objreader.Resources {
			p := "/api/" + res.Version
			if res.Group != "" {
				p = "/apis/" + res.Group + "/" + res.Version
			}
			ns := ""
			if rest, ok := strings.CutPrefix(r.URL.Path, p+"/namespaces/"); ok && res.Namespaced && strings.HasSuffix(rest, "/"+res.Plural) {
				ns = strings.TrimSuffix(rest, "/"+res.Plural)
			} else if r.URL.Path != p+"/"+res.Plural {
				continue
			}
			objs, _, err := s.List(r.Context(), res, ns)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			items := []json.RawMessage{}
			for _, o := range objs {
				items = append(items, o.Raw)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": items})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(c.srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw})
	kc := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "test",
		"clusters": []any{map[string]any{"name": "test", "cluster": map[string]any{"server": c.srv.URL, "certificate-authority-data": base64.StdEncoding.EncodeToString(ca)}}},
		"users":    []any{map[string]any{"name": "admin", "user": map[string]any{"token": "preflight-test-token"}}},
		"contexts": []any{map[string]any{"name": "test", "context": map[string]any{"cluster": "test", "user": "admin"}}}}
	b, _ := json.Marshal(kc)
	c.kubeconfig = filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(c.kubeconfig, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func preflightSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for _, n := range []string{"fairctl-preflight.schema.json", "fair-preflight-report-v1.schema.json"} {
		b, err := os.ReadFile(filepath.Join(repo, "docs/formats", n)) // #nosec G304 -- a test file
		if err != nil {
			t.Fatal(err)
		}
		sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(n, sd); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile("fairctl-preflight.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// T-13 (AC-15, AC-21, AC-54): fairctl preflight verifies the package,
// renders its chart with the decisions' values, reads the cluster through
// the kubeconfig with GET requests only, prints the report (plain lines or
// one JSON document) and exits 1 when refused; before install the
// release's own endpoints cannot be reached, so tls_endpoints refuses.
func TestPreflightCommand(t *testing.T) {
	pkg, key := chartPackage(t)
	decisions := decisionsFile(t, nil)
	c := newCluster(t)
	args := []string{"preflight", "-kubeconfig", c.kubeconfig, "-decisions", decisions, "-package", pkg, "-key", key}

	r := fairctl(t, nil, args...)
	noEscapes(t, r)
	if r.code != exitRefused || !strings.Contains(r.stdout, "result: refused") || !strings.Contains(r.stdout, "release: v1.2.3") ||
		!strings.Contains(r.stdout, "ok: pod_security_admission") || !strings.Contains(r.stdout, "FAIL: tls_endpoints: endpoint/") {
		t.Fatalf("exit %d\n%s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	t.Logf("%s", r.stdout)
	j := fairctl(t, nil, append(args, "-output", "json")...)
	noEscapes(t, j)
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(j.stdout))
	if err != nil {
		t.Fatalf("%v\n%s", err, j.stdout)
	}
	if err := preflightSchema(t).Validate(inst); err != nil {
		t.Fatalf("%v\n%s", err, j.stdout)
	}
	var doc struct {
		Report struct {
			Purpose, Mode, Profile, Result string
		} `json:"report"`
	}
	_ = json.Unmarshal([]byte(j.stdout), &doc)
	if j.code != exitRefused || doc.Report.Purpose != "check" || doc.Report.Mode != "self-hosted" || doc.Report.Profile != "fedramp-moderate" {
		t.Fatalf("%d %+v", j.code, doc)
	}
	c.mu.Lock()
	methods := maps.Clone(c.methods)
	c.mu.Unlock()
	if len(methods) != 1 || methods[http.MethodGet] == 0 {
		t.Errorf("requests by method: %v (want GET only)", methods)
	}

	t.Run("refusals", func(t *testing.T) {
		errSchema := compileSchema(t, "fairctl-error.schema.json")
		check := func(t *testing.T, r result, code int, msg string) {
			t.Helper()
			noEscapes(t, r)
			if r.code != code || !strings.Contains(r.stderr, msg) {
				t.Fatalf("exit %d (want %d)\n%s%s", r.code, code, r.stdout, r.stderr)
			}
		}
		without := func(flag string) []string {
			var out []string
			for i := 0; i < len(args); i++ {
				if args[i] == "-"+flag {
					i++
					continue
				}
				out = append(out, args[i])
			}
			return out
		}
		for _, f := range []string{"package", "key", "decisions"} {
			check(t, fairctl(t, nil, without(f)...), exitUsage, "-"+f+" is required")
		}
		check(t, fairctl(t, nil, append(args, "-in-cluster")...), exitUsage, "not yet available")
		check(t, fairctl(t, nil, append(args, "-mode", "on-prem")...), exitUsage, "-mode must be saas")
		// A package that does not verify: refused before the cluster is read.
		_, otherKey := chartPackage(t)
		check(t, fairctl(t, nil, append(without("key"), "-key", otherKey)...), exitRefused, "does not verify")
		// Decisions the chart refuses (no API server range).
		nocidr := decisionsFile(t, strings.NewReplacer("  api_server_cidr: 10.0.0.0/24\n", ""))
		check(t, fairctl(t, nil, append(without("decisions"), "-decisions", nocidr)...), exitUsage, "do not give the chart's values")
		// An unreachable cluster: exit 4.
		down := newCluster(t)
		down.srv.Close()
		r := fairctl(t, nil, append(without("kubeconfig"), "-kubeconfig", down.kubeconfig)...)
		check(t, r, 4, "unreachable")
		jr := fairctl(t, nil, append(without("kubeconfig"), "-kubeconfig", down.kubeconfig, "-output", "json")...)
		validateAgainst(t, errSchema, "fairctl-error.schema.json", jr.stdout)
		if !strings.Contains(jr.stdout, `"unreachable"`) || jr.code != 4 {
			t.Fatalf("%d %s", jr.code, jr.stdout)
		}
	})
}

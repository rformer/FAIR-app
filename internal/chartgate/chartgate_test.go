package chartgate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

// F-014 T-09 (F-014-AC-02, AC-03; design §3.17): the chart release gate.

const root = "../.."

// components are the release's images: the platform's, the bundled
// dependencies' (F-014 T-07) and the hooks' (fairctl).
var components = []string{"iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate",
	"engine-gate", "engine", fleet.OpenBaoComponent, fleet.FairctlComponent, "postgres", "nats", "versitygw", "keycloak"}

// releaseImages names each component's image by a digest of its own.
func releaseImages() map[string]string {
	m := map[string]string{}
	for i, c := range components {
		m[c] = fmt.Sprintf("%s/fair-%s@sha256:%064x", fleet.DefaultRegistry, c, i+1)
	}
	return m
}

func thirdParty(t *testing.T) fleet.ThirdPartyList {
	t.Helper()
	l, err := fleet.LoadThirdParty(filepath.Join(root, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// renderChart renders the release's chart from the repository's manifests.
func renderChart(t *testing.T, imgs map[string]string, bundled bool) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "chart")
	o := fleet.ChartOptions{Options: fleet.Options{Release: "v1.2.3", Images: imgs, Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: thirdParty(t).Mirror(fleet.DefaultRegistry + "/mirror")},
		Hooks: filepath.Join(root, "deploy/k8s/hooks")}
	if bundled {
		o.Bundled = filepath.Join(root, "deploy/bundled")
	}
	if err := fleet.RenderChart(o, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// manifestFor is the release manifest releasegen writes for these images:
// RBAC from deploy/k8s, the hooks and the bundled dependencies.
func manifestFor(t *testing.T, imgs map[string]string, bundled bool) *releasemanifest.Manifest {
	t.Helper()
	src := fleet.RBACSources{Deploy: []string{filepath.Join(root, "deploy/k8s")}, Hooks: filepath.Join(root, "deploy/k8s/hooks")}
	if bundled {
		src.Bundled = filepath.Join(root, "deploy/bundled")
	}
	rbac, err := fleet.ReleaseRBAC(src)
	if err != nil {
		t.Fatal(err)
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "v1.2.3", Images: imgs, RBAC: rbac}
	if img, ok := imgs[releasemanifest.EngineComponent]; ok {
		m.EngineValidation = &releasemanifest.EngineValidation{Image: img, SuiteVersion: "1", EngineVersion: "1", Architecture: "amd64",
			Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

func residue(t *testing.T) map[string][]string {
	t.Helper()
	r, err := fleet.BundledResidue(filepath.Join(root, "deploy/bundled"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func options(t *testing.T, chart string, m *releasemanifest.Manifest) Options {
	t.Helper()
	return Options{Chart: chart, Manifest: m, ThirdParty: thirdParty(t), Residue: residue(t)}
}

// TestChartOptionsPassChecks (design §3.17, AC-03): every combination of
// the chart's switches and choices the schema allows renders, and F-015's
// checks find nothing in any of them on the compliant cluster; every image
// is by digest and the release's, every RBAC object the manifest's.
func TestChartOptionsPassChecks(t *testing.T) {
	imgs := releaseImages()
	chart := renderChart(t, imgs, true)
	r, err := Check(context.Background(), options(t, chart, manifestFor(t, imgs, true)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Failures {
		t.Errorf("%s", f)
	}
	wantSwitches := []string{"fipsProbe.enabled", "scanner.enabled"}
	for _, b := range fleet.Bundled {
		wantSwitches = append(wantSwitches, b.Value+".bundled")
	}
	slices.Sort(wantSwitches)
	if !slices.Equal(r.Switches, wantSwitches) {
		t.Errorf("switches %v, want %v", r.Switches, wantSwitches)
	}
	if !slices.Equal(r.Choices, []string{"keyStore.kind", "mode"}) {
		t.Errorf("choices %v", r.Choices)
	}
	// 2^8 switch settings, two key stores, two modes; the schema refuses the
	// bundled Keycloak without the bundled PostgreSQL (a quarter of them).
	if all := 1 << len(wantSwitches) * 2 * 2; r.Rendered+r.Refused != all || r.Refused != all/4 {
		t.Errorf("%d rendered, %d refused of %d", r.Rendered, r.Refused, all)
	}
	if r.Checks != 10 || r.Objects < 100 {
		t.Errorf("%d checks, %d objects", r.Checks, r.Objects)
	}
	t.Logf("%s", r.Summary(AreaRender))
}

// edit changes a template file of the chart.
func edit(t *testing.T, chart, file string, fn func(string) string) {
	t.Helper()
	p := filepath.Join(chart, "templates", file)
	b, err := os.ReadFile(p) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	out := fn(string(b))
	if out == string(b) {
		t.Fatalf("%s: the edit changed nothing", file)
	}
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// dropDoc removes the template documents of a file that contain every
// marker.
func dropDoc(markers ...string) func(string) string {
	return func(s string) string {
		parts := strings.Split(s, "\n---\n")
		var keep []string
		for _, p := range parts {
			all := true
			for _, m := range markers {
				all = all && strings.Contains(p, m)
			}
			if !all {
				keep = append(keep, p)
			}
		}
		return strings.Join(keep, "\n---\n")
	}
}

// TestGateRefuses (design §3.17, §7): the gate refuses a chart that
// differs from the release: a changed image, an image by tag, an added,
// changed or missing RBAC object, a weakened template (a dropped
// readOnlyRootFilesystem, a dropped NetworkPolicy), each by name.
func TestGateRefuses(t *testing.T) {
	imgs := releaseImages()
	iam := releasemanifest.Digest(imgs["iam"])
	cases := []struct {
		name     string
		chart    func(t *testing.T, chart string)
		manifest func(m *releasemanifest.Manifest)
		reason   string
		subject  string   // a substring of the failure's subject
		bundled  []string // the bundled switches enumerated (the others off)
	}{
		{name: "changed image", reason: ReasonImageDiffers, subject: "Deployment/fair-platform/iam",
			chart: func(t *testing.T, c string) {
				edit(t, c, "iam.yaml", func(s string) string { return strings.ReplaceAll(s, iam, "sha256:"+strings.Repeat("e", 64)) })
			}},
		{name: "image by tag", reason: ReasonImageTag, subject: "Deployment/fair-platform/iam",
			chart: func(t *testing.T, c string) {
				edit(t, c, "iam.yaml", func(s string) string { return strings.ReplaceAll(s, "@"+iam, ":1.2.3") })
			}},
		{name: "image not in the release", reason: ReasonImageUnknown, subject: "fair-iam@",
			manifest: func(m *releasemanifest.Manifest) { delete(m.Images, "iam") }},
		{name: "added RBAC object", reason: ReasonRBACUnexpected, subject: "Role/fair-platform/extra",
			chart: func(t *testing.T, c string) {
				edit(t, c, "iam.yaml", func(s string) string {
					return s + "\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: extra\n  namespace: fair-platform\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n  verbs: [list]\n"
				})
			}},
		{name: "changed RBAC object", reason: ReasonRBACChanged, subject: "ClusterRole//fair-preflight",
			chart: func(t *testing.T, c string) {
				edit(t, c, "hooks/preflight.yaml", func(s string) string {
					s = strings.Replace(s, "[namespaces, nodes]", "[namespaces, nodes, secrets]", 1)
					return regexp.MustCompile(`(?m)^(\s*- )namespaces$`).ReplaceAllString(s, "${1}namespaces\n${1}secrets")
				})
			}},
		{name: "missing RBAC object", reason: ReasonRBACMissing, subject: "RoleBinding/fair-platform/posture-scanner",
			chart: func(t *testing.T, c string) {
				edit(t, c, "posture-scanner.yaml", dropDoc("kind: RoleBinding", "name: posture-scanner"))
			}},
		{name: "readOnlyRootFilesystem dropped", reason: ReasonFinding, subject: "pod_hardening workload/fair-platform/Deployment/iam",
			chart: func(t *testing.T, c string) {
				edit(t, c, "iam.yaml", func(s string) string {
					return strings.ReplaceAll(s, "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false")
				})
			}},
		{name: "NetworkPolicy dropped", reason: ReasonFinding, subject: "network_policy",
			chart: func(t *testing.T, c string) {
				edit(t, c, "namespaces.yaml", dropDoc("kind: NetworkPolicy", "namespace: fair-platform"))
			}},
		{name: "bundled template weakened", reason: ReasonFinding, subject: "pod_hardening workload/fair-platform/StatefulSet/nats",
			bundled: []string{"nats.bundled"},
			chart: func(t *testing.T, c string) {
				edit(t, c, "bundled-nats.yaml", func(s string) string {
					return strings.ReplaceAll(s, "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false")
				})
			}},
		{name: "residue changed", reason: ReasonRBACChanged, subject: "ClusterRole//fair-cnpg-manager-read",
			bundled: []string{"postgres.bundled"},
			manifest: func(m *releasemanifest.Manifest) {
				for i, e := range m.RBAC {
					if e.Key() == "ClusterRole//fair-cnpg-manager-read" {
						m.RBAC[i].SHA256 = strings.Repeat("f", 64)
					}
				}
			}},
		{name: "mirrored image changed", reason: ReasonImageDiffers, subject: "mirror/cloudnative-pg@",
			bundled: []string{"postgres.bundled"},
			chart: func(t *testing.T, c string) {
				var d string
				for _, i := range thirdParty(t).Images {
					if i.Name == "cloudnative-pg" {
						d = i.Digest()
					}
				}
				edit(t, c, "bundled-postgres.yaml", func(s string) string { return strings.ReplaceAll(s, d, "sha256:"+strings.Repeat("e", 64)) })
			}},
	}
	base := renderChart(t, imgs, true)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chart := filepath.Join(t.TempDir(), "chart")
			if err := os.CopyFS(chart, os.DirFS(base)); err != nil {
				t.Fatal(err)
			}
			if tc.chart != nil {
				tc.chart(t, chart)
			}
			m := manifestFor(t, imgs, true)
			if tc.manifest != nil {
				tc.manifest(m)
			}
			o := options(t, chart, m)
			o.Fixed = map[string]any{}
			for _, b := range fleet.Bundled {
				if !slices.Contains(tc.bundled, b.Value+".bundled") {
					o.Fixed[b.Value+".bundled"] = false // every bundled render is TestChartOptionsPassChecks'
				}
			}
			r, err := Check(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range r.Failures {
				found = found || f.Reason == tc.reason && strings.Contains(f.Subject, tc.subject) && f.Combinations > 0 && f.Example != ""
			}
			if !found {
				t.Errorf("no %s failure for %s; failures:", tc.reason, tc.subject)
				for _, f := range r.Failures {
					t.Logf("  %s", f)
				}
			}
			if !r.Failed(reasonArea[tc.reason]) {
				t.Errorf("area %s not failed", reasonArea[tc.reason])
			}
		})
	}
}

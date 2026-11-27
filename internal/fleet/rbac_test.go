package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/releasemanifest"
)

// F-014 T-09: the release manifest's RBAC covers deploy/k8s, the chart's
// hooks and the bundled dependencies with fairctl's cluster-scoped objects,
// each marked with when it exists; deploy/k8s alone hashes as before.
func TestReleaseRBAC(t *testing.T) {
	es, err := ReleaseRBAC(RBACSources{Deploy: []string{filepath.Join(root, "deploy/k8s")}, Hooks: filepath.Join(root, "deploy/k8s/hooks"),
		Bundled: filepath.Join(root, "deploy/bundled")})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]releasemanifest.RBACEntry{}
	for _, e := range es {
		got[e.Key()] = e
	}
	want := map[string]string{
		"ClusterRole//fair-preflight":                 releasemanifest.OptionalHook,
		"ClusterRoleBinding//fair-preflight":          releasemanifest.OptionalHook,
		"ClusterRole//fair-posture-scanner":           "scanner.enabled",
		"ClusterRoleBinding//fair-posture-scanner":    "scanner.enabled",
		"Role/fair-platform/posture-scanner":          "scanner.enabled",
		"RoleBinding/fair-platform/posture-scanner":   "scanner.enabled",
		"Role/fair-fips-probe/posture-scanner":        "scanner.enabled",
		"RoleBinding/fair-fips-probe/posture-scanner": "scanner.enabled",
		"Role/fair-data/cnpg-manager":                 "postgres.bundled",
		"RoleBinding/fair-data/cnpg-manager":          "postgres.bundled",
		"ClusterRole//fair-cnpg-manager-read":         "postgres.bundled",
		"ClusterRoleBinding//fair-cnpg-manager-read":  "postgres.bundled",
	}
	if len(got) != len(want) {
		t.Errorf("%d entries, want %d: %v", len(got), len(want), es)
	}
	for key, opt := range want {
		if e, ok := got[key]; !ok || e.Optional != opt {
			t.Errorf("%s: %+v, want optional %q", key, e, opt)
		}
	}
	plain, err := releasemanifest.RBACFromDir(filepath.Join(root, "deploy/k8s"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plain {
		e, ok := got[p.Key()]
		if !ok || e.SHA256 != p.SHA256 {
			t.Errorf("%s: %+v, deploy/k8s hashes %s", p.Key(), e, p.SHA256)
		}
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "v1", Images: map[string]string{"x": "r/x@sha256:" + strings.Repeat("0", 64)}, RBAC: es}
	if err := m.Validate(); err != nil {
		t.Error(err)
	}
	// An object twice is refused.
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join(root, "deploy/k8s/hooks/preflight.yaml")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "copy.yaml"), b, 0o600); err != nil { // #nosec G703 -- a test directory
		t.Fatal(err)
	}
	if _, err := ReleaseRBAC(RBACSources{Deploy: []string{dir}, Hooks: filepath.Join(root, "deploy/k8s/hooks")}); err == nil {
		t.Error("an RBAC object in two files was accepted")
	}
	if r, err := BundledResidue(filepath.Join(root, "deploy/bundled")); err != nil || len(r["postgres.bundled"]) != 1 || len(r) != 1 {
		t.Errorf("residue %v %v", r, err)
	}
}

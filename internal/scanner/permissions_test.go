package scanner

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// F-015 T-30 (AC-39): the committed permission manifest is current, lists
// a purpose for every permission, and grants only reads, never Secrets.
func TestPermissionManifest(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile("../../deploy/k8s/permission-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(committed), "\r\n", "\n") != string(b) {
		t.Fatal("deploy/k8s/permission-manifest.json is stale: run go run ./cmd/releasegen permissions")
	}
	n := 0
	for _, p := range m.Permissions {
		if p.Purpose == "" || !slices.Equal(p.Verbs, []string{"get", "list", "watch"}) || slices.Contains(p.Resources, "secrets") {
			t.Errorf("permission %+v", p)
		}
		n += len(p.Resources)
	}
	if want := len(Access.Cluster) + len(Access.Namespaced) + len(Access.ProbeNamespaced); n != want {
		t.Errorf("%d resources listed, %d read", n, want)
	}
	d1, _ := m.Digest()
	d2, _ := m.Digest()
	if len(d1) != 64 || d1 != d2 {
		t.Fatalf("digest %q %q", d1, d2)
	}
}

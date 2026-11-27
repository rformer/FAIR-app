package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/rformer/fair-app/internal/releasemanifest"
)

// F-014 T-09 (AC-02, AC-03; design §3.17, §7 "the installer or its hooks
// leave cluster-wide rights behind"): the release manifest's RBAC covers
// every RBAC object any installation of the release can hold, each marked
// with when it exists (releasemanifest.RBACEntry.Optional):
//
//   - deploy/k8s: always, but the files a chart switch includes
//     (ChartSwitches: the scanner's RBAC exists only with scanner.enabled);
//   - the chart's hooks (deploy/k8s/hooks): while a hook runs
//     (releasemanifest.OptionalHook);
//   - each bundled dependency (deploy/bundled/<dir>, Bundled): with its
//     switch <value>.bundled, including what fairctl applies at cluster
//     scope for it (its ResidueDir, the CloudNativePG operator's read-only
//     ClusterRole and binding).

// ResidueDir is the subdirectory of a bundled dependency holding what
// fairctl applies for it outside the chart (cluster-scoped objects the
// chart never holds; design §3.3, §10 conflict 3).
const ResidueDir = "cluster"

// RBACSources locate the release's RBAC.
type RBACSources struct {
	// Deploy are reference manifest directories (deploy/k8s, plus a
	// platform's own such as deploy/k8s/openshift), their YAML files only.
	Deploy []string
	// Hooks is the chart's hook directory ("" for none).
	Hooks string
	// Bundled is deploy/bundled ("" for none).
	Bundled string
}

// ReleaseRBAC hashes every RBAC object of the sources with its Optional
// marking, sorted; an object found twice is refused.
func ReleaseRBAC(s RBACSources) ([]releasemanifest.RBACEntry, error) {
	type file struct{ path, optional string }
	var files []file
	for _, dir := range s.Deploy {
		fs, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		sort.Strings(fs)
		for _, f := range fs {
			files = append(files, file{f, ChartSwitches[filepath.Base(f)]})
		}
	}
	if s.Hooks != "" {
		fs, err := filepath.Glob(filepath.Join(s.Hooks, "*.yaml"))
		if err != nil {
			return nil, err
		}
		sort.Strings(fs)
		for _, f := range fs {
			files = append(files, file{f, releasemanifest.OptionalHook})
		}
	}
	if s.Bundled != "" {
		for _, b := range Bundled {
			for _, sub := range []string{b.Dir, filepath.Join(b.Dir, ResidueDir)} {
				fs, err := filepath.Glob(filepath.Join(s.Bundled, sub, "*.yaml"))
				if err != nil {
					return nil, err
				}
				sort.Strings(fs)
				for _, f := range fs {
					if filepath.Base(f) == "kustomization.yaml" {
						continue
					}
					files = append(files, file{f, b.Value + ".bundled"})
				}
			}
		}
	}
	var out []releasemanifest.RBACEntry
	seen := map[string]string{}
	for _, f := range files {
		es, err := releasemanifest.RBACFromFile(f.path, f.optional)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			if prev, dup := seen[e.Key()]; dup {
				return nil, fmt.Errorf("fleet: RBAC %s is in %s and %s", e.Key(), prev, f.path)
			}
			seen[e.Key()] = f.path
			out = append(out, e)
		}
	}
	releasemanifest.SortRBAC(out)
	return out, nil
}

// BundledResidue maps each bundled dependency's switch (<value>.bundled) to
// the files of what fairctl applies for it outside the chart (ResidueDir),
// for the dependencies that have any.
func BundledResidue(bundled string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, b := range Bundled {
		fs, err := filepath.Glob(filepath.Join(bundled, b.Dir, ResidueDir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		if len(fs) == 0 {
			continue
		}
		sort.Strings(fs)
		out[b.Value+".bundled"] = fs
	}
	if _, err := os.Stat(bundled); err != nil {
		return nil, err
	}
	return out, nil
}

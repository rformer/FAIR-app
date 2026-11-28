package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

// F-014 T-09: release-check's chart rows over a chart releasegen would
// write and the release manifest releasegen manifest would write for it.
func TestReleaseCheckChartRows(t *testing.T) {
	const root = "../.."
	imgs := map[string]string{}
	for i, c := range []string{"iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate",
		"engine-gate", "engine", fleet.OpenBaoComponent, fleet.FairctlComponent, "postgres", "nats", "versitygw", "keycloak"} {
		imgs[c] = fmt.Sprintf("%s/fair-%s@sha256:%064x", fleet.DefaultRegistry, c, i+1)
	}
	third, err := fleet.LoadThirdParty(filepath.Join(root, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	chart := filepath.Join(t.TempDir(), "chart")
	if err := fleet.RenderChart(fleet.ChartOptions{Options: fleet.Options{Release: "v1.2.3", Images: imgs, Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: third.Mirror(fleet.DefaultRegistry + "/mirror")},
		Hooks: filepath.Join(root, "deploy/k8s/hooks"), Bundled: filepath.Join(root, "deploy/bundled")}, chart); err != nil {
		t.Fatal(err)
	}
	rbac, err := fleet.ReleaseRBAC(fleet.RBACSources{Deploy: []string{filepath.Join(root, "deploy/k8s")},
		Hooks: filepath.Join(root, "deploy/k8s/hooks"), Bundled: filepath.Join(root, "deploy/bundled")})
	if err != nil {
		t.Fatal(err)
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "v1.2.3", Images: imgs, RBAC: rbac,
		EngineValidation: &releasemanifest.EngineValidation{Image: imgs["engine"], SuiteVersion: "1", EngineVersion: "1",
			Architecture: "amd64", Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}}
	if m.Mirrors, err = third.MirrorsAt(fleet.DefaultRegistry + "/mirror"); err != nil {
		t.Fatal(err)
	}
	b, err := releasemanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "release-manifest.json")
	if err := os.WriteFile(manifest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	in := gateInputs{chart: chart, manifest: manifest, bundled: filepath.Join(root, "deploy/bundled")}
	rows := chartChecks(context.Background(), in)
	if len(rows) != len(chartRows)+1 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if !r.OK {
			t.Errorf("%s: %s", r.Name, r.Detail)
		}
	}
	if !strings.HasPrefix(rows[len(rows)-1].Detail, "skipped") {
		t.Errorf("package row without -package: %+v", rows[len(rows)-1])
	}
	// Without the manifest the chart rows fail; -package needs -key.
	in.manifest, in.pkg = "", t.TempDir()
	rows = chartChecks(context.Background(), in)
	if len(rows) != 2 || rows[0].OK || !strings.Contains(rows[0].Detail, "-manifest") || rows[1].OK || !strings.Contains(rows[1].Detail, "-key") {
		t.Errorf("rows %+v", rows)
	}
}

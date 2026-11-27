package chartgate

import (
	"archive/tar"
	"context"
	"crypto/ecdsa"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"

	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

// F-014 T-09 (AC-02; design §3.1, §3.17): `release-check -package` over a
// fixture package in the format T-11 defines (fair.airgap-package.v1) and
// T-10 builds: the verification kit, the images as OCI layouts with
// signatures and attestations, the chart as chart/fair-platform-<v>.tgz.

type pkgFixture struct {
	dir   string
	key   *ecdsa.PrivateKey
	third fleet.ThirdPartyList // the fixture's mirrored copies
	pm    *releaseverify.PackageManifest
}

// pkgEdits change a fixture package before its package manifest is written.
type pkgEdits struct {
	images  func(map[string]string)              // the images the chart names
	noChart bool                                 // leave the chart out
	pm      func(*releaseverify.PackageManifest) // after the files are listed
}

func buildPackage(t *testing.T, e pkgEdits) *pkgFixture {
	t.Helper()
	k := rt.NewKey(t)
	published := thirdParty(t)
	var imgs, extra []rt.Image
	for _, c := range components {
		imgs = append(imgs, rt.Image{Component: c, Repository: fleet.DefaultRegistry + "/fair-" + c})
	}
	for _, tp := range published.Images {
		extra = append(extra, rt.Image{Component: "mirror-" + tp.Name, Repository: fleet.DefaultRegistry + "/mirror/" + tp.Name})
	}
	rbac, err := fleet.ReleaseRBAC(fleet.RBACSources{Deploy: []string{filepath.Join(root, "deploy/k8s")},
		Hooks: filepath.Join(root, "deploy/k8s/hooks"), Bundled: filepath.Join(root, "deploy/bundled")})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "fair-v1.2.3-airgap")
	w := rt.Build(t, dir, rt.Release{Key: k, Release: "v1.2.3", Images: imgs, Extra: extra, Amend: func(m *releasemanifest.Manifest) {
		m.RBAC = rbac
		m.EngineValidation = &releasemanifest.EngineValidation{Image: m.Images[releasemanifest.EngineComponent], SuiteVersion: "1",
			EngineVersion: "1", Architecture: "amd64", Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}
	}})
	// The package's mirrored copies: the bundled manifests name the
	// publishers' images, the chart their copies (here the fixture's).
	all := map[string]string{}
	f := &pkgFixture{dir: dir, key: k, third: fleet.ThirdPartyList{Format: fleet.ThirdPartyFormat}}
	mirror := map[string]string{}
	for _, tp := range published.Images {
		copyRef := w.Extra["mirror-"+tp.Name]
		all["mirror-"+tp.Name] = copyRef
		mirror[tp.Image] = copyRef
		f.third.Images = append(f.third.Images, fleet.ThirdParty{Name: tp.Name, Image: tp.Repository() + "@" + releasemanifest.Digest(copyRef)})
	}
	chartImgs := map[string]string{}
	for c, ref := range w.Images {
		all[c] = ref
		chartImgs[c] = ref
	}
	if e.images != nil {
		e.images(chartImgs)
	}
	if !e.noChart {
		src := filepath.Join(t.TempDir(), "chart")
		if err := fleet.RenderChart(fleet.ChartOptions{Options: fleet.Options{Release: "v1.2.3", Images: chartImgs, Deploy: filepath.Join(root, "deploy/k8s"),
			Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: mirror}, Hooks: filepath.Join(root, "deploy/k8s/hooks"),
			Bundled: filepath.Join(root, "deploy/bundled")}, src); err != nil {
			t.Fatal(err)
		}
		ch, err := loader.LoadDir(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "chart"), 0o750); err != nil {
			t.Fatal(err)
		}
		p, err := chartutil.Save(ch, filepath.Join(dir, "chart"))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(p) != ChartFile("v1.2.3") {
			t.Fatalf("chart file %s, want %s", p, ChartFile("v1.2.3"))
		}
	}
	pm := &releaseverify.PackageManifest{Format: releaseverify.PackageFormat, Release: "v1.2.3", SourceDate: "2026-11-20T10:00:00Z",
		MinorFirstReleased: "2026-11-01", UpgradeFrom: []string{"v1.0.0", "v1.1.0"}, Files: rt.ListFiles(t, dir)}
	for _, c := range slices.Sorted(maps.Keys(all)) {
		pm.Images = append(pm.Images, releaseverify.PackageImage{Component: c, Image: all[c]})
	}
	if e.pm != nil {
		e.pm(pm)
	}
	rt.WritePackageManifest(t, dir, k, pm)
	f.pm = pm
	return f
}

func (f *pkgFixture) options(t *testing.T) PackageOptions {
	t.Helper()
	return PackageOptions{Path: f.dir, Key: &f.key.PublicKey, Chart: Options{ThirdParty: f.third, Residue: residue(t)}}
}

// quick fixes every bundled switch off but one (the full matrix is
// TestPackageGate's and TestChartOptionsPassChecks').
func quick(o PackageOptions) PackageOptions {
	o.Chart.Fixed = map[string]any{}
	for _, b := range fleet.Bundled {
		if b.Value != "postgres" {
			o.Chart.Fixed[b.Value+".bundled"] = false
		}
	}
	return o
}

// tarDir writes dir as a package tarball (one top directory).
func tarDir(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(dir)+".tar")
	f, err := os.Create(out) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Dir(dir), p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- a test directory
		if err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPackageGate: a package that verifies, whose chart passes every
// combination, as a directory and as its tarball.
func TestPackageGate(t *testing.T) {
	f := buildPackage(t, pkgEdits{})
	for name, o := range map[string]PackageOptions{"directory": f.options(t), "tarball": quick(f.options(t))} {
		t.Run(name, func(t *testing.T) {
			if name == "tarball" {
				o.Path = tarDir(t, f.dir)
			}
			r, err := CheckPackage(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if r.Refusal != nil {
				t.Fatalf("refused: %+v", *r.Refusal)
			}
			for _, x := range r.Chart.Failures {
				t.Errorf("%s", x)
			}
			if r.Failed() || !r.Verify.Verified || r.Chart.Rendered == 0 {
				t.Errorf("failed %v, verified %v, %d rendered", r.Failed(), r.Verify.Verified, r.Chart.Rendered)
			}
		})
	}
}

// TestPackageGateRefuses: a tampered package, a package without its chart,
// a chart naming an image other than the package's, and a mirrored image
// the package does not list are refused by name.
func TestPackageGateRefuses(t *testing.T) {
	cases := []struct {
		name    string
		edits   pkgEdits
		after   func(t *testing.T, f *pkgFixture)
		reason  string
		subject string
	}{
		{name: "tampered", reason: ReasonPackageVerify, after: func(t *testing.T, f *pkgFixture) {
			p := filepath.Join(f.dir, "chart", ChartFile("v1.2.3"))
			b, err := os.ReadFile(p) // #nosec G304 -- a test directory
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, 0), 0o600); err != nil { // #nosec G703 -- a test directory
				t.Fatal(err)
			}
		}},
		{name: "no chart", reason: ReasonPackageChart, subject: ChartFile("v1.2.3"), edits: pkgEdits{noChart: true}},
		{name: "chart image differs", reason: ReasonImageDiffers, subject: "Deployment/fair-platform/iam", edits: pkgEdits{images: func(m map[string]string) {
			m["iam"] = fleet.DefaultRegistry + "/fair-iam@sha256:" + strings.Repeat("e", 64)
		}}},
		{name: "mirrored image not listed", reason: ReasonImageUnlisted, subject: "mirror/cloudnative-pg@", edits: pkgEdits{pm: func(pm *releaseverify.PackageManifest) {
			pm.Images = slices.DeleteFunc(pm.Images, func(i releaseverify.PackageImage) bool { return i.Component == "mirror-cloudnative-pg" })
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildPackage(t, tc.edits)
			if tc.after != nil {
				tc.after(t, f)
			}
			r, err := CheckPackage(context.Background(), quick(f.options(t)))
			if err != nil {
				t.Fatal(err)
			}
			if !r.Failed() {
				t.Fatal("the package passed")
			}
			var got []Failure
			if r.Refusal != nil {
				got = append(got, *r.Refusal)
			}
			if r.Chart != nil {
				got = append(got, r.Chart.Failures...)
			}
			if !slices.ContainsFunc(got, func(x Failure) bool { return x.Reason == tc.reason && strings.Contains(x.Subject, tc.subject) }) {
				t.Errorf("no %s %q failure in %+v", tc.reason, tc.subject, got)
			}
		})
	}
}

package airgap_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/santhosh-tekuri/jsonschema/v6"
	yaml "go.yaml.in/yaml/v3"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"

	"github.com/rformer/fair-app/internal/airgap"
	"github.com/rformer/fair-app/internal/chartgate"
	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

const root = "../.."

// components are every image the chart can run (as chartgate's tests).
var components = []string{"iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate",
	"engine-gate", "engine", fleet.OpenBaoComponent, fleet.FairctlComponent, "postgres", "nats", "versitygw", "keycloak"}

func put(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil { // #nosec G703 -- a test directory
		t.Fatal(err)
	}
}

func sign(t *testing.T, k *ecdsa.PrivateKey, b []byte) []byte {
	t.Helper()
	sig, err := profilepkg.Sign(k, b)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func publicPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// packageManifest lists dir's files and the manifest's images.
func packageManifest(t *testing.T, dir string, manifest []byte) []byte {
	t.Helper()
	var m releasemanifest.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	files, err := airgap.ListFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	pm := releaseverify.PackageManifest{Format: releaseverify.PackageFormat, Release: m.Release, SourceDate: "2026-11-20T10:00:00Z",
		MinorFirstReleased: "2026-11-01", UpgradeFrom: []string{}, Files: files}
	imgs := airgap.Images(&m)
	for _, c := range slices.Sorted(mapKeys(imgs)) {
		pm.Images = append(pm.Images, releaseverify.PackageImage{Component: c, Image: imgs[c]})
	}
	b, err := profilepkg.Encode(pm)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// writeSigned writes name and its release-key signature.
func writeSigned(t *testing.T, dir string, k *ecdsa.PrivateKey, name string, b []byte) {
	t.Helper()
	put(t, dir, name, b)
	put(t, dir, name+".sig", sign(t, k, b))
}

// writeChecksums writes and signs SHA256SUMS over dir's listed files.
func writeChecksums(t *testing.T, dir string, k *ecdsa.PrivateKey) {
	t.Helper()
	files, err := airgap.ListFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range files {
		b.WriteString(f.SHA256 + "  " + f.Path + "\n")
	}
	writeSigned(t, dir, k, releaseverify.ChecksumsFile, []byte(b.String()))
}

// zarfPackage writes a Zarf package as `zarf package create` lays it out
// (zarf.yaml, checksums.txt, components/, images/ as an OCI layout,
// zarf.bundle.sig), zstd-compressed.
func zarfPackage(t *testing.T, file string, cfg []byte, layout string) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	add := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	add("zarf.yaml", cfg)
	add("components/fair-platform.tar", []byte("component"))
	if err := tw.WriteHeader(&tar.Header{Name: "images/", Mode: 0o755, Typeflag: tar.TypeDir, ModTime: time.Unix(0, 0)}); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(layout, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(layout, p)
		b, err := os.ReadFile(p) // #nosec G304 G122 -- a test directory
		if err != nil {
			return err
		}
		add("images/"+filepath.ToSlash(rel), b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	add("checksums.txt", []byte("zarf's own\n"))
	add("zarf.bundle.sig", []byte("{}"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Dir(file), filepath.Base(file), out.Bytes())
}

// fixture is a fixture release turned into an air-gap package.
type fixture struct {
	key   *ecdsa.PrivateKey
	dir   string // the package
	pm    *releaseverify.PackageManifest
	zarf  []byte // zarf.yaml
	cfg   map[string]any
	third fleet.ThirdPartyList
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// build makes a release from releasetest (every chart component, the
// third-party list's images as mirrors, the release's RBAC), renders its
// chart, writes a Zarf package holding its images, and builds the package.
func build(t *testing.T) *fixture {
	t.Helper()
	const release = "v1.2.3"
	k := rt.NewKey(t)
	third, err := fleet.LoadThirdParty(filepath.Join(root, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	var imgs, mirrors []rt.Image
	for _, c := range components {
		imgs = append(imgs, rt.Image{Component: c, Repository: fleet.DefaultRegistry + "/fair-" + c, Mode: rt.Tag})
	}
	for _, tp := range third.Images {
		mirrors = append(mirrors, rt.Image{Component: tp.Name, Repository: fleet.DefaultRegistry + "/mirror/" + tp.Name, Mode: rt.Tag})
	}
	rbac, err := fleet.ReleaseRBAC(fleet.RBACSources{Deploy: []string{filepath.Join(root, "deploy/k8s")},
		Hooks: filepath.Join(root, "deploy/k8s/hooks"), Bundled: filepath.Join(root, "deploy/bundled")})
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	releaseDir := filepath.Join(tmp, "release")
	layout := filepath.Join(tmp, "zarf-build", "images")
	files := map[string][]byte{
		"component-definition.json": []byte(`{"component-definition": {}}`),
		"manifest.json":             []byte(`{"packages": []}`),
		"profile-x-1.0.0.json":      []byte(`{"profile": "x"}`),
		"release-notes.md":          []byte("# FAIR v1.2.3\n"),
	}
	for _, f := range []string{"manifest.json", "profile-x-1.0.0.json"} {
		files[f+".sig"] = sign(t, k, files[f])
	}
	toolsDir := filepath.Join(tmp, "tools")
	for _, p := range airgap.Platforms {
		ext := ""
		if strings.HasPrefix(p, "windows-") {
			ext = ".exe"
		}
		files["fairctl-"+release+"-"+p+ext] = []byte("fairctl " + p)
		files["fair-audit-verify-"+release+"-"+p+ext] = []byte("fair-audit-verify " + p)
		put(t, toolsDir, "releasegen-"+release+"-"+p+ext, []byte("releasegen "+p))
	}
	w := rt.Build(t, releaseDir, rt.Release{Key: k, Release: release, Images: imgs, Mirrors: mirrors, LayoutDir: layout, Files: files,
		Amend: func(m *releasemanifest.Manifest) {
			m.RBAC = rbac
			m.EngineValidation = &releasemanifest.EngineValidation{Image: m.Images[releasemanifest.EngineComponent], SuiteVersion: "1",
				EngineVersion: "1", Architecture: "amd64", Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}
		}})
	// The chart, naming the release's images and the mirrored copies.
	mirror := map[string]string{}
	for _, tp := range third.Images {
		mirror[tp.Image] = w.Mirrors[tp.Name]
	}
	src := filepath.Join(tmp, "chart-src")
	if err := fleet.RenderChart(fleet.ChartOptions{Options: fleet.Options{Release: release, Images: w.Images, Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: mirror}, Hooks: filepath.Join(root, "deploy/k8s/hooks"),
		Bundled: filepath.Join(root, "deploy/bundled")}, src); err != nil {
		t.Fatal(err)
	}
	ch, err := loader.LoadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	chart, err := chartutil.Save(ch, tmp)
	if err != nil {
		t.Fatal(err)
	}
	// zarf.yaml and the Zarf package (what zarf package create makes of it).
	mb, err := os.ReadFile(filepath.Join(releaseDir, releaseverify.ReleaseManifestFile)) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	var m releasemanifest.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	cfg, err := airgap.ZarfConfig(&m, filepath.Base(chart), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	zarf := filepath.Join(tmp, airgap.ZarfFile(release, "amd64"))
	zarfPackage(t, zarf, cfg, layout)
	notes := filepath.Join(tmp, "notes")
	put(t, notes, release+".md", files["release-notes.md"])
	put(t, notes, "v1.1.0.md", []byte("# FAIR v1.1.0\n"))
	out := filepath.Join(tmp, airgap.PackageDir(release))
	pm, err := airgap.Build(airgap.BuildOptions{Release: release, ReleaseDir: releaseDir, Tools: toolsDir, Chart: chart, Zarf: zarf, Notes: notes,
		Root: root, SourceDate: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC), MinorFirstReleased: "2026-11-01",
		UpgradeFrom: []string{"v1.0.0", "v1.1.0"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	// The pipeline's signing step (releasegen sign -any).
	for _, f := range []string{releaseverify.PackageManifestFile, releaseverify.ChecksumsFile} {
		b, err := os.ReadFile(filepath.Join(out, f)) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		put(t, out, f+".sig", sign(t, k, b))
	}
	var doc map[string]any
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	return &fixture{key: k, dir: out, pm: pm, zarf: cfg, cfg: doc, third: third}
}

// TestPackageContents (F-014 T-10; AC-01, AC-02, AC-04; design §3.1,
// D-OQ4): a package built from a fixture release holds every required
// path; package-manifest.json lists every file (and SHA256SUMS the same)
// and verifies with releaseverify, the images read from the Zarf package's
// own layout, once; the release-check package gate passes on it.
func TestPackageContents(t *testing.T) {
	f := build(t)
	const release = "v1.2.3"
	required := []string{
		airgap.ZarfFile(release, "amd64"), airgap.ChartPath(release),
		"release-manifest.json", "release-manifest.json.sig", "cosign.pub",
		"SHA256SUMS", "SHA256SUMS.sig", "package-manifest.json", "package-manifest.json.sig",
		"content/profiles/manifest.json", "content/profiles/manifest.json.sig", "content/profiles/profile-x-1.0.0.json",
		"content/frameworks/shipped.json.gz", "content/starter-library/starter.json", "content/question-bank/questions.json",
		"compliance/component-definition.json",
		"docs/security/verify.md", "docs/formats/fair-airgap-package-v1.md", "docs/install/keys.md",
		"notes/" + release + ".md", "notes/v1.1.0.md", "platforms.json",
	}
	for _, tool := range airgap.Tools {
		for _, p := range airgap.Platforms {
			name := "tools/" + tool + "-" + release + "-" + p
			if strings.HasPrefix(p, "windows-") {
				name += ".exe"
			}
			required = append(required, name)
		}
	}
	var present []string
	err := filepath.WalkDir(f.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(f.dir, p)
		present = append(present, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range required {
		if !slices.Contains(present, r) {
			t.Errorf("no %s in the package", r)
		}
	}
	// D-OQ4: the images are only in the Zarf package.
	for _, p := range present {
		if strings.HasPrefix(p, "images/") || path.Base(p) == "index.json" || strings.Contains(p, "/blobs/") {
			t.Errorf("%s: an image outside the Zarf package", p)
		}
	}
	// package-manifest.json lists every file but itself, SHA256SUMS and
	// their signatures; SHA256SUMS the same files.
	listed := map[string]string{}
	for _, x := range f.pm.Files {
		listed[x.Path] = x.SHA256
	}
	sums, err := os.ReadFile(filepath.Join(f.dir, "SHA256SUMS")) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	cs, err := releaseverify.ParseChecksums(sums)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != len(listed) {
		t.Errorf("SHA256SUMS lists %d files, the package manifest %d", len(cs), len(listed))
	}
	for _, c := range cs {
		if listed[c.Path] != c.SHA256 {
			t.Errorf("SHA256SUMS: %s differs from the package manifest", c.Path)
		}
	}
	for _, p := range present {
		switch p {
		case "package-manifest.json", "package-manifest.json.sig", "SHA256SUMS", "SHA256SUMS.sig":
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.dir, filepath.FromSlash(p))) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		if listed[p] != hexSum(b) {
			t.Errorf("%s: not listed with its digest", p)
		}
	}
	// Every release image and every mirrored copy, by reference.
	mb, _ := os.ReadFile(filepath.Join(f.dir, "release-manifest.json")) // #nosec G304 -- a test directory
	var m releasemanifest.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Mirrors) != len(f.third.Images) {
		t.Errorf("%d mirrors in the release manifest, %d third-party images", len(m.Mirrors), len(f.third.Images))
	}
	if len(f.pm.Images) != len(m.Images)+len(m.Mirrors) {
		t.Errorf("%d package images for %d images and %d mirrors", len(f.pm.Images), len(m.Images), len(m.Mirrors))
	}
	for _, x := range m.Mirrors {
		if !slices.Contains(f.pm.Images, releaseverify.PackageImage{Component: x.Component, Image: x.Image}) {
			t.Errorf("mirror %s is not a package image", x.Component)
		}
	}
	// zarf.yaml pulls each image, its signatures, and the release's
	// attestations.
	if want := airgap.ZarfImages(&m); len(want) != 2*len(m.Mirrors)+3*len(m.Images) {
		t.Errorf("zarf.yaml pulls %d references", len(want))
	}
	// The package verifies, as fairctl verify verifies it.
	layout, cleanup, err := airgap.Layout(f.dir, &f.key.PublicKey, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	r := releaseverify.Verify(f.dir, releaseverify.Options{Key: &f.key.PublicKey, Package: true, Provenance: releaseverify.ReleasePolicy(), Layout: layout})
	if !r.Verified {
		t.Fatalf("refused: %+v", r.Refusal)
	}
	if len(r.Images) != len(f.pm.Images) {
		t.Errorf("%d images verified, %d listed", len(r.Images), len(f.pm.Images))
	}
	// The release gate: chartgate.CheckPackage over the package (its
	// layout found in the Zarf package), every combination of the
	// dependency switches but the bundled ones fixed off save PostgreSQL.
	residue, err := fleet.BundledResidue(filepath.Join(root, "deploy/bundled"))
	if err != nil {
		t.Fatal(err)
	}
	fixed := map[string]any{}
	for _, b := range fleet.Bundled {
		if b.Value != "postgres" {
			fixed[b.Value+".bundled"] = false
		}
	}
	gr, err := chartgate.CheckPackage(context.Background(), chartgate.PackageOptions{Path: f.dir, Key: &f.key.PublicKey,
		Chart: chartgate.Options{Residue: residue, Fixed: fixed}})
	if err != nil {
		t.Fatal(err)
	}
	if gr.Refusal != nil {
		t.Fatalf("gate refused: %+v", *gr.Refusal)
	}
	for _, x := range gr.Chart.Failures {
		t.Errorf("gate: %s", x)
	}
	if gr.Failed() || gr.Chart.Rendered == 0 {
		t.Errorf("gate failed %v, %d rendered", gr.Failed(), gr.Chart.Rendered)
	}
}

// A changed Zarf package, an unlisted file and a missing tool are refused.
func TestPackageRefuses(t *testing.T) {
	f := build(t)
	verify := func(t *testing.T) *releaseverify.Report {
		t.Helper()
		layout, cleanup, err := airgap.Layout(f.dir, &f.key.PublicKey, t.TempDir())
		if err == nil {
			defer cleanup()
		}
		return releaseverify.Verify(f.dir, releaseverify.Options{Key: &f.key.PublicKey, Package: true, Layout: layout})
	}
	t.Run("unlisted file", func(t *testing.T) {
		put(t, f.dir, "tools/extra", []byte("x"))
		defer func() { _ = os.Remove(filepath.Join(f.dir, "tools", "extra")) }()
		if r := verify(t); r.Verified || r.Refusal.Subject != "tools/extra" {
			t.Errorf("verified %v, refusal %+v", r.Verified, r.Refusal)
		}
	})
	t.Run("changed Zarf package", func(t *testing.T) {
		zf := filepath.Join(f.dir, airgap.ZarfFile("v1.2.3", "amd64"))
		b, err := os.ReadFile(zf) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		put(t, f.dir, filepath.Base(zf), append(slices.Clone(b), 0))
		defer put(t, f.dir, filepath.Base(zf), b)
		if _, _, err := airgap.Layout(f.dir, &f.key.PublicKey, t.TempDir()); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("layout read: %v", err)
		}
		if r := verify(t); r.Verified {
			t.Error("verified")
		}
	})
	t.Run("foreign key", func(t *testing.T) {
		if _, _, err := airgap.Layout(f.dir, &rt.NewKey(t).PublicKey, t.TempDir()); err == nil {
			t.Error("a package manifest signed by another key was read")
		}
	})
}

// zarf.yaml is a current Zarf package definition: zarf.dev/v1beta1, valid
// against the schema of the Zarf release the pipeline runs
// (third_party/zarf, pinned by SHA-256), naming the chart and only images
// by digest or by cosign's signature and attestation tags.
func TestZarfConfig(t *testing.T) {
	var man struct {
		Version string `json:"zarf_version"`
		API     string `json:"package_api_version"`
		License string `json:"license"`
		Files   []struct {
			Path, SHA256 string
		} `json:"files"`
	}
	mb, err := os.ReadFile(filepath.Join(root, "third_party/zarf/MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	if man.Version != airgap.ZarfVersion || man.API != airgap.ZarfAPIVersion || man.License != "Apache-2.0" {
		t.Errorf("third_party/zarf is %s (%s, %s); internal/airgap names %s (%s)", man.Version, man.API, man.License, airgap.ZarfVersion, airgap.ZarfAPIVersion)
	}
	for _, x := range man.Files {
		b, err := os.ReadFile(filepath.Join(root, "third_party/zarf", x.Path)) // #nosec G304 -- the repository's pinned file
		if err != nil || hexSum(b) != x.SHA256 {
			t.Errorf("third_party/zarf/%s: not the pinned bytes (%v)", x.Path, err)
		}
	}
	// The pinned image the release pipeline runs is the same Zarf release.
	wf, err := os.ReadFile(filepath.Join(root, "scripts/airgap-package.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wf), "ghcr.io/zarf-dev/zarf/agent:"+airgap.ZarfVersion+"@sha256:") {
		t.Errorf("scripts/airgap-package.sh does not pin Zarf %s by digest", airgap.ZarfVersion)
	}
	sch, err := os.Open(filepath.Join(root, "third_party/zarf/zarf.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sch.Close() }()
	doc, err := jsonschema.UnmarshalJSON(sch)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("zarf.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("zarf.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	f := build(t)
	j, err := json.Marshal(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(j))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Errorf("zarf.yaml is not a valid Zarf %s package: %v", airgap.ZarfVersion, err)
	}
	// A v1alpha1 document is refused by the same schema's v1beta1 rules
	// when it uses v1beta1's fields (the check above is not vacuous).
	bad := map[string]any{"apiVersion": airgap.ZarfAPIVersion, "kind": "ZarfPackageConfig", "metadata": map[string]any{"name": "x"},
		"components": []any{map[string]any{"name": "c", "required": true}}}
	j, _ = json.Marshal(bad)
	inst, _ = jsonschema.UnmarshalJSON(bytes.NewReader(j))
	if s.Validate(inst) == nil {
		t.Error("the schema accepts v1alpha1's component field required under v1beta1")
	}
	if f.cfg["apiVersion"] != airgap.ZarfAPIVersion {
		t.Errorf("apiVersion %v", f.cfg["apiVersion"])
	}
	comps, _ := f.cfg["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("%d components", len(comps))
	}
	images, _ := comps[0].(map[string]any)["images"].([]any)
	for _, i := range images {
		name, _ := i.(map[string]any)["name"].(string)
		if releasemanifest.Digest(name) == "" && !strings.HasSuffix(name, ".sig") && !strings.HasSuffix(name, ".att") {
			t.Errorf("zarf.yaml pulls %s by tag", name)
		}
	}
	if _, err := airgap.ZarfConfig(&releasemanifest.Manifest{Format: releasemanifest.Format, Release: "v1", Images: map[string]string{"x": "r/x:1"}}, "c.tgz", "amd64"); err == nil {
		t.Error("an invalid manifest was accepted")
	}
}

// The names the package uses agree with the chart's and the gate's.
func TestNames(t *testing.T) {
	if airgap.PackageName != fleet.ChartName {
		t.Errorf("PackageName %s, chart %s", airgap.PackageName, fleet.ChartName)
	}
	if path.Base(airgap.ChartPath("v1.2.3")) != chartgate.ChartFile("v1.2.3") {
		t.Errorf("chart path %s, gate %s", airgap.ChartPath("v1.2.3"), chartgate.ChartFile("v1.2.3"))
	}
	if z := airgap.ZarfFile("v1.2.3", "amd64"); z != "zarf-package-fair-platform-amd64-v1.2.3.tar.zst" || !airgap.ZarfFileRE.MatchString(z) {
		t.Errorf("Zarf file %s", z)
	}
}

// deploy/platforms.json is a valid fair.platforms.v1 document whose minimum
// is the chart's kubeVersion.
func TestPlatforms(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "deploy", airgap.PlatformsFile))
	if err != nil {
		t.Fatal(err)
	}
	p, err := airgap.ParsePlatforms(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := ">=" + p.Kubernetes.Minimum + ".0-0"; fleet.MinKubeVersion != want {
		t.Errorf("platforms.json minimum %s, the chart's kubeVersion %s", p.Kubernetes.Minimum, fleet.MinKubeVersion)
	}
	for name, edit := range map[string]func(string) string{
		"format":       func(s string) string { return strings.Replace(s, "fair.platforms.v1", "fair.platforms.v2", 1) },
		"verification": func(s string) string { return strings.Replace(s, `"recorded"`, `"maybe"`, 1) },
		"unknown":      func(s string) string { return strings.Replace(s, `"format"`, `"x": 1, "format"`, 1) },
		"old tested":   func(s string) string { return strings.Replace(s, `"1.34"`, `"1.20"`, 1) },
	} {
		if _, err := airgap.ParsePlatforms([]byte(edit(string(b)))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ExtractImages takes only images/ and refuses entries outside it.
func TestExtractImages(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, entries map[string]string) string {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		for _, n := range slices.Sorted(mapKeys(entries)) {
			_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(entries[n])), Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte(entries[n]))
		}
		_ = tw.Close()
		p := filepath.Join(dir, name)
		put(t, dir, name, raw.Bytes())
		return p
	}
	ok := write("ok.tar", map[string]string{"zarf.yaml": "x", "images/index.json": "{}", "images/oci-layout": "{}", "components/c.tar": "c"})
	into := t.TempDir()
	if err := airgap.ExtractImages(ok, into); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(into, "zarf.yaml")); err == nil {
		t.Error("zarf.yaml was extracted")
	}
	if _, err := os.Stat(filepath.Join(into, "images", "index.json")); err != nil {
		t.Error(err)
	}
	for name, entries := range map[string]map[string]string{
		"escape.tar":    {"images/../../x": "x"},
		"no-images.tar": {"zarf.yaml": "x"},
	} {
		if err := airgap.ExtractImages(write(name, entries), t.TempDir()); err == nil {
			t.Errorf("%s: extracted", name)
		}
	}
}

// The release pipeline builds every image the chart can run, gates the
// chart and the package, and builds, signs and publishes both (F-014 T-10;
// design §3.17).
func TestReleaseJobs(t *testing.T) {
	type job struct {
		Needs    any `yaml:"needs"`
		Strategy struct {
			Matrix struct {
				Component []string `yaml:"component"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		With  map[string]any `yaml:"with"`
		Steps []struct {
			Run string `yaml:"run"`
		} `yaml:"steps"`
	}
	read := func(name string) (map[string]job, string) {
		b, err := os.ReadFile(filepath.Join(root, ".github/workflows", name)) // #nosec G304 -- the repository's workflow
		if err != nil {
			t.Fatal(err)
		}
		var w struct {
			Jobs map[string]job `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(b, &w); err != nil {
			t.Fatal(err)
		}
		return w.Jobs, string(b)
	}
	jobs, _ := read("release.yml")
	for _, name := range []string{"build", "provenance"} {
		for _, c := range components {
			if !slices.Contains(jobs[name].Strategy.Matrix.Component, c) {
				t.Errorf("release.yml %s does not build %s", name, c)
			}
		}
	}
	runs := func(j job) string {
		var b strings.Builder
		for _, s := range j.Steps {
			b.WriteString(s.Run + "\n")
		}
		return b.String()
	}
	for name, want := range map[string][]string{
		"manifest":          {"-mirrors release/mirror.json"},
		"chart":             {"releasegen chart", "-registry \"$RELEASE\"", "releasegen push-chart", "cosign sign --yes"},
		"release-checklist": {"-chart release-chart/"},
		"package":           {"cosign sign-blob --yes --bundle", "release-check", "-package"},
		"publish":           {"release/chart.json"},
		"verify":            {"fairctl verify", "verify-blob"},
	} {
		got := runs(jobs[name])
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("release.yml %s does not run %q", name, w)
			}
		}
	}
	if jobs["sign"].With["package"] != true {
		t.Error("release.yml sign does not build the air-gap package")
	}
	_, sign := read("release-sign.yml")
	for _, w := range []string{"scripts/airgap-package.sh", "Sign the chart with the release key"} {
		if !strings.Contains(sign, w) {
			t.Errorf("release-sign.yml has no %q", w)
		}
	}
}

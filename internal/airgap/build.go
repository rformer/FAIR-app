package airgap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
)

// Platforms are the operating systems and architectures the package's
// tools are built for (scripts/fairctl-dist.sh, audit-verify-dist.sh).
var Platforms = []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"}

// Tools are the binaries tools/ holds for each platform:
// <tool>-<release>-<os>-<arch>[.exe].
var Tools = []string{"fairctl", "fair-audit-verify", "releasegen"}

// Content are the reference data the images embed, copied to content/ so
// an assessor can read them (design §3.1): repository path -> package
// path. The profile packages come from the signed release (ReleaseDir).
var Content = map[string]string{
	"internal/framework/content/shipped.json.gz": "content/frameworks/shipped.json.gz",
	"internal/risk/starter/starter.json":         "content/starter-library/starter.json",
	"internal/estimate/bank/questions.json":      "content/question-bank/questions.json",
}

// Docs are the documents docs/ holds (the offline site, design §3.15,
// comes with its task): repository path patterns.
var Docs = []string{
	"docs/security/verify.md",
	"docs/install/*.md",
	"docs/formats/fair-airgap-package-v1.md",
	"docs/formats/fair-install-decisions-v1.md",
	"docs/formats/fairctl-*.schema.json",
}

// PlatformsFile is the supported Kubernetes versions and distributions
// (OQ14), deploy/platforms.json in the repository.
const PlatformsFile = "platforms.json"

// BuildOptions are Build's inputs.
type BuildOptions struct {
	// Release is the release (vX.Y.Z).
	Release string
	// ReleaseDir holds the signed release's files: release-manifest.json
	// and .sig, cosign.pub, component-definition.json, the profile
	// packages (manifest.json, profile-*.json and their .sig), and the
	// fairctl-* and fair-audit-verify-* binaries.
	ReleaseDir string
	// Tools holds further binaries for tools/ (releasegen-*).
	Tools string
	// Chart is the packaged chart (fair-platform-<v>.tgz), the one Zarf
	// holds.
	Chart string
	// Zarf is the signed Zarf package (ZarfFile).
	Zarf string
	// Notes holds the release notes of every release in the upgrade
	// window, <release>.md each; this release's is required.
	Notes string
	// Root is the repository root (content, docs, deploy/platforms.json).
	Root string
	// SourceDate is the release commit's time.
	SourceDate time.Time
	// MinorFirstReleased is the day the release's minor line was first
	// released (YYYY-MM-DD).
	MinorFirstReleased string
	// UpgradeFrom are the releases this one upgrades from.
	UpgradeFrom []string
	// Out is the package directory (created; must not exist).
	Out string
}

var notesRE = regexp.MustCompile(`^(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)\.md$`)

// Build writes the package directory, package-manifest.json and SHA256SUMS
// (both unsigned: `releasegen sign -any` signs them) and returns the
// package manifest.
func Build(o BuildOptions) (*releaseverify.PackageManifest, error) {
	if o.Out == "" || o.Release == "" {
		return nil, errors.New("airgap: the release and the output directory are required")
	}
	if _, err := os.Stat(o.Out); err == nil {
		return nil, fmt.Errorf("airgap: %s exists", o.Out)
	}
	// Read as signed; the package's verification checks the signature.
	m, err := readManifest(filepath.Join(o.ReleaseDir, releaseverify.ReleaseManifestFile))
	if err != nil {
		return nil, err
	}
	if m.Release != o.Release {
		return nil, fmt.Errorf("airgap: the release manifest is %s, not %s", m.Release, o.Release)
	}
	if base := path.Base(filepath.ToSlash(o.Zarf)); !ZarfFileRE.MatchString(base) || !strings.Contains(base, "-"+o.Release+".tar") {
		return nil, fmt.Errorf("airgap: %s is not this release's Zarf package (%s)", base, ZarfFile(o.Release, Architectures[0]))
	}
	if path.Base(filepath.ToSlash(o.Chart)) != path.Base(ChartPath(o.Release)) {
		return nil, fmt.Errorf("airgap: the chart must be %s", path.Base(ChartPath(o.Release)))
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil { // #nosec G301 -- a public release artifact
		return nil, err
	}
	b := &builder{out: o.Out}
	// The verification kit.
	for _, f := range []string{releaseverify.ReleaseManifestFile, releaseverify.ReleaseManifestFile + ".sig", releaseverify.ReleaseKeyFile} {
		b.copy(filepath.Join(o.ReleaseDir, f), f)
	}
	b.copy(o.Zarf, path.Base(filepath.ToSlash(o.Zarf)))
	b.copy(o.Chart, ChartPath(o.Release))
	// tools/
	for _, t := range Tools {
		for _, p := range Platforms {
			name := t + "-" + o.Release + "-" + p
			if strings.HasPrefix(p, "windows-") {
				name += ".exe"
			}
			src := filepath.Join(o.ReleaseDir, name)
			if _, err := os.Stat(src); err != nil && o.Tools != "" {
				src = filepath.Join(o.Tools, name)
			}
			b.copy(src, "tools/"+name)
		}
	}
	// content/: the signed profile packages, then the embedded data.
	profiles, err := filepath.Glob(filepath.Join(o.ReleaseDir, "profile-*.json"))
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		b.fail(errors.New("no profile packages (profile-*.json) in the release"))
	}
	for _, p := range append(profiles, filepath.Join(o.ReleaseDir, "manifest.json")) {
		b.copy(p, "content/profiles/"+filepath.Base(p))
		b.copy(p+".sig", "content/profiles/"+filepath.Base(p)+".sig")
	}
	for _, src := range slices.Sorted(maps.Keys(Content)) {
		b.copy(filepath.Join(o.Root, filepath.FromSlash(src)), Content[src])
	}
	// compliance/: the component definition (the responsibility matrix
	// joins it with design §3.13's task).
	b.copy(filepath.Join(o.ReleaseDir, "component-definition.json"), "compliance/component-definition.json")
	// docs/
	for _, pat := range Docs {
		fs, err := filepath.Glob(filepath.Join(o.Root, filepath.FromSlash(pat)))
		if err != nil {
			return nil, err
		}
		if len(fs) == 0 {
			b.fail(fmt.Errorf("no %s in the repository", pat))
		}
		for _, f := range fs {
			rel, err := filepath.Rel(o.Root, f)
			if err != nil {
				return nil, err
			}
			b.copy(f, filepath.ToSlash(rel))
		}
	}
	// notes/
	notes, err := os.ReadDir(o.Notes)
	if err != nil {
		return nil, err
	}
	own := false
	for _, n := range notes {
		mm := notesRE.FindStringSubmatch(n.Name())
		if mm == nil || !n.Type().IsRegular() {
			b.fail(fmt.Errorf("notes: %s is not <release>.md", n.Name()))
			continue
		}
		own = own || mm[1] == o.Release
		b.copy(filepath.Join(o.Notes, n.Name()), "notes/"+n.Name())
	}
	if !own {
		b.fail(fmt.Errorf("notes: no %s.md", o.Release))
	}
	// platforms.json
	pb, err := os.ReadFile(filepath.Join(o.Root, "deploy", PlatformsFile)) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, err
	}
	if _, err := ParsePlatforms(pb); err != nil {
		b.fail(err)
	}
	b.write(PlatformsFile, pb)
	if err := errors.Join(b.errs...); err != nil {
		return nil, err
	}

	pm := &releaseverify.PackageManifest{
		Format:             releaseverify.PackageFormat,
		Release:            o.Release,
		SourceDate:         o.SourceDate.UTC().Format(time.RFC3339),
		MinorFirstReleased: o.MinorFirstReleased,
		UpgradeFrom:        o.UpgradeFrom,
	}
	if pm.UpgradeFrom == nil {
		pm.UpgradeFrom = []string{}
	}
	if pm.Files, err = ListFiles(o.Out); err != nil {
		return nil, err
	}
	imgs := Images(m)
	for _, c := range slices.Sorted(maps.Keys(imgs)) {
		pm.Images = append(pm.Images, releaseverify.PackageImage{Component: c, Image: imgs[c]})
	}
	if err := pm.Validate(); err != nil {
		return nil, fmt.Errorf("airgap: the package manifest: %w", err)
	}
	enc, err := profilepkg.Encode(pm)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(o.Out, releaseverify.PackageManifestFile), enc, 0o644); err != nil { // #nosec G306 -- a public release artifact
		return nil, err
	}
	var sums strings.Builder
	for _, f := range pm.Files {
		sums.WriteString(f.SHA256 + "  " + f.Path + "\n")
	}
	if err := os.WriteFile(filepath.Join(o.Out, releaseverify.ChecksumsFile), []byte(sums.String()), 0o644); err != nil { // #nosec G306 -- a public release artifact
		return nil, err
	}
	return pm, nil
}

// readManifest decodes the release manifest strictly (unsigned here).
func readManifest(file string) (*releasemanifest.Manifest, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- the release pipeline's file
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m releasemanifest.Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &m, m.Validate()
}

// ListFiles lists every file of a package directory with its SHA-256, by
// slash-separated path, sorted: everything but package-manifest.json,
// SHA256SUMS and their signatures (what package-manifest.json lists).
func ListFiles(dir string) ([]releaseverify.PackageFile, error) {
	skip := map[string]bool{
		releaseverify.PackageManifestFile: true, releaseverify.PackageManifestFile + ".sig": true,
		releaseverify.ChecksumsFile: true, releaseverify.ChecksumsFile + ".sig": true,
	}
	var out []releaseverify.PackageFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip[rel] {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("airgap: %s is not a regular file", rel)
		}
		sum, err := fileSHA256(p)
		if err != nil {
			return err
		}
		out = append(out, releaseverify.PackageFile{Path: rel, SHA256: sum})
		return nil
	})
	slices.SortFunc(out, func(a, b releaseverify.PackageFile) int { return strings.Compare(a.Path, b.Path) })
	return out, err
}

type builder struct {
	out  string
	errs []error
}

func (b *builder) fail(err error) { b.errs = append(b.errs, err) }

// copy copies src to the package path dst; a missing source is recorded.
func (b *builder) copy(src, dst string) {
	in, err := os.Open(src) // #nosec G304 -- release-pipeline inputs
	if err != nil {
		b.fail(fmt.Errorf("%s: %w", dst, err))
		return
	}
	defer func() { _ = in.Close() }()
	p := filepath.Join(b.out, filepath.FromSlash(dst))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- a public release artifact
		b.fail(err)
		return
	}
	mode := os.FileMode(0o644)
	if strings.HasPrefix(dst, "tools/") {
		mode = 0o755
	}
	out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G302 G304 -- a public release artifact; the binaries are executable
	if err != nil {
		b.fail(err)
		return
	}
	_, cerr := io.Copy(out, in)
	if err := errors.Join(cerr, out.Close()); err != nil {
		b.fail(err)
	}
}

func (b *builder) write(dst string, data []byte) {
	if err := os.WriteFile(filepath.Join(b.out, filepath.FromSlash(dst)), data, 0o644); err != nil { // #nosec G306 G703 -- a public release artifact under the package directory
		b.fail(err)
	}
}

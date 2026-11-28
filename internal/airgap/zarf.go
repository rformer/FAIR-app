// Package airgap builds the air-gap package (F-014 T-10, AC-01, AC-02,
// AC-04; design §3.1, D-OQ4): one directory, fair-<version>-airgap/,
// holding
//   - the Zarf package zarf-package-fair-platform-<arch>-<version>.tar.zst:
//     the chart and every image any option of the chart runs (the release
//     manifest's images and its mirrored third-party copies) with their
//     cosign signatures and, for the release's own images, attestations,
//     once each, in Zarf's OCI image layout (images/);
//   - the verification kit, readable without Zarf: release-manifest.json,
//     cosign.pub, SHA256SUMS and package-manifest.json, each signed with
//     the release key (internal/releaseverify reads them);
//   - chart/fair-platform-<v>.tgz (the chart Zarf holds, as a file the
//     standard library reads), tools/ (fairctl, fair-audit-verify and
//     releasegen per platform), content/, compliance/, docs/, notes/ and
//     platforms.json.
//
// ZarfConfig writes the zarf.yaml `zarf package create` builds the Zarf
// package from (zarf.dev/v1beta1, Zarf ZarfVersion); Build assembles the
// directory around the signed Zarf package and writes
// package-manifest.json (fair.airgap-package.v1) and SHA256SUMS, which
// `releasegen sign -any` then signs; Layout reads the images back out of the
// Zarf package for releaseverify, after checking the Zarf package against
// the signed package manifest.
package airgap

import (
	"bytes"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/releasemanifest"
)

// Zarf, as the release pipeline runs it (pinned by digest in
// release-sign.yml as ZARF_IMAGE): Apache-2.0, its v1beta1 package format
// (v1alpha1 is deprecated since Zarf v1.0.0).
const (
	ZarfVersion    = "v1.0.1"
	ZarfAPIVersion = "zarf.dev/v1beta1"
	ZarfKind       = "ZarfPackageConfig"
	PackageName    = "fair-platform" // fleet.ChartName (TestNames); airgap does not link the renderer, so fairctl verify stays small
	ChartNamespace = "fair-platform"
)

// Architectures the package is built for: the release's images are built
// for amd64 only (release.yml's build job).
var Architectures = []string{"amd64"}

// ZarfFile is the Zarf package's file name (Zarf's own naming,
// zarf-package-<name>-<arch>-<version>.tar.zst).
func ZarfFile(release, arch string) string {
	return "zarf-package-" + PackageName + "-" + arch + "-" + release + ".tar.zst"
}

// ZarfFileRE matches a Zarf package's file name.
var ZarfFileRE = regexp.MustCompile(`^zarf-package-` + regexp.QuoteMeta(PackageName) + `-(amd64|arm64)-(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)\.tar(\.zst)?$`)

// PackageDir is the package directory's (and its tarball's) name.
func PackageDir(release string) string { return "fair-" + release + "-airgap" }

// ChartPath is the chart's path in the package.
func ChartPath(release string) string {
	return "chart/" + PackageName + "-" + strings.TrimPrefix(release, "v") + ".tgz"
}

// zarf.yaml (zarf.dev/v1beta1): the fields the package uses.
type zarfPackage struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   zarfMetadata `yaml:"metadata"`
	Components []zarfCompnt `yaml:"components"`
}

type zarfMetadata struct {
	Name         string            `yaml:"name"`
	Description  string            `yaml:"description"`
	Version      string            `yaml:"version"`
	Architecture string            `yaml:"architecture"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
}

type zarfCompnt struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Charts      []zarfChart `yaml:"charts"`
	Images      []zarfImage `yaml:"images"`
}

type zarfChart struct {
	Name        string    `yaml:"name"`
	Local       zarfLocal `yaml:"local"`
	Namespace   string    `yaml:"namespace"`
	ReleaseName string    `yaml:"releaseName"`
}

type zarfLocal struct {
	Path string `yaml:"path"`
}

type zarfImage struct {
	Name string `yaml:"name"`
}

// Images is every image of the package, by component, as the package
// manifest lists them: the release manifest's images and its mirrors.
func Images(m *releasemanifest.Manifest) map[string]string {
	out := map[string]string{}
	for c, img := range m.Images {
		out[c] = img
	}
	for _, x := range m.Mirrors {
		out[x.Component] = x.Image
	}
	return out
}

// sigTag is cosign's tag of an image's signatures (suffix "sig") or
// attestations ("att"): <repository>:sha256-<hex>.<suffix>.
func sigTag(image, suffix string) string {
	return releasemanifest.Repository(image) + ":" + strings.Replace(releasemanifest.Digest(image), ":", "-", 1) + "." + suffix
}

// ZarfImages is every reference the Zarf package pulls, sorted: each
// image by digest and its signatures; the release's own images also their
// attestations (mirrors carry none of the release's).
func ZarfImages(m *releasemanifest.Manifest) []string {
	var out []string
	for _, c := range slices.Sorted(maps.Keys(m.Images)) {
		img := m.Images[c]
		out = append(out, img, sigTag(img, "sig"), sigTag(img, "att"))
	}
	for _, x := range m.Mirrors {
		out = append(out, x.Image, sigTag(x.Image, "sig"))
	}
	slices.Sort(out)
	return out
}

// ZarfConfig is the zarf.yaml for the release's Zarf package: one required
// component holding the chart (chartFile, beside zarf.yaml) and every image
// ZarfImages names. The images are named in the release repository; the
// pipeline pulls them from staging with --registry-override.
func ZarfConfig(m *releasemanifest.Manifest, chartFile, arch string) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if !slices.Contains(Architectures, arch) {
		return nil, fmt.Errorf("airgap: architecture %q (want one of %v)", arch, Architectures)
	}
	if strings.ContainsAny(chartFile, `/\`) || !strings.HasSuffix(chartFile, ".tgz") {
		return nil, fmt.Errorf("airgap: the chart %q must be a .tgz beside zarf.yaml", chartFile)
	}
	p := zarfPackage{
		APIVersion: ZarfAPIVersion,
		Kind:       ZarfKind,
		Metadata: zarfMetadata{
			Name:         PackageName,
			Description:  "FAIR Risk Platform " + m.Release + ": the fair-platform chart and every image it can run, with their signatures and attestations. Install with fairctl; verify with fairctl verify or scripts/verify-release.sh.",
			Version:      m.Release,
			Architecture: arch,
		},
		Components: []zarfCompnt{{
			Name:        PackageName,
			Description: "The fair-platform chart and its images.",
			Charts: []zarfChart{{
				Name:        PackageName,
				Local:       zarfLocal{Path: chartFile},
				Namespace:   ChartNamespace,
				ReleaseName: "fair",
			}},
		}},
	}
	for _, ref := range ZarfImages(m) {
		p.Components[0].Images = append(p.Components[0].Images, zarfImage{Name: ref})
	}
	var b bytes.Buffer
	b.WriteString("# The FAIR air-gap package's Zarf definition (F-014 T-10; written by releasegen package zarf).\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

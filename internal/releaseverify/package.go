package releaseverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// The air-gap package manifest (design §3.1): package-manifest.json and its
// detached signature package-manifest.json.sig (the profilepkg format, made
// by `releasegen sign -any`, the release key). T-10 (`releasegen package`)
// writes it; this is the format it must write.

// PackageFormat identifies the package manifest format.
const PackageFormat = "fair.airgap-package.v1"

// PackageManifestFile is the package manifest's file name in the package.
const PackageManifestFile = "package-manifest.json"

// PackageManifest describes one air-gap package.
type PackageManifest struct {
	Format  string `json:"format"`
	Release string `json:"release"`
	// SourceDate is the release commit's time (RFC 3339, UTC).
	SourceDate string `json:"source_date"`
	// MinorFirstReleased is the date (YYYY-MM-DD) the release's minor line
	// was first released, for entitlements (design §3.9).
	MinorFirstReleased string `json:"minor_first_released"`
	// UpgradeFrom lists the releases this one upgrades from (design §3.10).
	UpgradeFrom []string `json:"upgrade_from"`
	// Files lists every file of the package but this manifest, SHA256SUMS
	// and their signatures, by path relative to the package directory
	// (slash-separated). A file the list does not name refuses the package.
	Files []PackageFile `json:"files"`
	// Images lists every image the Zarf package holds, by digest: the
	// release manifest's and the bundled third parties'.
	Images []PackageImage `json:"images"`
}

// PackageFile is one file of the package and its SHA-256.
type PackageFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PackageImage is one image of the package.
type PackageImage struct {
	Component string `json:"component"`
	Image     string `json:"image"` // repository@sha256:<digest>
}

var (
	versionRE   = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	componentRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// DecodePackageManifest decodes strictly (unknown fields and trailing data
// refused) and validates.
func DecodePackageManifest(b []byte) (*PackageManifest, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m PackageManifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("data after the manifest")
	}
	return &m, m.Validate()
}

// Validate checks the manifest's shape.
func (m *PackageManifest) Validate() error {
	if m.Format != PackageFormat {
		return fmt.Errorf("format %q, want %q", m.Format, PackageFormat)
	}
	if !versionRE.MatchString(m.Release) {
		return fmt.Errorf("release %q is not a version", m.Release)
	}
	if t, err := time.Parse(time.RFC3339, m.SourceDate); err != nil || t.Location() != time.UTC {
		return fmt.Errorf("source_date %q is not an RFC 3339 UTC time", m.SourceDate)
	}
	if _, err := time.Parse(time.DateOnly, m.MinorFirstReleased); err != nil {
		return fmt.Errorf("minor_first_released %q is not a date", m.MinorFirstReleased)
	}
	seen := map[string]bool{}
	for _, v := range m.UpgradeFrom {
		if !versionRE.MatchString(v) || seen[v] || v == m.Release {
			return fmt.Errorf("upgrade_from %q is not a version, or repeated", v)
		}
		seen[v] = true
	}
	if len(m.Files) == 0 || len(m.Images) == 0 {
		return errors.New("files and images are required")
	}
	files := map[string]bool{}
	for _, f := range m.Files {
		if !safePath(f.Path) || files[f.Path] || f.Path == PackageManifestFile || f.Path == PackageManifestFile+".sig" {
			return fmt.Errorf("file %q: not a relative path in the package, or repeated", f.Path)
		}
		if !hex64.MatchString(f.SHA256) {
			return fmt.Errorf("file %q: sha256 must be 64 hexadecimal digits", f.Path)
		}
		files[f.Path] = true
	}
	comps := map[string]bool{}
	for _, i := range m.Images {
		if !componentRE.MatchString(i.Component) || comps[i.Component] || !imageRE.MatchString(i.Image) {
			return fmt.Errorf("image %q (%q): not component and repository@sha256:<digest>, or repeated", i.Image, i.Component)
		}
		comps[i.Component] = true
	}
	return nil
}

// safePath reports whether p is a clean, relative, slash-separated path
// inside the package.
func safePath(p string) bool {
	return p != "" && p == path.Clean(p) && !path.IsAbs(p) && p != "." &&
		p != ".." && !strings.HasPrefix(p, "../") && !strings.Contains(p, `\`) && !strings.Contains(p, ":")
}

package pincheck

// F-014 T-07 (F-014-AC-17; design §3.3, D-OQ3): the bundled dependency
// images are built from upstream inputs pinned in deploy/bundled/sources.json:
// source tarballs by tag, commit and SHA-256, release artifacts by SHA-256,
// base and mirrored images by digest (and, for a mirrored image, its
// publisher's exact signing identity). Every Dockerfile ADD of a URL carries
// --checksum=sha256 and names an entry of the file with the same checksum;
// every source and artifact entry is used by an ADD and every base image by
// a FROM, so the file and the Dockerfile cannot drift apart.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BundledSourcesFile is where the pins live, relative to the root.
const BundledSourcesFile = "deploy/bundled/sources.json"

// BundledSourcesFormat is the file's format.
const BundledSourcesFormat = "fair.bundled-sources.v1"

// Kinds of entry.
const (
	KindSource    = "source"     // a source tarball, built by a Dockerfile stage
	KindArtifact  = "artifact"   // a released binary artifact (no public commit), added as is
	KindBaseImage = "base-image" // an upstream image a stage builds on
	KindMirror    = "mirror"     // an upstream image shipped as is, mirrored and re-signed
)

// BundledSources is deploy/bundled/sources.json.
type BundledSources struct {
	Format  string          `json:"format"`
	Checked string          `json:"checked"`
	Sources []BundledSource `json:"sources"`
}

// BundledSource is one pinned upstream input.
type BundledSource struct {
	Name       string `json:"name"`
	Component  string `json:"component"` // the image (Dockerfile target) it goes into
	Kind       string `json:"kind"`
	Version    string `json:"version"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Commit     string `json:"commit,omitempty"`
	URL        string `json:"url,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Image      string `json:"image,omitempty"`
	Identity   string `json:"certificate_identity,omitempty"`
	Issuer     string `json:"certificate_oidc_issuer,omitempty"`
	License    string `json:"license"`
	Go         string `json:"go,omitempty"` // the go directive of the upstream go.mod
	// Overrides are Go modules raised above the upstream go.mod for a
	// security fix not yet released upstream (module@version).
	Overrides []string `json:"overrides,omitempty"`
	FIPS       string `json:"fips"`         // what is and is not FIPS 140 validated
}

var (
	commitRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	addRE      = regexp.MustCompile(`(?i)^\s*ADD\s+(.*)$`)
	urlRE      = regexp.MustCompile(`https?://\S+`)
	checksumRE = regexp.MustCompile(`--checksum=sha256:([0-9a-f]{64})\b`)
	regexMeta  = regexp.MustCompile(`[\^$*+?()\[\]{}|\\]`)
)

// LoadBundledSources reads and checks the file; problems are returned
// alongside, by entry.
func LoadBundledSources(path string) (*BundledSources, []string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var s BundledSources
	if err := d.Decode(&s); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, s.Check(), nil
}

// Check answers every problem of the file.
func (s *BundledSources) Check() []string {
	var out []string
	if s.Format != BundledSourcesFormat {
		out = append(out, fmt.Sprintf("format %q, want %s", s.Format, BundledSourcesFormat))
	}
	seen := map[string]bool{}
	for i, e := range s.Sources {
		bad := func(f string, a ...any) {
			out = append(out, fmt.Sprintf("source %d (%s): %s", i, e.Name, fmt.Sprintf(f, a...)))
		}
		if e.Name == "" || seen[e.Name] {
			bad("missing or duplicate name")
		}
		seen[e.Name] = true
		if e.Component == "" || e.Version == "" || e.License == "" || e.FIPS == "" {
			bad("component, version, license and fips are required")
		}
		needCommit := func() {
			if !commitRE.MatchString(e.Commit) || e.Tag == "" || !strings.HasPrefix(e.Repository, "https://") {
				bad("needs its repository, tag and the tag's full commit")
			}
		}
		switch e.Kind {
		case KindSource:
			needCommit()
			fallthrough
		case KindArtifact:
			if !strings.HasPrefix(e.URL, "https://") || !sha256RE.MatchString(e.SHA256) {
				bad("needs an https URL and its SHA-256")
			}
			if e.Image != "" {
				bad("a %s has no image", e.Kind)
			}
		case KindMirror:
			if !strings.HasPrefix(e.Identity, "https://") || regexMeta.MatchString(e.Identity) || !strings.HasPrefix(e.Issuer, "https://") {
				bad("needs its publisher's exact certificate identity and issuer")
			}
			fallthrough
		case KindBaseImage:
			needCommit()
			if !digestRE.MatchString(e.Image) {
				bad("image %q is not pinned by digest", e.Image)
			}
			if e.URL != "" || e.SHA256 != "" {
				bad("an image has no URL or SHA-256 (its digest pins it)")
			}
		default:
			bad("kind %q", e.Kind)
		}
	}
	return out
}

// dockerAdd is one ADD of a URL.
type dockerAdd struct {
	file, url, sum string
	line           int
}

// bundled collects what the Dockerfiles fetch and build on.
type bundled struct {
	adds  []dockerAdd
	froms map[string]bool
}

func (b *bundled) scanAdd(path string, n int, l string, add adder) {
	m := addRE.FindStringSubmatch(l)
	if m == nil {
		return
	}
	u := urlRE.FindString(m[1])
	if u == "" {
		return
	}
	c := checksumRE.FindStringSubmatch(m[1])
	if c == nil {
		add(path, n, "ADD %s has no --checksum=sha256:...", u)
		return
	}
	b.adds = append(b.adds, dockerAdd{file: path, line: n, url: u, sum: c[1]})
}

// check ties the Dockerfiles to deploy/bundled/sources.json.
func (b *bundled) check(root string, add adder) error {
	path := filepath.Join(root, filepath.FromSlash(BundledSourcesFile))
	if _, err := os.Stat(path); err != nil {
		for _, a := range b.adds {
			add(a.file, a.line, "ADD %s is not pinned in %s", a.url, BundledSourcesFile)
		}
		return nil
	}
	s, problems, err := LoadBundledSources(path)
	if err != nil {
		return err
	}
	for _, p := range problems {
		add(path, 0, "%s", p)
	}
	byURL := map[string]BundledSource{}
	used := map[string]bool{}
	for _, e := range s.Sources {
		if e.URL != "" {
			byURL[e.URL] = e
		}
	}
	for _, a := range b.adds {
		e, ok := byURL[a.url]
		switch {
		case !ok:
			add(a.file, a.line, "ADD %s is not pinned in %s", a.url, BundledSourcesFile)
		case e.SHA256 != a.sum:
			add(a.file, a.line, "ADD %s: checksum %s, %s pins %s", a.url, a.sum, BundledSourcesFile, e.SHA256)
		default:
			used[e.Name] = true
		}
	}
	for _, e := range s.Sources {
		switch e.Kind {
		case KindSource, KindArtifact:
			if !used[e.Name] {
				add(path, 0, "source %s is pinned but no Dockerfile ADDs %s", e.Name, e.URL)
			}
		case KindBaseImage:
			if !b.froms[e.Image] {
				add(path, 0, "base image %s is pinned but no Dockerfile builds FROM it", e.Image)
			}
		}
	}
	return nil
}

// SPDX is an SPDX 2.3 document listing the component's source and artifact
// entries, with their download locations and checksums. The images built
// from sources a scanner cannot recognise in the binaries (the OpenSSL FIPS
// provider) carry it under /usr/share/doc/fair/sbom/, and the image SBOM
// includes it (syft's sbom cataloger, .github/actions/image), so the SBOM
// names everything the image was built from (F-012-AC-08). The creation
// time is the file's checked date, so the output is reproducible.
func (s *BundledSources) SPDX(component string) ([]byte, error) {
	type ref struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	}
	type sum struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	}
	type pkg struct {
		Name             string `json:"name"`
		SPDXID           string `json:"SPDXID"`
		Version          string `json:"versionInfo"`
		Download         string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
		Checksums        []sum  `json:"checksums"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		Copyright        string `json:"copyrightText"`
		Comment          string `json:"comment"`
		Refs             []ref  `json:"externalRefs"`
	}
	type doc struct {
		Version   string `json:"spdxVersion"`
		License   string `json:"dataLicense"`
		SPDXID    string `json:"SPDXID"`
		Name      string `json:"name"`
		Namespace string `json:"documentNamespace"`
		Creation  struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []pkg `json:"packages"`
	}
	d := doc{Version: "SPDX-2.3", License: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name: "fair-" + component + "-sources", Namespace: "https://github.com/rformer/fair-app/" + BundledSourcesFile + "/" + component}
	d.Creation.Created = s.Checked + "T00:00:00Z"
	d.Creation.Creators = []string{"Tool: fair-pincheck"}
	for _, e := range s.Sources {
		if e.Component != component || (e.Kind != KindSource && e.Kind != KindArtifact) {
			continue
		}
		p := pkg{Name: e.Name, SPDXID: "SPDXRef-Package-" + e.Name, Version: e.Version, Download: e.URL,
			Checksums: []sum{{"SHA256", e.SHA256}}, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION",
			Copyright: "NOASSERTION", Comment: e.FIPS,
			Refs: []ref{{"PACKAGE-MANAGER", "purl", "pkg:generic/" + e.purlName() + "@" + e.Version + "?download_url=" + e.URL}}}
		if cpe := e.cpe(); cpe != "" {
			p.Refs = append(p.Refs, ref{"SECURITY", "cpe23Type", cpe})
		}
		d.Packages = append(d.Packages, p)
	}
	if len(d.Packages) == 0 {
		return nil, fmt.Errorf("no source or artifact entries for component %q", component)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	return append(b, '\n'), err
}

// purlName and cpe name the upstream product, so vulnerability matching
// finds it: the FIPS provider is OpenSSL at its own version.
func (e BundledSource) purlName() string {
	if e.Name == "openssl-fips-provider" {
		return "openssl"
	}
	return e.Name
}

func (e BundledSource) cpe() string {
	switch e.Name {
	case "openssl", "openssl-fips-provider":
		return "cpe:2.3:a:openssl:openssl:" + e.Version + ":*:*:*:*:*:*:*"
	case "postgresql":
		return "cpe:2.3:a:postgresql:postgresql:" + e.Version + ":*:*:*:*:*:*:*"
	}
	return ""
}

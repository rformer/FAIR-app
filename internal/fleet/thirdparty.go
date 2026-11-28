package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/rformer/fair-app/internal/releasemanifest"
)

// Third-party images (F-012 T-15; design §3.6, amended 2026-11-26): every
// image the release runs that this repository does not build is listed in
// deploy/third-party-images.json with its publisher's exact signing
// identity. The release verifies each against that identity, copies it by
// digest to the release repository's mirror/<name> and signs the copy with
// the release key; the release's manifests name the copy, and admission
// requires the release key for it like for the platform's own images.

// ThirdPartyFormat is deploy/third-party-images.json's format.
const ThirdPartyFormat = "fair.third-party-images.v1"

// ThirdParty is one third-party image.
type ThirdParty struct {
	Name     string `json:"name"`                    // the mirror repository: <release>/mirror/<name>
	Image    string `json:"image"`                   // repository[:tag]@sha256:<digest>, as the manifests name it
	Identity string `json:"certificate_identity"`    // the publisher's exact certificate identity
	Issuer   string `json:"certificate_oidc_issuer"` // its OIDC issuer
}

// ThirdPartyList is deploy/third-party-images.json.
type ThirdPartyList struct {
	Format string       `json:"format"`
	Images []ThirdParty `json:"images"`
}

var (
	nameRE        = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	thirdImageRE  = regexp.MustCompile(`^([a-z0-9][a-z0-9._/-]*)(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?@(sha256:[0-9a-f]{64})$`)
	identityRegex = regexp.MustCompile(`[\\^$*+?()\[\]{}|]`)
)

// LoadThirdParty reads and checks the list.
func LoadThirdParty(path string) (ThirdPartyList, error) {
	var l ThirdPartyList
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own file
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("%s: %w", path, err)
	}
	return l, l.Check()
}

// Check requires a known format and, per image, a mirror name, an image by digest, and an
// exact identity (no pattern) with an https issuer; names unique.
func (l ThirdPartyList) Check() error {
	var errs []error
	if l.Format != ThirdPartyFormat {
		errs = append(errs, fmt.Errorf("format %q, want %q", l.Format, ThirdPartyFormat))
	}
	seen := map[string]bool{}
	for i, t := range l.Images {
		if !nameRE.MatchString(t.Name) || seen[t.Name] {
			errs = append(errs, fmt.Errorf("image %d: name %q (unique, lower case)", i, t.Name))
		}
		seen[t.Name] = true
		if !thirdImageRE.MatchString(t.Image) {
			errs = append(errs, fmt.Errorf("%s: image %q is not repository[:tag]@sha256:<digest>", t.Name, t.Image))
		}
		if !strings.HasPrefix(t.Identity, "https://") || identityRegex.MatchString(t.Identity) {
			errs = append(errs, fmt.Errorf("%s: identity %q is not one exact URI", t.Name, t.Identity))
		}
		if !strings.HasPrefix(t.Issuer, "https://") {
			errs = append(errs, fmt.Errorf("%s: issuer %q", t.Name, t.Issuer))
		}
	}
	return errors.Join(errs...)
}

// Digest is the image's digest.
func (t ThirdParty) Digest() string { return thirdImageRE.FindStringSubmatch(t.Image)[2] }

// Repository is the image's repository, without tag and digest.
func (t ThirdParty) Repository() string { return thirdImageRE.FindStringSubmatch(t.Image)[1] }

// Mirrored is the copy's reference under the mirror prefix
// (<release repository>/mirror).
func (t ThirdParty) Mirrored(prefix string) string {
	return strings.TrimSuffix(prefix, "/") + "/" + t.Name + "@" + t.Digest()
}

// Mirror maps each listed image, as the manifests name it, to its copy.
func (l ThirdPartyList) Mirror(prefix string) map[string]string {
	m := map[string]string{}
	for _, t := range l.Images {
		m[t.Image] = t.Mirrored(prefix)
	}
	return m
}

// Copy is one entry of the release's mirror.json (release.yml's manifest
// job): the publisher's image it verified and where it copied it.
type Copy struct {
	Source  string `json:"source"`  // repository@sha256:<digest>, verified against the publisher's identity
	Staging string `json:"staging"` // the copy in the staging repository
	Release string `json:"release"` // the copy in the release repository, by the same digest
}

// ManifestMirrors is the signed release manifest's mirrors section (F-014
// T-10; design §3.17) from the list and the copies the release made
// (mirror.json, by name): every listed image copied by its own digest, and
// no copy of an image the list does not name.
func (l ThirdPartyList) ManifestMirrors(copies map[string]Copy) ([]releasemanifest.Mirror, error) {
	var out []releasemanifest.Mirror
	var errs []error
	for _, t := range l.Images {
		c, ok := copies[t.Name]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: not mirrored by the release", t.Name))
			continue
		case c.Source != t.Repository()+"@"+t.Digest():
			errs = append(errs, fmt.Errorf("%s: mirrored from %s, the list names %s", t.Name, c.Source, t.Image))
			continue
		case releasemanifest.Digest(c.Release) != t.Digest() || releasemanifest.Digest(c.Staging) != t.Digest():
			errs = append(errs, fmt.Errorf("%s: the copy is not by the publisher's digest %s", t.Name, t.Digest()))
			continue
		}
		x := releasemanifest.Mirror{Component: t.Name, Image: c.Release, Source: t.Image, Identity: t.Identity, Issuer: t.Issuer}
		if err := releasemanifest.ValidateMirror(x); err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, x)
	}
	for name := range copies {
		if !slices.ContainsFunc(l.Images, func(t ThirdParty) bool { return t.Name == name }) {
			errs = append(errs, fmt.Errorf("%s: mirrored, but not in the third-party list", name))
		}
	}
	slices.SortFunc(out, func(a, b releasemanifest.Mirror) int { return strings.Compare(a.Component, b.Component) })
	return out, errors.Join(errs...)
}

// MirrorsAt is ManifestMirrors for copies under prefix (<release
// repository>/mirror) and staging (the same, for tests and renders that
// have no staging repository).
func (l ThirdPartyList) MirrorsAt(prefix string) ([]releasemanifest.Mirror, error) {
	copies := map[string]Copy{}
	for _, t := range l.Images {
		ref := t.Mirrored(prefix)
		copies[t.Name] = Copy{Source: t.Repository() + "@" + t.Digest(), Staging: ref, Release: ref}
	}
	return l.ManifestMirrors(copies)
}

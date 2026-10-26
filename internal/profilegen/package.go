package profilegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/settings"
)

// GeneratorVersion identifies profilegen's package output. Bump it when the
// same inputs would produce different package bytes.
const GeneratorVersion = "profilegen/1.0.0"

// Repository-relative names recorded in packages, whatever directories the
// generator was given.
const (
	repoPinDir      = "third_party/oscal"
	repoProfilesDir = "profiles"
	repoBindingsDir = "bindings"
)

// PackageSpec is one entry of profiles/packages.yaml.
type PackageSpec struct {
	ID      string `yaml:"id"`
	Title   string `yaml:"title"`
	Family  string `yaml:"family"`
	Version string `yaml:"version"`
	Base    string `yaml:"base"`
}

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// LoadPackageSpecs reads profiles/packages.yaml strictly.
func LoadPackageSpecs(file string) ([]PackageSpec, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- build-time input
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var doc struct {
		Packages []PackageSpec `yaml:"packages"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("packages.yaml: %w", err)
	}
	seen := map[string]bool{}
	for _, s := range doc.Packages {
		if !safeName.MatchString(s.ID) || !safeName.MatchString(s.Version) {
			return nil, fmt.Errorf("packages.yaml: id %q and version %q must match %s", s.ID, s.Version, safeName)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("packages.yaml: %s is listed twice", s.ID)
		}
		seen[s.ID] = true
		switch settings.Family(s.Family) {
		case settings.FamilyFedRAMP, settings.FamilyCMMC, settings.FamilyEnterprise:
		default:
			return nil, fmt.Errorf("packages.yaml: %s has unknown family %q", s.ID, s.Family)
		}
		if s.Title == "" || s.Base == "" {
			return nil, fmt.Errorf("packages.yaml: %s needs a title and a base", s.ID)
		}
	}
	if len(doc.Packages) == 0 {
		return nil, errors.New("packages.yaml lists no packages")
	}
	return doc.Packages, nil
}

// ManifestFile is the release manifest's file name in the packages directory.
const ManifestFile = "manifest.json"

// BuildPackages builds every package listed in profilesDir/packages.yaml and
// the release manifest pinning them, keyed by file name. Every binding is
// validated, drift-checked against the resolved profiles, and every key in
// defs must be bound; any problem fails the build. previous is the committed
// manifest (nil for none): a pinned file whose bytes would change is refused,
// because packages are immutable.
func BuildPackages(pinDir, profilesDir, bindingsDir string, defs []settings.Def, previous *profilepkg.Manifest) (map[string][]byte, error) {
	specs, err := LoadPackageSpecs(filepath.Join(profilesDir, "packages.yaml"))
	if err != nil {
		return nil, err
	}
	l, err := NewPinnedLoader(pinDir)
	if err != nil {
		return nil, err
	}

	// Resolve every base, recording what each resolution read.
	resolved := map[string]map[string]any{}
	sources := map[string][]profilepkg.Source{}
	families := map[string]settings.Family{}
	for _, s := range specs {
		families[s.ID] = settings.Family(s.Family)
		var (
			cat  map[string]any
			srcs []profilepkg.Source
		)
		if rel, ok := strings.CutPrefix(s.Base, repoProfilesDir+"/"); ok {
			b, err := os.ReadFile(filepath.Join(profilesDir, filepath.FromSlash(rel))) // #nosec G304 -- build-time input
			if err != nil {
				return nil, err
			}
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", s.Base, err)
			}
			u := "repo:" + s.Base
			if cat, err = Resolve(OverlayLoader{Docs: map[string]map[string]any{u: doc}, Next: l}, u); err != nil {
				return nil, fmt.Errorf("%s: %w", s.ID, err)
			}
			srcs = append(srcs, profilepkg.Source{Path: s.Base, SHA256: digest(b)})
		} else if rel, ok := strings.CutPrefix(s.Base, repoPinDir+"/"); ok {
			u, pinned := l.SourceOf(rel)
			if !pinned {
				return nil, fmt.Errorf("%s: base %s is not pinned in MANIFEST.json", s.ID, s.Base)
			}
			if cat, err = Resolve(l, u); err != nil {
				return nil, fmt.Errorf("%s: %w", s.ID, err)
			}
		} else {
			return nil, fmt.Errorf("%s: base %s is neither under %s/ nor %s/", s.ID, s.Base, repoPinDir, repoProfilesDir)
		}
		for _, p := range l.Read() {
			u, _ := l.SourceOf(p)
			srcs = append(srcs, profilepkg.Source{Path: path.Join(repoPinDir, p), URL: u, SHA256: l.SHA256(p)})
		}
		resolved[s.ID] = cat
		sources[s.ID] = srcs
	}

	// Validate the bindings against the resolved profiles.
	nist, err := l.Load(nistCatalogURL(l))
	if err != nil {
		return nil, err
	}
	l.Read()
	ctx := Context{
		Defs:     defs,
		Profiles: families,
		HasParam: func(catalog, param string) bool {
			_, ok := findParam(nist, param)
			return catalog == CatalogNIST80053r5 && ok
		},
		Resolved: resolved,
	}
	bindings, err := LoadBindings(bindingsDir)
	if err != nil {
		return nil, err
	}
	var errs []error
	bound := map[string]bool{}
	var bindingSources []profilepkg.Source
	for _, b := range bindings {
		errs = append(errs, ctx.Validate(b)...)
		if b.file != b.Setting+".yaml" {
			errs = append(errs, fmt.Errorf("%s: file must be named %s.yaml", b.file, b.Setting))
		}
		bound[b.Setting] = true
		raw, err := os.ReadFile(filepath.Join(bindingsDir, b.file)) // #nosec G304 -- build-time input
		if err != nil {
			return nil, err
		}
		bindingSources = append(bindingSources, profilepkg.Source{Path: path.Join(repoBindingsDir, b.file), SHA256: digest(raw)})
	}
	for _, d := range defs {
		if !bound[d.Key] {
			errs = append(errs, fmt.Errorf("registered setting %s has no binding", d.Key))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	out := map[string][]byte{}
	m := profilepkg.Manifest{Format: profilepkg.ManifestFormat, Generator: GeneratorVersion}
	for _, s := range specs {
		p, err := buildPackage(s, bindings, append(sources[s.ID], bindingSources...))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.ID, err)
		}
		b, err := profilepkg.Encode(p)
		if err != nil {
			return nil, err
		}
		// Round-trip through the importer's own checks before shipping.
		if _, err := profilepkg.Decode(b); err != nil {
			return nil, fmt.Errorf("%s: %w", s.ID, err)
		}
		file := profilepkg.FileName(s.ID, s.Version)
		out[file] = b
		m.Packages = append(m.Packages, profilepkg.ManifestEntry{File: file, ID: s.ID, Version: s.Version, SHA256: profilepkg.Digest(b)})
	}
	slices.SortFunc(m.Packages, func(a, b profilepkg.ManifestEntry) int { return strings.Compare(a.File, b.File) })
	if previous != nil {
		for _, e := range m.Packages {
			for _, old := range previous.Packages {
				if old.File == e.File && old.SHA256 != e.SHA256 {
					errs = append(errs, fmt.Errorf("%s changed but is already pinned (sha256 %s); packages are immutable, so bump %s's version in packages.yaml", e.File, old.SHA256, e.ID))
				}
			}
		}
		if err := errors.Join(errs...); err != nil {
			return nil, err
		}
	}
	if out[ManifestFile], err = profilepkg.Encode(m); err != nil {
		return nil, err
	}
	return out, nil
}

// buildPackage assembles one profile's package from the validated bindings.
func buildPackage(s PackageSpec, bindings []Binding, sources []profilepkg.Source) (*profilepkg.Package, error) {
	p := &profilepkg.Package{
		Format: profilepkg.Format,
		Profile: profilepkg.Meta{ID: s.ID, Title: s.Title, Family: s.Family, Version: s.Version, Base: s.Base,
			Sources: sources, Generator: GeneratorVersion},
		Settings:  map[string]profilepkg.Setting{},
		HardFloor: map[string]profilepkg.Floor{},
	}
	for _, b := range bindings {
		d, err := b.Def()
		if err != nil {
			return nil, err
		}
		bd, err := b.Bound(s.ID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Setting, err)
		}
		pb := b.Profiles[s.ID]
		set := profilepkg.Setting{
			Type: b.Type, Direction: b.Direction, Order: b.Order, BUScopable: b.BUScopable,
			Default: profilepkg.EncodeValue(bd.Default), Bound: profilepkg.EncodeValue(bd.Weakest),
			Params: d.Params,
		}
		if pb.Source != nil {
			set.Origin = profilepkg.Origin{SourceParam: pb.Source.Param, SourceConstraint: pb.Source.Constraint}
		} else {
			set.Origin = profilepkg.Origin{PlatformChoice: strings.TrimSpace(pb.PlatformChoice)}
		}
		p.Settings[b.Setting] = set
		if d.Floor != nil {
			p.HardFloor[b.Setting] = profilepkg.Floor{Value: profilepkg.EncodeValue(d.Floor), Families: b.HardFloorFamilies}
		}
	}
	return p, nil
}

// nistCatalogURL is the source URL of the pinned 800-53r5 catalog that
// binding params are checked against.
func nistCatalogURL(l *PinnedLoader) string {
	u, _ := l.SourceOf("nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json")
	return u
}

func digest(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

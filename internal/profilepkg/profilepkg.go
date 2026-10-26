// Package profilepkg is the signed profile package format (F-015 T-06;
// AC-05; design §4.3). profilegen builds and signs packages at release time;
// the posture service verifies and imports them, offline included.
//
// A package is canonical JSON: the same inputs always produce the same
// bytes, so its SHA-256 digest is reproducible and can be pinned in the
// release manifest. The detached signature is ECDSA P-256 over SHA-256 of
// those bytes (FIPS 140-validated module); ECDSA signatures are randomized,
// so signatures are verified, never compared.
package profilepkg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

// Format identifies this package format version.
const Format = "fair-profile-package/v1"

// FileName is a package's file name, profile-<id>-<version>.json (design
// §4.3). Packages are immutable: a new version gets a new file.
func FileName(id, version string) string { return "profile-" + id + "-" + version + ".json" }

// Package is one signed profile package.
type Package struct {
	Format    string             `json:"format"`
	Profile   Meta               `json:"profile"`
	Settings  map[string]Setting `json:"settings"`
	HardFloor map[string]Floor   `json:"hard_floor"`
}

// Meta describes the profile and how it was built.
type Meta struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Family    string   `json:"family"`
	Version   string   `json:"version"`
	Base      string   `json:"base"`      // the OSCAL profile it was resolved from
	Sources   []Source `json:"sources"`   // every pinned file resolution read
	Generator string   `json:"generator"` // profilegen version
}

// Source is one input file and its SHA-256.
type Source struct {
	Path   string `json:"path"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256"`
}

// Setting is one setting's default and bound in this profile.
type Setting struct {
	Type       string   `json:"type"`
	Direction  string   `json:"direction"`
	Order      []string `json:"order,omitempty"` // enum: weakest -> strictest
	BUScopable bool     `json:"bu_scopable"`
	Default    any      `json:"default"`
	Bound      any      `json:"bound"` // the weakest value allowed without an exception
	Params     []string `json:"params,omitempty"`
	Origin     Origin   `json:"origin"`
}

// Origin records where a value comes from (design §4.1).
type Origin struct {
	SourceParam      string `json:"source_param,omitempty"`
	SourceConstraint string `json:"source_constraint,omitempty"`
	PlatformChoice   string `json:"platform_choice,omitempty"`
}

// Floor is one hard-floor entry: the weakest value any profile may use.
type Floor struct {
	Value    any      `json:"value"`
	Families []string `json:"families,omitempty"` // empty: every profile
}

// Encode returns the canonical bytes. Map keys are sorted by encoding/json,
// slices keep their (deterministic) order, and durations are Go duration
// strings.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Digest is the hex SHA-256 of a package's bytes.
func Digest(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// Sign returns a detached signature (base64 ASN.1 DER) over SHA-256 of b.
func Sign(key *ecdsa.PrivateKey, b []byte) ([]byte, error) {
	if key.Curve.Params().Name != "P-256" {
		return nil, errors.New("profilepkg: signing key must be ECDSA P-256")
	}
	d := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}

// ErrSignature is returned when a signature does not verify.
var ErrSignature = errors.New("profilepkg: signature does not verify")

// VerifySignature checks a detached signature over b.
func VerifySignature(pub *ecdsa.PublicKey, b, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	d := sha256.Sum256(b)
	if !ecdsa.VerifyASN1(pub, d[:], raw) {
		return ErrSignature
	}
	return nil
}

// Verify checks the signature, then decodes and validates the package
// (Decode). Anything else is refused (design §4.3).
func Verify(pub *ecdsa.PublicKey, b, sig []byte) (*Package, error) {
	if err := VerifySignature(pub, b, sig); err != nil {
		return nil, err
	}
	return Decode(b)
}

// Decode decodes a package strictly (unknown fields, trailing data and
// non-canonical bytes are refused) and validates it: format, settings
// well-formed, defaults within bounds, and bounds not weaker than the hard
// floor. It does not check a signature; importers use Verify.
func Decode(b []byte) (*Package, error) {
	var p Package
	if err := decodeStrict(b, &p); err != nil {
		return nil, fmt.Errorf("profilepkg: decode: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if c, err := Encode(&p); err != nil || !bytes.Equal(c, b) {
		return nil, errors.New("profilepkg: package is not in canonical form")
	}
	return &p, nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Validate checks a package's internal consistency.
func (p *Package) Validate() error {
	if p.Format != Format {
		return fmt.Errorf("profilepkg: format %q, want %q", p.Format, Format)
	}
	if p.Profile.ID == "" || p.Profile.Version == "" || p.Profile.Family == "" || len(p.Settings) == 0 {
		return errors.New("profilepkg: profile id, version, family and settings are required")
	}
	prof, defs, err := p.ToSettings()
	if err != nil {
		return err
	}
	if err := settings.ValidateProfile(prof, defs); err != nil {
		return fmt.Errorf("profilepkg: %w", err)
	}
	return nil
}

// ToSettings converts the package to pkg/settings types.
func (p *Package) ToSettings() (settings.Profile, []settings.Def, error) {
	prof := settings.Profile{ID: p.Profile.ID, Title: p.Profile.Title, Family: settings.Family(p.Profile.Family),
		Version: p.Profile.Version, Settings: map[string]settings.Bound{}}
	keys := make([]string, 0, len(p.Settings))
	for k := range p.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var defs []settings.Def
	for _, k := range keys {
		s := p.Settings[k]
		d, err := s.def(k)
		if err != nil {
			return prof, nil, err
		}
		if f, ok := p.HardFloor[k]; ok {
			if d.Floor, err = decodeValue(d, f.Value); err != nil {
				return prof, nil, fmt.Errorf("profilepkg: %s hard floor: %w", k, err)
			}
			for _, fam := range f.Families {
				d.FloorFamilies = append(d.FloorFamilies, settings.Family(fam))
			}
		}
		def, err := decodeValue(d, s.Default)
		if err != nil {
			return prof, nil, fmt.Errorf("profilepkg: %s default: %w", k, err)
		}
		weak, err := decodeValue(d, s.Bound)
		if err != nil {
			return prof, nil, fmt.Errorf("profilepkg: %s bound: %w", k, err)
		}
		if c, err := d.Compare(def, weak); err != nil || c < 0 {
			return prof, nil, fmt.Errorf("profilepkg: %s default %v is weaker than its bound %v", k, def, weak)
		}
		o := s.Origin
		fromSource := o.SourceParam != "" && o.SourceConstraint != "" && o.PlatformChoice == ""
		fromChoice := o.PlatformChoice != "" && o.SourceParam == "" && o.SourceConstraint == ""
		if !fromSource && !fromChoice {
			return prof, nil, fmt.Errorf("profilepkg: %s must say where its value comes from: a source, or a platform choice", k)
		}
		prof.Settings[k] = settings.Bound{Default: def, Weakest: weak}
		defs = append(defs, d)
	}
	for k := range p.HardFloor {
		if _, ok := p.Settings[k]; !ok {
			return prof, nil, fmt.Errorf("profilepkg: hard floor for unknown setting %s", k)
		}
	}
	return prof, defs, nil
}

var kinds = map[string]settings.Kind{"duration": settings.KindDuration, "int": settings.KindInt, "bool": settings.KindBool, "enum": settings.KindEnum}

var directions = map[string]settings.Direction{
	"lower_is_stricter": settings.LowerIsStricter, "higher_is_stricter": settings.HigherIsStricter,
	"true_is_stricter": settings.TrueIsStricter, "false_is_stricter": settings.FalseIsStricter, "ordered": settings.OrderedEnum,
}

func (s Setting) def(key string) (settings.Def, error) {
	k, ok := kinds[s.Type]
	if !ok {
		return settings.Def{}, fmt.Errorf("profilepkg: %s has unknown type %q", key, s.Type)
	}
	d, ok := directions[s.Direction]
	if !ok {
		return settings.Def{}, fmt.Errorf("profilepkg: %s has unknown direction %q", key, s.Direction)
	}
	return settings.Def{Key: key, Kind: k, Direction: d, Order: s.Order, Params: s.Params, BUScopable: s.BUScopable}, nil
}

// EncodeValue converts a pkg/settings value to its package form.
func EncodeValue(v any) any {
	if d, ok := v.(time.Duration); ok {
		return d.String()
	}
	return v
}

// decodeValue converts a package value back to the Go type d expects.
func decodeValue(d settings.Def, raw any) (any, error) {
	var v any
	switch d.Kind {
	case settings.KindDuration:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a duration", raw)
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return nil, err
		}
		v = dur
	case settings.KindInt:
		var n int64
		switch x := raw.(type) {
		case json.Number:
			var err error
			if n, err = x.Int64(); err != nil {
				return nil, err
			}
		case int:
			n = int64(x)
		default:
			return nil, fmt.Errorf("%v is not an integer", raw)
		}
		v = int(n)
	default:
		v = raw
	}
	if err := d.Validate(v); err != nil {
		return nil, err
	}
	return v, nil
}

// Manifest is the release manifest: every package file and its digest.
type Manifest struct {
	Format    string          `json:"format"`
	Generator string          `json:"generator"`
	Packages  []ManifestEntry `json:"packages"`
}

// ManifestEntry pins one package by digest.
type ManifestEntry struct {
	File    string `json:"file"`
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// ManifestFormat identifies the release manifest format.
const ManifestFormat = "fair-profile-release-manifest/v1"

// CheckPinned reports whether package bytes b are pinned in the manifest
// under file.
func (m *Manifest) CheckPinned(file string, b []byte) error {
	for _, e := range m.Packages {
		if e.File == file {
			if e.SHA256 != Digest(b) {
				return fmt.Errorf("profilepkg: %s digest %s is not the pinned %s", file, Digest(b), e.SHA256)
			}
			return nil
		}
	}
	return fmt.Errorf("profilepkg: %s is not in the release manifest", file)
}

// VerifyManifest checks the manifest's signature and decodes it.
func VerifyManifest(pub *ecdsa.PublicKey, b, sig []byte) (*Manifest, error) {
	if err := VerifySignature(pub, b, sig); err != nil {
		return nil, err
	}
	return DecodeManifest(b)
}

// DecodeManifest decodes a release manifest strictly. It does not check a
// signature.
func DecodeManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := decodeStrict(b, &m); err != nil {
		return nil, fmt.Errorf("profilepkg: manifest: %w", err)
	}
	if m.Format != ManifestFormat {
		return nil, fmt.Errorf("profilepkg: manifest format %q, want %q", m.Format, ManifestFormat)
	}
	seen := map[string]bool{}
	for _, e := range m.Packages {
		if e.File == "" || e.ID == "" || e.Version == "" || len(e.SHA256) != 64 || seen[e.File] {
			return nil, fmt.Errorf("profilepkg: manifest entry %+v is incomplete or repeated", e)
		}
		seen[e.File] = true
	}
	return &m, nil
}

// SigSuffix names a file's detached signature: <file>.sig.
const SigSuffix = ".sig"

// SignRelease signs the manifest (named manifestFile in files) and every
// package it pins, after checking each package's bytes against its pin and
// its own validity. It returns the signature files, keyed by name.
func SignRelease(key *ecdsa.PrivateKey, manifestFile string, files map[string][]byte) (map[string][]byte, error) {
	m, err := DecodeManifest(files[manifestFile])
	if err != nil {
		return nil, err
	}
	sigs := map[string][]byte{}
	for _, e := range m.Packages {
		b, ok := files[e.File]
		if !ok {
			return nil, fmt.Errorf("profilepkg: %s is pinned but missing", e.File)
		}
		if err := m.CheckPinned(e.File, b); err != nil {
			return nil, err
		}
		if _, err := Decode(b); err != nil {
			return nil, fmt.Errorf("%s: %w", e.File, err)
		}
		if sigs[e.File+SigSuffix], err = Sign(key, b); err != nil {
			return nil, err
		}
	}
	if sigs[manifestFile+SigSuffix], err = Sign(key, files[manifestFile]); err != nil {
		return nil, err
	}
	return sigs, nil
}

// VerifyRelease checks a release's manifest signature, then every pinned
// package: present, matching its pinned digest, signed, valid, and with the
// id and version its pin names. It returns the packages in manifest order.
func VerifyRelease(pub *ecdsa.PublicKey, manifestFile string, files map[string][]byte) ([]*Package, error) {
	m, err := VerifyManifest(pub, files[manifestFile], files[manifestFile+SigSuffix])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifestFile, err)
	}
	var out []*Package
	for _, e := range m.Packages {
		b, ok := files[e.File]
		if !ok {
			return nil, fmt.Errorf("profilepkg: %s is pinned but missing", e.File)
		}
		if err := m.CheckPinned(e.File, b); err != nil {
			return nil, err
		}
		p, err := Verify(pub, b, files[e.File+SigSuffix])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.File, err)
		}
		if p.Profile.ID != e.ID || p.Profile.Version != e.Version || e.File != FileName(e.ID, e.Version) {
			return nil, fmt.Errorf("profilepkg: %s is %s %s, but is pinned as %s %s", e.File, p.Profile.ID, p.Profile.Version, e.ID, e.Version)
		}
		out = append(out, p)
	}
	return out, nil
}

// LoadPrivateKey reads a PEM ECDSA P-256 private key (PKCS#8 or SEC 1) from
// a mounted secret file.
func LoadPrivateKey(file string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("profilepkg: key file is not PEM")
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("profilepkg: key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("profilepkg: key must be ECDSA P-256")
	}
	return ek, nil
}

// LoadPublicKey reads a PEM (PKIX) ECDSA P-256 public key.
func LoadPublicKey(file string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- bundled public key
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("profilepkg: public key file is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("profilepkg: public key must be ECDSA P-256")
	}
	return ek, nil
}

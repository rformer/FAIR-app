package releaseverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// The release manifest as internal/releasemanifest defines it (F-015 T-28).
// This package reads it with the standard library alone; a test holds the
// decoding and validation equal to releasemanifest.Verify.

// ManifestFormat identifies the release manifest format.
const ManifestFormat = "fair-platform-release-manifest/v1"

// Manifest is the signed release manifest.
type Manifest struct {
	Format           string            `json:"format"`
	Release          string            `json:"release"`
	Images           map[string]string `json:"images"` // component -> repository@sha256:<digest>
	RBAC             []RBACEntry       `json:"rbac"`
	EngineValidation *EngineValidation `json:"engine_validation,omitempty"`
	Mirrors          []Mirror          `json:"mirrors,omitempty"`
}

// Mirror is one mirrored third-party image (F-014 T-10, design §3.17): the
// release's copy, the publisher's source by the same digest and the
// publisher identity the release verified. Mirrors are checked by the
// release key's signature alone; they carry no attestation.
type Mirror struct {
	Component string `json:"component"`
	Image     string `json:"image"`
	Source    string `json:"source"`
	Identity  string `json:"certificate_identity"`
	Issuer    string `json:"certificate_oidc_issuer"`
}

var identityMeta = regexp.MustCompile(`[\\^$*+?()\[\]{}|\s]`)

func digestOf(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

// validate holds releasemanifest.ValidateMirror's rules.
func (x Mirror) validate() error {
	switch {
	case !componentRE.MatchString(x.Component):
		return fmt.Errorf("mirror %q: the component is not a lower-case name", x.Component)
	case !imageRE.MatchString(x.Image) || !imageRE.MatchString(x.Source):
		return fmt.Errorf("mirror %s: image and source must be repository@sha256:<digest>", x.Component)
	case digestOf(x.Image) != digestOf(x.Source):
		return fmt.Errorf("mirror %s: the copy is not the source's digest", x.Component)
	case !strings.HasPrefix(x.Identity, "https://") || identityMeta.MatchString(x.Identity):
		return fmt.Errorf("mirror %s: the publisher identity must be one exact https URI", x.Component)
	case !strings.HasPrefix(x.Issuer, "https://") || identityMeta.MatchString(x.Issuer):
		return fmt.Errorf("mirror %s: the OIDC issuer must be an https URI", x.Component)
	}
	return nil
}

// RBACEntry is one platform RBAC object's hash.
type RBACEntry struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Optional  string `json:"optional,omitempty"` // "hook" or the chart value that switches it on
}

// EngineValidation is the engine image's validation record (F-005 T-09).
type EngineValidation struct {
	Image         string `json:"image"`
	SuiteVersion  string `json:"suite_version"`
	EngineVersion string `json:"engine_version"`
	Architecture  string `json:"architecture"`
	Passed        bool   `json:"passed"`
	RunAtUnixMS   int64  `json:"run_at_unix_ms"`
	RecordSHA256  string `json:"record_sha256"`
}

const engineComponent = "engine"

var (
	imageRE   = regexp.MustCompile(`^[a-z0-9.\-/:]+@sha256:[0-9a-f]{64}$`)
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	optional  = regexp.MustCompile(`^(hook|[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)+)$`)
	rbacKinds = []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
)

// Validate checks the manifest's shape, as releasemanifest.Manifest.Validate.
func (m *Manifest) Validate() error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("format %q, want %q", m.Format, ManifestFormat)
	}
	if m.Release == "" || len(m.Images) == 0 {
		return errors.New("release and images are required")
	}
	for c, img := range m.Images {
		if c == "" || !imageRE.MatchString(img) {
			return fmt.Errorf("image %q for %q must be repository@sha256:<digest>", img, c)
		}
	}
	seen := map[string]bool{}
	for _, e := range m.RBAC {
		key := e.Kind + "/" + e.Namespace + "/" + e.Name
		if !slices.Contains(rbacKinds, e.Kind) || e.Name == "" || len(e.SHA256) != 64 || seen[key] {
			return fmt.Errorf("invalid or duplicate RBAC entry %+v", e)
		}
		if (e.Kind == "Role" || e.Kind == "RoleBinding") != (e.Namespace != "") {
			return fmt.Errorf("%s %s: namespace mismatch", e.Kind, e.Name)
		}
		if e.Optional != "" && !optional.MatchString(e.Optional) {
			return fmt.Errorf("%s %s: optional %q is neither \"hook\" nor a chart value", e.Kind, e.Name, e.Optional)
		}
		seen[key] = true
	}
	mirrors := map[string]bool{}
	for _, x := range m.Mirrors {
		if err := x.validate(); err != nil {
			return err
		}
		if _, ok := m.Images[x.Component]; ok || mirrors[x.Component] {
			return fmt.Errorf("mirror %s: repeated, or also a release image", x.Component)
		}
		mirrors[x.Component] = true
	}
	if v := m.EngineValidation; v != nil {
		if v.Image == "" || v.Image != m.Images[engineComponent] {
			return fmt.Errorf("the engine validation is for %q, the engine image is %q", v.Image, m.Images[engineComponent])
		}
		if v.SuiteVersion == "" || v.EngineVersion == "" || v.Architecture == "" || v.RunAtUnixMS <= 0 || !hex64.MatchString(v.RecordSHA256) {
			return errors.New("the engine validation is incomplete")
		}
	} else if m.Images[engineComponent] != "" {
		return errors.New("an engine image needs its validation record")
	}
	return nil
}

// Components returns the manifest's components, sorted.
func (m *Manifest) Components() []string {
	cs := make([]string, 0, len(m.Images))
	for c := range m.Images {
		cs = append(cs, c)
	}
	slices.Sort(cs)
	return cs
}

// VerifyManifest checks the detached signature over b with the release key,
// then decodes the manifest strictly and validates it, as
// releasemanifest.Verify (what `releasegen verify` runs).
func VerifyManifest(pub *ecdsa.PublicKey, b, sig []byte) (*Manifest, error) {
	if err := VerifySignature(pub, b, sig); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ErrSignature is returned when a signature does not verify.
var ErrSignature = errors.New("signature does not verify")

// VerifySignature checks a detached release-key signature (the profilepkg
// format: base64 of the ASN.1 DER ECDSA P-256 signature over SHA-256 of b,
// optionally followed by white space), as profilepkg.VerifySignature.
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

// ParsePublicKey reads a PEM (PKIX) ECDSA P-256 public key, the release's
// cosign.pub.
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("the public key must be ECDSA P-256")
	}
	return ek, nil
}

// LoadPublicKey reads ParsePublicKey's input from a file.
func LoadPublicKey(file string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- the operator's pinned key file
	if err != nil {
		return nil, err
	}
	k, err := ParsePublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return k, nil
}

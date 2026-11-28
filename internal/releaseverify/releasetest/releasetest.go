// Package releasetest writes synthetic FAIR releases for tests of
// internal/releaseverify and fairctl verify: the verification kit
// (release-manifest.json, cosign.pub, SHA256SUMS, package-manifest.json and
// their signatures, as releasegen writes them) and the images as OCI image
// layouts in the forms cosign writes (cosign save, tags, referrers), with
// signatures and attestations made by a test key. Only tests import it.
package releasetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
)

// NewKey returns a fresh ECDSA P-256 key.
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// PublicPEM is a key's public half as cosign.pub holds it.
func PublicPEM(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Sign is a detached release-key signature (`releasegen sign`).
func Sign(t testing.TB, k *ecdsa.PrivateKey, b []byte) []byte {
	t.Helper()
	sig, err := profilepkg.Sign(k, b)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// Layout modes: how signatures and attestations are attached.
const (
	Save     = "save"     // cosign save: kind annotations in index.json
	Tag      = "tag"      // cosign's tags sha256-<hex>.sig and .att
	Referrer = "referrer" // OCI referrers: manifests whose subject is the image
)

// Image describes one image and what is attached to it.
type Image struct {
	Component  string
	Repository string // default registry.invalid/fair-<component>
	Seed       string // varies the image's content; default the component
	Mode       string // default Save
	// Keys sign the signature and each attestation; nil leaves it out.
	// Build uses the release key for all three when all are nil.
	SigKey, SBOMKey, ProvKey *ecdsa.PrivateKey
	// SigDigest, when set, is the digest the signature's payload names in
	// place of the image's; AttDigest likewise for the attestations'
	// subjects.
	SigDigest, AttDigest string
	// Provenance is the SLSA predicate; nil: one that ReleasePolicy allows.
	Provenance map[string]any
}

// Release describes a release to write.
type Release struct {
	Key     *ecdsa.PrivateKey // the release key (required)
	Release string            // default v1.2.3
	Images  []Image           // default one image "fixture"
	// Extra are images only the package lists (bundled third parties).
	Extra []Image
	// Mirrors are mirrored third-party images (F-014 T-10): signed by the
	// release key (SigKey, default the release key), never attested, and
	// named in the release manifest's mirrors with a publisher identity.
	Mirrors []Image
	// Files are further files of the release, listed in SHA256SUMS.
	Files map[string][]byte
	// Package writes package-manifest.json and its signature.
	Package bool
	// Layout, when set, writes every image into one layout at this path
	// relative to the release directory in place of images/<component>/.
	Layout string
	// LayoutDir, when set, is that one layout's absolute directory, outside
	// the release (an air-gap package's Zarf layout, F-014 T-10).
	LayoutDir string
	// Amend, when set, changes the release manifest before it is signed
	// (its RBAC, the engine's validation record: F-014 T-09's package
	// fixture).
	Amend func(m *releasemanifest.Manifest)
}

// Written is what Build wrote.
type Written struct {
	Dir     string
	Images  map[string]string // component -> repository@sha256:<digest>
	Extra   map[string]string // the Extra images, likewise
	Mirrors map[string]string // the Mirrors, likewise
	Package *releaseverify.PackageManifest
}

// DefaultProvenance is a SLSA v0.2 predicate the release policy allows.
func DefaultProvenance(release string) map[string]any {
	return map[string]any{
		"builder":   map[string]any{"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"},
		"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
		"invocation": map[string]any{"configSource": map[string]any{
			"uri":        "git+https://github.com/rformer/FAIR-app@refs/tags/" + release,
			"digest":     map[string]any{"sha1": strings.Repeat("a", 40)},
			"entryPoint": ".github/workflows/release.yml",
		}},
		"materials": []any{},
	}
}

// Build writes the release into dir (created).
func Build(t testing.TB, dir string, r Release) *Written {
	t.Helper()
	if r.Release == "" {
		r.Release = "v1.2.3"
	}
	if r.Images == nil {
		r.Images = []Image{{Component: "fixture"}}
	}
	w := &Written{Dir: dir, Images: map[string]string{}, Extra: map[string]string{}, Mirrors: map[string]string{}}
	write(t, filepath.Join(dir, releaseverify.ReleaseKeyFile), PublicPEM(t, r.Key))
	all := map[string]string{}
	for i, img := range slices.Concat(r.Images, r.Extra, r.Mirrors) {
		mirror := i >= len(r.Images)+len(r.Extra)
		if img.Repository == "" {
			img.Repository = "registry.invalid/fair-" + img.Component
			if mirror {
				img.Repository = "registry.invalid/mirror/" + img.Component
			}
		}
		if img.Provenance == nil {
			img.Provenance = DefaultProvenance(r.Release)
		}
		switch {
		case mirror && img.SigKey == nil:
			img.SigKey, img.SBOMKey, img.ProvKey = r.Key, nil, nil
		case !mirror && img.SigKey == nil && img.SBOMKey == nil && img.ProvKey == nil:
			img = WithKey(img, r.Key)
		}
		ldir := filepath.Join(dir, "images", img.Component)
		switch {
		case r.LayoutDir != "":
			ldir = r.LayoutDir
		case r.Layout != "":
			ldir = filepath.Join(dir, r.Layout)
		}
		d := AddImage(t, ldir, img)
		all[img.Component] = img.Repository + "@" + d
		switch {
		case i < len(r.Images):
			w.Images[img.Component] = img.Repository + "@" + d
		case mirror:
			w.Mirrors[img.Component] = img.Repository + "@" + d
		default:
			w.Extra[img.Component] = img.Repository + "@" + d
		}
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: r.Release, Images: w.Images, RBAC: []releasemanifest.RBACEntry{}}
	for _, c := range sortedKeys(w.Mirrors) {
		m.Mirrors = append(m.Mirrors, MirrorOf(c, w.Mirrors[c]))
	}
	if r.Amend != nil {
		r.Amend(m)
	}
	mb, err := releasemanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, releaseverify.ReleaseManifestFile), mb)
	write(t, filepath.Join(dir, releaseverify.ReleaseManifestFile+".sig"), Sign(t, r.Key, mb))
	sums := []string{releaseverify.ReleaseManifestFile, releaseverify.ReleaseKeyFile}
	for n, b := range r.Files {
		write(t, filepath.Join(dir, filepath.FromSlash(n)), b)
		sums = append(sums, n)
	}
	slices.Sort(sums)
	var sb strings.Builder
	for _, n := range sums {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n))) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString(hexSum(b) + "  " + n + "\n")
	}
	write(t, filepath.Join(dir, releaseverify.ChecksumsFile), []byte(sb.String()))
	write(t, filepath.Join(dir, releaseverify.ChecksumsFile+".sig"), Sign(t, r.Key, []byte(sb.String())))
	if r.Package {
		pm := &releaseverify.PackageManifest{
			Format: releaseverify.PackageFormat, Release: r.Release, SourceDate: "2026-11-20T10:00:00Z",
			MinorFirstReleased: "2026-11-01", UpgradeFrom: []string{"v1.0.0", "v1.1.0"},
		}
		for _, c := range sortedKeys(all) {
			pm.Images = append(pm.Images, releaseverify.PackageImage{Component: c, Image: all[c]})
		}
		pm.Files = ListFiles(t, dir)
		WritePackageManifest(t, dir, r.Key, pm)
		w.Package = pm
	}
	return w
}

// ListFiles lists every file of dir a package manifest lists, with digests.
func ListFiles(t testing.TB, dir string) []releaseverify.PackageFile {
	t.Helper()
	skip := map[string]bool{
		releaseverify.PackageManifestFile: true, releaseverify.PackageManifestFile + ".sig": true,
		releaseverify.ChecksumsFile: true, releaseverify.ChecksumsFile + ".sig": true,
	}
	var out []releaseverify.PackageFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if skip[rel] {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the test's own directory
		if err != nil {
			return err
		}
		out = append(out, releaseverify.PackageFile{Path: rel, SHA256: hexSum(b)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// WritePackageManifest encodes, writes and signs a package manifest.
func WritePackageManifest(t testing.TB, dir string, k *ecdsa.PrivateKey, pm *releaseverify.PackageManifest) {
	t.Helper()
	b, err := profilepkg.Encode(pm)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, releaseverify.PackageManifestFile), b)
	write(t, filepath.Join(dir, releaseverify.PackageManifestFile+".sig"), Sign(t, k, b))
}

// Resign rewrites dir's SHA256SUMS for its current files and signs it, and
// signs release-manifest.json again (after a test changed a file).
func Resign(t testing.TB, dir string, k *ecdsa.PrivateKey) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, releaseverify.ChecksumsFile)) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	sums, err := releaseverify.ParseChecksums(b)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, s := range sums {
		f, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(s.Path))) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString(hexSum(f) + "  " + s.Path + "\n")
	}
	m, err := os.ReadFile(filepath.Join(dir, releaseverify.ReleaseManifestFile)) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, releaseverify.ReleaseManifestFile+".sig"), Sign(t, k, m))
	write(t, filepath.Join(dir, releaseverify.ChecksumsFile), []byte(sb.String()))
	write(t, filepath.Join(dir, releaseverify.ChecksumsFile+".sig"), Sign(t, k, []byte(sb.String())))
}

type desc struct {
	MediaType    string            `json:"mediaType"`
	Size         int64             `json:"size"`
	Digest       string            `json:"digest"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
}

type index struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []desc `json:"manifests"`
}

const (
	mediaManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaConfig   = "application/vnd.oci.image.config.v1+json"
)

// AddImage writes an image, and what img attaches to it, into the layout
// at dir (created, or appended to), and returns the image's digest.
func AddImage(t testing.TB, dir string, img Image) string {
	t.Helper()
	if img.Mode == "" {
		img.Mode = Save
	}
	if img.Seed == "" {
		img.Seed = img.Component
	}
	if img.Repository == "" {
		img.Repository = "registry.invalid/fair-" + img.Component
	}
	if img.Provenance == nil {
		img.Provenance = DefaultProvenance("v1.2.3")
	}
	write(t, filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion": "1.0.0"}`))
	idx := index{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []desc{}}
	if b, err := os.ReadFile(filepath.Join(dir, "index.json")); err == nil { // #nosec G304 -- a test directory
		if err := json.Unmarshal(b, &idx); err != nil {
			t.Fatal(err)
		}
	}
	layer := blob(t, dir, []byte("layer of "+img.Seed))
	diff := "sha256:" + hexSum([]byte("layer of "+img.Seed))
	cfg := blob(t, dir, mustJSON(t, map[string]any{
		"architecture": "amd64", "os": "linux",
		"config": map[string]any{"User": "65532"},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diff}},
	}))
	im := mustJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": mediaManifest,
		"config": desc{MediaType: mediaConfig, Size: cfg.Size, Digest: cfg.Digest},
		"layers": []desc{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Size: layer.Size, Digest: layer.Digest}},
	})
	imd := blob(t, dir, im)
	imd.MediaType = mediaManifest
	d := imd.Digest
	entry := imd
	switch img.Mode {
	case Save:
		entry.Annotations = map[string]string{"kind": "dev.cosignproject.cosign/image"}
	default:
		entry.Annotations = map[string]string{"org.opencontainers.image.ref.name": img.Repository + ":test"}
	}
	idx.Manifests = append(idx.Manifests, entry)

	attach := func(kind, suffix, artifactType string, layers []desc) {
		diffs := make([]string, len(layers))
		for i, l := range layers {
			diffs[i] = l.Digest
		}
		c := blob(t, dir, mustJSON(t, map[string]any{
			"architecture": "", "created": "0001-01-01T00:00:00Z", "history": []any{map[string]any{"created": "0001-01-01T00:00:00Z"}},
			"os": "", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}, "config": map[string]any{},
		}))
		m := map[string]any{
			"schemaVersion": 2, "mediaType": mediaManifest,
			"config": desc{MediaType: mediaConfig, Size: c.Size, Digest: c.Digest},
			"layers": layers,
		}
		if img.Mode == Referrer {
			m["artifactType"] = artifactType
			m["subject"] = desc{MediaType: mediaManifest, Size: imd.Size, Digest: d}
		}
		md := blob(t, dir, mustJSON(t, m))
		md.MediaType = mediaManifest
		switch img.Mode {
		case Save:
			md.Annotations = map[string]string{"kind": kind}
		case Tag:
			md.Annotations = map[string]string{"org.opencontainers.image.ref.name": img.Repository + ":" + strings.Replace(d, ":", "-", 1) + "." + suffix}
		case Referrer:
			md.ArtifactType = artifactType
		}
		idx.Manifests = append(idx.Manifests, md)
	}

	if img.SigKey != nil {
		named := d
		if img.SigDigest != "" {
			named = img.SigDigest
		}
		payload := fmt.Appendf(nil, `{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, img.Repository, named)
		sum := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, img.SigKey, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		p := blob(t, dir, payload)
		p.MediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
		p.Annotations = map[string]string{"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig)}
		attach("dev.cosignproject.cosign/sigs", "sig", "application/vnd.dev.cosign.artifact.sig.v1+json", []desc{p})
	}
	var atts []desc
	subject := d
	if img.AttDigest != "" {
		subject = img.AttDigest
	}
	for _, a := range []struct {
		key  *ecdsa.PrivateKey
		pt   string
		pred any
	}{
		{img.SBOMKey, releaseverify.PredicateSPDX, map[string]any{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "fair-" + img.Component, "packages": []any{}}},
		{img.ProvKey, releaseverify.PredicateSLSA, img.Provenance},
	} {
		if a.key == nil {
			continue
		}
		st := mustJSON(t, map[string]any{
			"_type": "https://in-toto.io/Statement/v0.1", "predicateType": a.pt,
			"subject":   []any{map[string]any{"name": img.Repository, "digest": map[string]string{"sha256": strings.TrimPrefix(subject, "sha256:")}}},
			"predicate": a.pred,
		})
		pt := "application/vnd.in-toto+json"
		pae := "DSSEv1 " + strconv.Itoa(len(pt)) + " " + pt + " " + strconv.Itoa(len(st)) + " " + string(st)
		sum := sha256.Sum256([]byte(pae))
		sig, err := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		env := mustJSON(t, map[string]any{
			"payloadType": pt, "payload": base64.StdEncoding.EncodeToString(st),
			"signatures": []any{map[string]string{"keyid": "", "sig": base64.StdEncoding.EncodeToString(sig)}},
		})
		e := blob(t, dir, env)
		e.MediaType = "application/vnd.dsse.envelope.v1+json"
		e.Annotations = map[string]string{"dev.cosignproject.cosign/signature": "", "predicateType": a.pt}
		atts = append(atts, e)
	}
	if len(atts) > 0 {
		attach("dev.cosignproject.cosign/atts", "att", "application/vnd.dev.cosign.artifact.att.v1+json", atts)
	}
	write(t, filepath.Join(dir, "index.json"), mustJSON(t, idx))
	return d
}

// MirrorOf is a mirror entry for the copy ref of component c, made from a
// publisher's image of the same digest.
func MirrorOf(c, ref string) releasemanifest.Mirror {
	return releasemanifest.Mirror{
		Component: c, Image: ref,
		Source:   "publisher.invalid/" + c + ":1.0.0@" + releasemanifest.Digest(ref),
		Identity: "https://github.com/publisher/" + c + "/.github/workflows/release.yml@refs/tags/v1.0.0",
		Issuer:   "https://token.actions.githubusercontent.com",
	}
}

// WithKey returns img with every signature and attestation made by k.
func WithKey(img Image, k *ecdsa.PrivateKey) Image {
	img.SigKey, img.SBOMKey, img.ProvKey = k, k, k
	return img
}

func blob(t testing.TB, dir string, b []byte) desc {
	t.Helper()
	h := hexSum(b)
	write(t, filepath.Join(dir, "blobs", "sha256", h), b)
	return desc{Size: int64(len(b)), Digest: "sha256:" + h}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func write(t testing.TB, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil { // #nosec G703 -- a test directory
		t.Fatal(err)
	}
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

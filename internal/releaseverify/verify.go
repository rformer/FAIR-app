// Package releaseverify verifies a FAIR release offline with the release
// key alone (F-014 T-11, AC-07; design §3.5; ADR-018, ADR-019): what
// scripts/verify-release.sh -offline does with cosign and releasegen, in Go
// with the standard library only, so the installer (fairctl verify) needs
// neither binary and makes no network call.
//
// Verify checks, in this order, stopping at the first failure:
//   - cosign.pub is present and is the pinned release key;
//   - release-manifest.json's detached signature, then the manifest itself
//     (strictly decoded and validated, as releasemanifest.Verify);
//   - SHA256SUMS's signature and every file it lists;
//   - package-manifest.json's signature, its shape, its release, every file
//     and every image it lists (an air-gap package, design §3.1);
//   - for each image (the release manifest's, then the package's others),
//     from an OCI image layout on disk: a cosign signature by the release key
//     whose payload names the image's digest, the digest the manifests name,
//     the image's content against its digest, and SPDX and SLSA provenance
//     attestations (DSSE, in-toto, subject the image) signed by the release
//     key; with a ProvenancePolicy, the provenance's builder and source;
//   - for each mirrored third-party image (the manifest's mirrors, F-014
//     T-10): the release key's signature, the digest and the content, no
//     attestation (they carry none of the release's).
//
// The messages are the script's, word for word, so the two verifiers can be
// compared (TestVerifyMatchesVerifyRelease); checks the script does not make
// (the pinned key, the package manifest, the image content, the provenance
// policy) have messages of their own.
package releaseverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// File names of the verification kit.
const (
	ReleaseKeyFile      = "cosign.pub"
	ReleaseManifestFile = "release-manifest.json"
	ChecksumsFile       = "SHA256SUMS"
	ImagesDir           = "images"
)

// Check names, stable for -output json.
const (
	CheckReleaseKey      = "release_key"
	CheckReleaseManifest = "release_manifest"
	CheckChecksums       = "checksums"
	CheckPackageManifest = "package_manifest"
	CheckImageSignature  = "image_signature"
	CheckImageDigest     = "image_digest"
	CheckImageContent    = "image_content"
	CheckSBOM            = "sbom_attestation"
	CheckProvenance      = "provenance_attestation"
	CheckProvenancePol   = "provenance_policy"
	CheckRelease         = "release"
)

// Options configure a verification.
type Options struct {
	// Key is the pinned release public key (required): the release's
	// cosign.pub must be this key.
	Key *ecdsa.PublicKey
	// Package requires an air-gap package: SHA256SUMS and
	// package-manifest.json must be present. Without it they are verified
	// when present, as the script verifies SHA256SUMS.
	Package bool
	// Provenance, when set, also requires each image's SLSA provenance to
	// name its builder and source. verify-release.sh does not check them.
	Provenance *ProvenancePolicy
	// Layout is one OCI image layout holding every image (signatures and
	// attestations as cosign tags or referrers). Empty: each image in its
	// own layout images/<component>/, as `cosign save` writes it.
	Layout string
}

// Step is one passed check, or the failed one.
type Step struct {
	Check   string `json:"check"`
	Subject string `json:"subject,omitempty"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// Report is a verification's result.
type Report struct {
	Dir      string  `json:"dir"`
	Release  string  `json:"release,omitempty"`
	Verified bool    `json:"verified"`
	Steps    []Step  `json:"steps"`
	Refusal  *Step   `json:"refusal,omitempty"`
	Images   []Image `json:"images,omitempty"`
}

// Image is one verified image.
type Image struct {
	Component string `json:"component"`
	Image     string `json:"image"`
}

// Err is the refusal as an error, or nil when the release verified.
func (r *Report) Err() error {
	if r.Refusal == nil {
		return nil
	}
	return &Refusal{Step: *r.Refusal}
}

// Refusal is a failed verification.
type Refusal struct{ Step }

func (e *Refusal) Error() string {
	if e.Detail != "" {
		return e.Message + " (" + e.Detail + ")"
	}
	return e.Message
}

// Final is the line a verified release ends with.
const Final = "release verified (offline)"

// WriteText writes the report as plain lines: "ok - …" per passed check,
// "FAIL - …" for the refusal (and its detail indented below), then Final.
// color marks ok and FAIL with ANSI colours; nothing else is ever written.
func (r *Report) WriteText(stdout, stderr io.Writer, color bool) {
	mark := func(s, c string) string {
		if color {
			return "\x1b[" + c + "m" + s + "\x1b[0m"
		}
		return s
	}
	for _, s := range r.Steps {
		_, _ = fmt.Fprintf(stdout, "%s - %s\n", mark("ok", "32"), s.Message)
	}
	if f := r.Refusal; f != nil {
		_, _ = fmt.Fprintf(stderr, "%s - %s\n", mark("FAIL", "31"), f.Message)
		if f.Detail != "" {
			_, _ = fmt.Fprintf(stderr, "  %s\n", f.Detail)
		}
		return
	}
	_, _ = fmt.Fprintln(stdout, Final)
}

// errRefused stops a verification; the refusal is in the report.
var errRefused = errors.New("refused")

type run struct {
	dir string
	o   Options
	r   *Report
}

func (v *run) ok(check, subject, msg string) {
	v.r.Steps = append(v.r.Steps, Step{Check: check, Subject: subject, OK: true, Message: msg})
}

func (v *run) fail(check, subject, msg string, detail error) error {
	s := &Step{Check: check, Subject: subject, Message: msg}
	if detail != nil {
		s.Detail = detail.Error()
	}
	v.r.Refusal = s
	return errRefused
}

// Verify verifies the release (or air-gap package) in dir.
func Verify(dir string, o Options) *Report {
	v := &run{dir: dir, o: o, r: &Report{Dir: dir, Steps: []Step{}}}
	if err := v.verify(); err == nil {
		v.r.Verified = true
	} else if v.r.Refusal == nil {
		_ = v.fail(CheckReleaseKey, "", err.Error(), nil)
	}
	return v.r
}

func (v *run) path(name string) string { return filepath.Join(v.dir, filepath.FromSlash(name)) }

func (v *run) verify() error {
	if v.o.Key == nil {
		return errors.New("no pinned release key")
	}
	pubBytes, err := os.ReadFile(v.path(ReleaseKeyFile))
	if err != nil {
		return v.fail(CheckReleaseKey, ReleaseKeyFile, "no cosign.pub in "+v.dir, nil)
	}
	if pub, err := ParsePublicKey(pubBytes); err != nil || !pub.Equal(v.o.Key) {
		return v.fail(CheckReleaseKey, ReleaseKeyFile, "cosign.pub: not the pinned release key", err)
	}
	sig, err := os.ReadFile(v.path(ReleaseManifestFile + ".sig"))
	if err != nil {
		return v.fail(CheckReleaseManifest, ReleaseManifestFile, "no release-manifest.json.sig in "+v.dir, nil)
	}
	b, err := os.ReadFile(v.path(ReleaseManifestFile))
	if err != nil {
		return v.fail(CheckReleaseManifest, ReleaseManifestFile, "release-manifest.json: the signature does not verify with cosign.pub", err)
	}
	m, err := VerifyManifest(v.o.Key, b, sig)
	if err != nil {
		return v.fail(CheckReleaseManifest, ReleaseManifestFile, "release-manifest.json: the signature does not verify with cosign.pub", err)
	}
	if len(m.Images) == 0 {
		return v.fail(CheckReleaseManifest, ReleaseManifestFile, "release-manifest.json names no images", nil)
	}
	v.r.Release = m.Release
	v.ok(CheckReleaseManifest, ReleaseManifestFile, "release manifest signed by the release key")

	if err := v.checksums(); err != nil {
		return err
	}
	images := make([]Image, 0, len(m.Images))
	for _, c := range m.Components() {
		images = append(images, Image{Component: c, Image: m.Images[c]})
	}
	extra, err := v.packageManifest(m)
	if err != nil {
		return err
	}
	for _, img := range images {
		if err := v.image(img); err != nil {
			return err
		}
		v.r.Images = append(v.r.Images, img)
	}
	// The mirrored third-party images (design §3.17): the release key's
	// signature, the digest and the content; no attestation.
	for _, x := range m.Mirrors {
		img := Image{Component: x.Component, Image: x.Image}
		if err := v.mirror(img); err != nil {
			return err
		}
		v.r.Images = append(v.r.Images, img)
	}
	for _, img := range extra {
		if err := v.image(img); err != nil {
			return err
		}
		v.r.Images = append(v.r.Images, img)
	}
	return nil
}

// openImage finds an image's layout and the digest its signatures name.
func (v *run) openImage(img Image) (*layout, string, error) {
	c := img.Component
	want := img.Image[strings.Index(img.Image, "@")+1:]
	dir := v.o.Layout
	if dir == "" {
		dir = v.path(ImagesDir + "/" + c)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return nil, "", v.fail(CheckImageSignature, c, c+": no images/"+c+" in the release", nil)
		}
	}
	noSig := c + ": the release key's signature does not verify"
	l, err := openLayout(dir)
	if err != nil {
		return nil, "", v.fail(CheckImageSignature, c, noSig, err)
	}
	got, saved, err := l.image()
	switch {
	case err != nil:
		return nil, "", v.fail(CheckImageSignature, c, noSig, err)
	case !saved && l.has(want):
		got = want
	case !saved:
		return nil, "", v.fail(CheckImageSignature, c, noSig, fmt.Errorf("the layout holds no image %s", want))
	}
	if l.verifySignatures(v.o.Key, got) == 0 {
		return nil, "", v.fail(CheckImageSignature, c, noSig, nil)
	}
	if got != want {
		return nil, "", v.fail(CheckImageDigest, c, fmt.Sprintf("%s: verified %s, the manifest names %s", c, got, want), nil)
	}
	if err := l.checkContent(want, 0); err != nil {
		return nil, "", v.fail(CheckImageContent, c, c+": the image's content does not match its digest", err)
	}
	return l, want, nil
}

// mirror verifies one mirrored third-party image.
func (v *run) mirror(img Image) error {
	_, want, err := v.openImage(img)
	if err != nil {
		return err
	}
	v.ok(CheckImageSignature, img.Component, fmt.Sprintf("%s %s: mirrored, signed by the release key", img.Component, want))
	return nil
}

// checksums verifies SHA256SUMS as `releasegen verify -any` and
// `sha256sum --strict -c` do.
func (v *run) checksums() error {
	b, err := os.ReadFile(v.path(ChecksumsFile))
	if errors.Is(err, fs.ErrNotExist) && !v.o.Package {
		return nil
	}
	if err != nil {
		return v.fail(CheckChecksums, ChecksumsFile, "no SHA256SUMS in "+v.dir, nil)
	}
	sig, err := os.ReadFile(v.path(ChecksumsFile + ".sig"))
	if err != nil {
		return v.fail(CheckChecksums, ChecksumsFile, "SHA256SUMS: the signature does not verify", err)
	}
	if err := VerifySignature(v.o.Key, b, sig); err != nil {
		return v.fail(CheckChecksums, ChecksumsFile, "SHA256SUMS: the signature does not verify", err)
	}
	sums, err := ParseChecksums(b)
	if err != nil {
		return v.fail(CheckChecksums, ChecksumsFile, "SHA256SUMS: a file does not match", err)
	}
	for _, s := range sums {
		if err := v.fileDigest(s.Path, s.SHA256); err != nil {
			return v.fail(CheckChecksums, s.Path, "SHA256SUMS: a file does not match", err)
		}
	}
	v.ok(CheckChecksums, ChecksumsFile, "SHA256SUMS signed, and every file it lists matches")
	return nil
}

// Checksum is one line of SHA256SUMS.
type Checksum struct{ SHA256, Path string }

// ParseChecksums reads SHA256SUMS as `sha256sum --strict -c` does
// ("<hex>  <path>" or "<hex> *<path>" per line; any other line refuses the
// file), and also refuses paths outside the directory.
func ParseChecksums(b []byte) ([]Checksum, error) {
	s := string(b)
	if !strings.HasSuffix(s, "\n") && s != "" {
		s += "\n"
	}
	var out []Checksum
	for i, l := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if len(l) < 67 || (l[65] != ' ' && l[65] != '*') || l[64] != ' ' {
			return nil, fmt.Errorf("line %d is not a checksum line", i+1)
		}
		sum := strings.ToLower(l[:64])
		p := l[66:]
		if !hex64.MatchString(sum) || !safePath(p) {
			return nil, fmt.Errorf("line %d is not a checksum line of a file in the release", i+1)
		}
		out = append(out, Checksum{SHA256: sum, Path: p})
	}
	if len(out) == 0 || s == "" {
		return nil, errors.New("no checksum lines")
	}
	return out, nil
}

func (v *run) fileDigest(name, want string) error {
	f, err := os.Open(v.path(name)) // #nosec G304 -- a file of the release being verified, path checked by safePath
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("%s does not match", name)
	}
	return nil
}

// packageManifest verifies package-manifest.json and returns the images it
// lists beyond the release manifest's.
func (v *run) packageManifest(m *Manifest) ([]Image, error) {
	const name = PackageManifestFile
	b, err := os.ReadFile(v.path(name))
	if errors.Is(err, fs.ErrNotExist) && !v.o.Package {
		return nil, nil
	}
	if err != nil {
		return nil, v.fail(CheckPackageManifest, name, "no package-manifest.json in "+v.dir, nil)
	}
	sig, err := os.ReadFile(v.path(name + ".sig"))
	if err != nil {
		return nil, v.fail(CheckPackageManifest, name, "package-manifest.json: the signature does not verify", err)
	}
	if err := VerifySignature(v.o.Key, b, sig); err != nil {
		return nil, v.fail(CheckPackageManifest, name, "package-manifest.json: the signature does not verify", err)
	}
	pm, err := DecodePackageManifest(b)
	if err != nil {
		return nil, v.fail(CheckPackageManifest, name, "package-manifest.json: not a "+PackageFormat+" manifest", err)
	}
	if pm.Release != m.Release {
		return nil, v.fail(CheckRelease, name, fmt.Sprintf("package-manifest.json: release %s, the release manifest names %s", pm.Release, m.Release), nil)
	}
	listed := map[string]bool{name: true, name + ".sig": true, ChecksumsFile: true, ChecksumsFile + ".sig": true}
	for _, f := range pm.Files {
		listed[f.Path] = true
		if err := v.fileDigest(f.Path, f.SHA256); err != nil {
			return nil, v.fail(CheckPackageManifest, f.Path, "package-manifest.json: "+f.Path+" does not match", err)
		}
	}
	var unlisted []string
	err = filepath.WalkDir(v.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(v.dir, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); !listed[rel] {
			unlisted = append(unlisted, rel)
		}
		return nil
	})
	if err != nil {
		return nil, v.fail(CheckPackageManifest, name, "package-manifest.json: the package cannot be read", err)
	}
	if len(unlisted) > 0 {
		slices.Sort(unlisted)
		return nil, v.fail(CheckPackageManifest, unlisted[0], "package-manifest.json: "+unlisted[0]+" is not listed", nil)
	}
	byComp := map[string]string{}
	for _, i := range pm.Images {
		byComp[i.Component] = i.Image
	}
	named := maps.Clone(m.Images)
	for _, x := range m.Mirrors {
		named[x.Component] = x.Image
	}
	for _, c := range slices.Sorted(maps.Keys(named)) {
		switch got := byComp[c]; {
		case got == "":
			return nil, v.fail(CheckPackageManifest, c, "package-manifest.json: does not list "+c+" "+named[c], nil)
		case got != named[c]:
			return nil, v.fail(CheckPackageManifest, c, fmt.Sprintf("package-manifest.json: %s is %s, the release manifest names %s", c, got, named[c]), nil)
		}
	}
	var extra []Image
	for _, i := range pm.Images {
		if _, ok := named[i.Component]; !ok {
			extra = append(extra, Image(i))
		}
	}
	slices.SortFunc(extra, func(a, b Image) int { return strings.Compare(a.Component, b.Component) })
	v.ok(CheckPackageManifest, name, "package manifest signed, and every file and image it lists matches")
	return extra, nil
}

// image verifies one image from its layout.
func (v *run) image(img Image) error {
	c := img.Component
	l, want, err := v.openImage(img)
	if err != nil {
		return err
	}
	if len(l.verifyAttestations(v.o.Key, want, PredicateSPDX)) == 0 {
		return v.fail(CheckSBOM, c, c+": no spdxjson attestation verifies with the release key", nil)
	}
	prov := l.verifyAttestations(v.o.Key, want, PredicateSLSA)
	if len(prov) == 0 {
		return v.fail(CheckProvenance, c, c+": no slsaprovenance attestation verifies with the release key", nil)
	}
	if p := v.o.Provenance; p != nil && !slices.ContainsFunc(prov, p.Allows) {
		return v.fail(CheckProvenancePol, c, c+": no slsaprovenance attestation names the release builder and source", nil)
	}
	v.ok(CheckImageSignature, c, fmt.Sprintf("%s %s: signed, SBOM and provenance attested", c, want))
	return nil
}

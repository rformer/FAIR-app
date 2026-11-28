package releaseverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// An OCI image layout on disk (image-spec image-layout.md): oci-layout,
// index.json and blobs/sha256/<hex>. Two writers matter here:
//   - `cosign save` (the per-component directories images/<component>/ of
//     F-012's verification kit): index.json lists the image, its signatures
//     and its attestations, told apart by the annotation "kind";
//   - registries' and Zarf's layouts, where signatures and attestations are
//     either tagged by cosign's convention (sha256-<hex>.sig, .att) or OCI
//     referrers (a manifest whose subject is the image).
// Signatures and attestations are found by any of the three; what is found
// is only a candidate: each is verified with the release key.

// Media types and annotations cosign uses.
const (
	mediaSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	mediaDSSE          = "application/vnd.dsse.envelope.v1+json"
	annotationKind     = "kind"
	annotationSig      = "dev.cosignproject.cosign/signature"
	kindImage          = "dev.cosignproject.cosign/image"
	kindImageIndex     = "dev.cosignproject.cosign/imageIndex"
	kindSigs           = "dev.cosignproject.cosign/sigs"
	kindAtts           = "dev.cosignproject.cosign/atts"
	annotationRefName  = "org.opencontainers.image.ref.name"
	annotationBaseName = "org.opencontainers.image.base.name" // Zarf's
	intotoPayloadType  = "application/vnd.in-toto+json"
	simpleSigningType  = "cosign container image signature"
	maxManifestBytes   = 4 << 20
	maxEnvelopeBytes   = 16 << 20
)

// Predicate types of the attestations the release carries (cosign attest
// --type spdxjson, --type slsaprovenance).
const (
	PredicateSPDX = "https://spdx.dev/Document"
	PredicateSLSA = "https://slsa.dev/provenance/v0.2"
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	URLs         []string          `json:"urls,omitempty"`
}

// manifest is an image manifest or an index (the fields this package reads).
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType,omitempty"`
	Config        *descriptor  `json:"config,omitempty"`
	Layers        []descriptor `json:"layers,omitempty"`
	Manifests     []descriptor `json:"manifests,omitempty"`
	Subject       *descriptor  `json:"subject,omitempty"`
}

func (m *manifest) isIndex() bool { return m.Manifests != nil && m.Config == nil }

// layout is an OCI image layout directory.
type layout struct {
	dir   string
	index manifest
	// every manifest reachable from index.json, with how it was named
	entries []entry
}

type entry struct {
	desc descriptor
	m    *manifest // nil when its blob is missing or not a manifest
}

func openLayout(dir string) (*layout, error) {
	ol, err := os.ReadFile(filepath.Join(dir, "oci-layout")) // #nosec G304 -- the release directory being verified
	if err != nil {
		return nil, fmt.Errorf("not an OCI image layout: %w", err)
	}
	var v struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(ol, &v); err != nil || v.Version == "" {
		return nil, errors.New("not an OCI image layout: oci-layout unreadable")
	}
	b, err := readLimited(filepath.Join(dir, "index.json"), maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	l := &layout{dir: dir}
	if err := json.Unmarshal(b, &l.index); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	if l.index.SchemaVersion != 2 {
		return nil, errors.New("index.json: schemaVersion is not 2")
	}
	seen := map[string]bool{}
	var walk func(ds []descriptor, depth int) error
	walk = func(ds []descriptor, depth int) error {
		if depth > 4 {
			return errors.New("index.json: indexes nested too deep")
		}
		for _, d := range ds {
			if !digestRE.MatchString(d.Digest) {
				return fmt.Errorf("index.json: digest %q is not sha256", d.Digest)
			}
			e := entry{desc: d}
			if m, err := l.manifest(d.Digest); err == nil {
				e.m = m
			}
			l.entries = append(l.entries, e)
			if e.m != nil && e.m.isIndex() && !seen[d.Digest] {
				seen[d.Digest] = true
				if err := walk(e.m.Manifests, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(l.index.Manifests, 0); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *layout) blobPath(digest string) string {
	return filepath.Join(l.dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// blob reads a small blob (a manifest, a payload, an envelope).
func (l *layout) blob(digest string, limit int64) ([]byte, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("digest %q is not sha256", digest)
	}
	return readLimited(l.blobPath(digest), limit)
}

func (l *layout) manifest(digest string) (*manifest, error) {
	b, err := l.blob(digest, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// checkBlob streams a blob and compares its SHA-256 with its digest.
func (l *layout) checkBlob(d descriptor) error {
	if !digestRE.MatchString(d.Digest) {
		return fmt.Errorf("digest %q is not sha256", d.Digest)
	}
	f, err := os.Open(l.blobPath(d.Digest)) // #nosec G304 -- a blob of the layout being verified
	if err != nil {
		return fmt.Errorf("blob %s is missing", d.Digest)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest || (d.Size > 0 && n != d.Size) {
		return fmt.Errorf("blob %s does not match its digest", d.Digest)
	}
	return nil
}

// image is the image a cosign-saved layout holds (kind image or
// imageIndex): its digest computed from its manifest's bytes, as cosign
// computes it. ok is false when the layout names no such image.
func (l *layout) image() (digest string, ok bool, err error) {
	for _, e := range l.index.Manifests {
		if k := e.Annotations[annotationKind]; k == kindImage || k == kindImageIndex {
			b, err := l.blob(e.Digest, maxManifestBytes)
			if err != nil {
				return "", true, fmt.Errorf("the image's manifest: %w", err)
			}
			sum := sha256.Sum256(b)
			return "sha256:" + hex.EncodeToString(sum[:]), true, nil
		}
	}
	return "", false, nil
}

// has reports whether the layout holds the manifest of digest d.
func (l *layout) has(d string) bool {
	for _, e := range l.entries {
		if e.desc.Digest == d && e.m != nil {
			return true
		}
	}
	return false
}

// attached returns the manifests that carry the signatures (suffix "sig")
// or attestations ("att") of the image with digest d: cosign save's kind
// annotation, cosign's tag convention, or OCI referrers.
func (l *layout) attached(d, suffix string) []*manifest {
	kind := kindSigs
	if suffix == "att" {
		kind = kindAtts
	}
	tag := strings.Replace(d, ":", "-", 1) + "." + suffix
	var out []*manifest
	seen := map[string]bool{}
	for _, e := range l.entries {
		if e.m == nil || seen[e.desc.Digest] {
			continue
		}
		name := e.desc.Annotations[annotationRefName]
		if name == "" {
			name = e.desc.Annotations[annotationBaseName]
		}
		match := e.desc.Annotations[annotationKind] == kind ||
			name == tag || strings.HasSuffix(name, ":"+tag) ||
			e.m.Subject != nil && e.m.Subject.Digest == d
		if match {
			seen[e.desc.Digest] = true
			out = append(out, e.m)
		}
	}
	return out
}

// checkContent requires the image's manifest (or index) and everything it
// references in the layout to match their digests: an image manifest's
// config and layers must be present; an index's children are checked when
// present, and at least one must be.
func (l *layout) checkContent(d string, depth int) error {
	if depth > 4 {
		return errors.New("indexes nested too deep")
	}
	if err := l.checkBlob(descriptor{Digest: d}); err != nil {
		return err
	}
	m, err := l.manifest(d)
	if err != nil {
		return fmt.Errorf("manifest %s: %w", d, err)
	}
	switch {
	case m.isIndex():
		present := 0
		for _, c := range m.Manifests {
			if _, err := os.Stat(l.blobPath(c.Digest)); err != nil || !digestRE.MatchString(c.Digest) {
				continue
			}
			present++
			if err := l.checkContent(c.Digest, depth+1); err != nil {
				return err
			}
		}
		if present == 0 {
			return fmt.Errorf("index %s: none of its images is in the layout", d)
		}
	case m.Config != nil:
		if err := l.checkBlob(*m.Config); err != nil {
			return err
		}
		for _, ly := range m.Layers {
			if len(ly.URLs) > 0 { // a foreign layer the image names by URL
				continue
			}
			if err := l.checkBlob(ly); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%s is neither an image manifest nor an index", d)
	}
	return nil
}

// simpleSigning is cosign's signature payload.
type simpleSigning struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// verifySignatures counts the cosign signatures of image d that verify
// with pub: an ECDSA signature (base64 in the layer's annotation) over
// SHA-256 of the simple-signing payload, whose critical.image digest is d.
func (l *layout) verifySignatures(pub *ecdsa.PublicKey, d string) int {
	n := 0
	for _, m := range l.attached(d, "sig") {
		for _, ly := range m.Layers {
			if ly.MediaType != mediaSimpleSigning {
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(ly.Annotations[annotationSig])
			if err != nil || len(sig) == 0 {
				continue
			}
			payload, err := l.blob(ly.Digest, maxManifestBytes)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(payload)
			if !ecdsa.VerifyASN1(pub, sum[:], sig) {
				continue
			}
			var p simpleSigning
			if json.Unmarshal(payload, &p) != nil || p.Critical.Type != simpleSigningType || p.Critical.Image.DockerManifestDigest != d {
				continue
			}
			n++
		}
	}
	return n
}

// envelope is a DSSE envelope.
type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// Statement is an in-toto statement, as an attestation's payload.
type Statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// pae is DSSE's pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// verifyAttestations returns the in-toto statements of predicate type pt
// attached to image d whose DSSE envelope verifies with pub (any of its
// signatures: ECDSA over SHA-256 of the PAE) and whose subject is d.
func (l *layout) verifyAttestations(pub *ecdsa.PublicKey, d, pt string) []Statement {
	var out []Statement
	want := strings.TrimPrefix(d, "sha256:")
	for _, m := range l.attached(d, "att") {
		for _, ly := range m.Layers {
			if ly.MediaType != mediaDSSE {
				continue
			}
			b, err := l.blob(ly.Digest, maxEnvelopeBytes)
			if err != nil {
				continue
			}
			var env envelope
			if json.Unmarshal(b, &env) != nil || env.PayloadType != intotoPayloadType {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(pae(env.PayloadType, payload))
			signed := false
			for _, s := range env.Signatures {
				sig, err := base64.StdEncoding.DecodeString(s.Sig)
				if err == nil && ecdsa.VerifyASN1(pub, sum[:], sig) {
					signed = true
					break
				}
			}
			if !signed {
				continue
			}
			var st Statement
			if json.Unmarshal(payload, &st) != nil || st.PredicateType != pt {
				continue
			}
			for _, s := range st.Subject {
				if s.Digest["sha256"] == want {
					out = append(out, st)
					break
				}
			}
		}
	}
	return out
}

func readLimited(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file) // #nosec G304 G703 -- a file of the release directory being verified
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(file), limit)
	}
	return b, nil
}

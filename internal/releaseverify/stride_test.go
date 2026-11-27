package releaseverify_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

// TestSTRIDEF014Verify: design §7, "S, T: a tampered, substituted or
// foreign-key-signed release, chart or package is installed". fairctl
// verifies the manifest, SHA256SUMS, package-manifest.json and every
// image's signature and attestations offline with the pinned release key
// before acting, and refuses each of these packages, naming the check.
func TestSTRIDEF014Verify(t *testing.T) {
	key := rt.NewKey(t)
	other := rt.NewKey(t)
	opts := releaseverify.Options{Key: &key.PublicKey, Package: true, Provenance: releaseverify.ReleasePolicy()}
	images := func() []rt.Image { return []rt.Image{{Component: "gateway"}, {Component: "iam"}} }
	extra := func() []rt.Image { return []rt.Image{{Component: "postgres"}} }
	pkg := func(t *testing.T, r rt.Release) (string, *rt.Written) {
		t.Helper()
		r.Key, r.Package = key, true
		if r.Images == nil {
			r.Images = images()
		}
		if r.Extra == nil {
			r.Extra = extra()
		}
		if r.Files == nil {
			r.Files = map[string][]byte{"tools/fairctl-linux-amd64": []byte("fairctl"), "notes/v1.2.3.md": []byte("# v1.2.3\n")}
		}
		dir := filepath.Join(t.TempDir(), "fair-v1.2.3-airgap")
		return dir, rt.Build(t, dir, r)
	}
	// relist re-signs the package manifest over the directory as it now is,
	// so a test reaches the check after it.
	relist := func(t *testing.T, dir string, w *rt.Written) {
		t.Helper()
		pm := *w.Package
		pm.Files = rt.ListFiles(t, dir)
		rt.WritePackageManifest(t, dir, key, &pm)
	}
	write := func(t *testing.T, p string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(t *testing.T, p string) []byte {
		t.Helper()
		b, err := os.ReadFile(p) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	expect := func(t *testing.T, dir string, o releaseverify.Options, check, msg string) {
		t.Helper()
		rep := releaseverify.Verify(dir, o)
		if rep.Verified || rep.Refusal == nil {
			t.Fatalf("verified; want refusal %s %q", check, msg)
		}
		if rep.Refusal.Check != check || !strings.Contains(rep.Refusal.Message, msg) {
			t.Fatalf("refused with %s %q (%s); want %s %q", rep.Refusal.Check, rep.Refusal.Message, rep.Refusal.Detail, check, msg)
		}
		if rep.Err() == nil {
			t.Fatal("Err() is nil for a refusal")
		}
	}

	t.Run("the package as signed verifies", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		rep := releaseverify.Verify(dir, opts)
		if !rep.Verified || rep.Err() != nil {
			t.Fatalf("refused: %+v", rep.Refusal)
		}
		if len(rep.Images) != 3 || rep.Images[2].Component != "postgres" {
			t.Fatalf("images %+v: the bundled image must be verified too", rep.Images)
		}
	})

	// Wrong key.
	t.Run("pinned key is another key", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		o := opts
		o.Key = &other.PublicKey
		expect(t, dir, o, releaseverify.CheckReleaseKey, "cosign.pub: not the pinned release key")
	})
	t.Run("cosign.pub substituted", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		write(t, filepath.Join(dir, "cosign.pub"), rt.PublicPEM(t, other))
		expect(t, dir, opts, releaseverify.CheckReleaseKey, "cosign.pub: not the pinned release key")
	})
	t.Run("a whole release signed by another key", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "r")
		rt.Build(t, dir, rt.Release{Key: other, Package: true, Images: images(), Extra: extra()})
		write(t, filepath.Join(dir, "cosign.pub"), rt.PublicPEM(t, key))
		expect(t, dir, opts, releaseverify.CheckReleaseManifest, "release-manifest.json: the signature does not verify with cosign.pub")
	})
	t.Run("no manifest signature", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		if err := os.Remove(filepath.Join(dir, "release-manifest.json.sig")); err != nil {
			t.Fatal(err)
		}
		expect(t, dir, opts, releaseverify.CheckReleaseManifest, "no release-manifest.json.sig in")
	})
	t.Run("an image signed by another key", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{rt.WithKey(rt.Image{Component: "gateway"}, other), {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckImageSignature, "gateway: the release key's signature does not verify")
	})
	t.Run("an attestation signed by another key", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway", SigKey: key, SBOMKey: key, ProvKey: other}, {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckProvenance, "gateway: no slsaprovenance attestation verifies with the release key")
	})

	// Tampered artifact.
	t.Run("an edited release manifest", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		p := filepath.Join(dir, "release-manifest.json")
		write(t, p, []byte(strings.Replace(string(read(t, p)), "v1.2.3", "v9.9.9", 1)))
		expect(t, dir, opts, releaseverify.CheckReleaseManifest, "release-manifest.json: the signature does not verify with cosign.pub")
	})
	t.Run("a file SHA256SUMS lists, changed", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		write(t, filepath.Join(dir, "tools", "fairctl-linux-amd64"), []byte("a substituted fairctl"))
		expect(t, dir, opts, releaseverify.CheckChecksums, "SHA256SUMS: a file does not match")
	})
	t.Run("SHA256SUMS edited", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		p := filepath.Join(dir, "SHA256SUMS")
		write(t, p, append(read(t, p), []byte(strings.Repeat("0", 64)+"  extra\n")...))
		expect(t, dir, opts, releaseverify.CheckChecksums, "SHA256SUMS: the signature does not verify")
	})
	t.Run("no SHA256SUMS in a package", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		if err := os.Remove(filepath.Join(dir, "SHA256SUMS")); err != nil {
			t.Fatal(err)
		}
		expect(t, dir, opts, releaseverify.CheckChecksums, "no SHA256SUMS in")
	})
	t.Run("a file the package manifest lists, changed", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		write(t, filepath.Join(dir, "notes", "v1.2.3.md"), []byte("# other notes\n"))
		rt.Resign(t, dir, key) // SHA256SUMS signed again over it: the package manifest still refuses it
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "package-manifest.json: notes/v1.2.3.md does not match")
	})
	t.Run("a file added to the package", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		write(t, filepath.Join(dir, "tools", "helper.sh"), []byte("#!/bin/sh\n"))
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "package-manifest.json: tools/helper.sh is not listed")
	})
	t.Run("package manifest edited", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		p := filepath.Join(dir, releaseverify.PackageManifestFile)
		write(t, p, []byte(strings.Replace(string(read(t, p)), "v1.0.0", "v0.1.0", 1)))
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "package-manifest.json: the signature does not verify")
	})
	t.Run("no package manifest", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		if err := os.Remove(filepath.Join(dir, releaseverify.PackageManifestFile)); err != nil {
			t.Fatal(err)
		}
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "no package-manifest.json in")
	})
	t.Run("an image layer changed in the layout", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{})
		layer := filepath.Join(dir, "images", "iam", "blobs", "sha256", sum("layer of iam"))
		write(t, layer, []byte("a substituted layer"))
		pm := readPackage(t, dir) // relisted: the package manifest's own digests would refuse it first
		pm.Files = rt.ListFiles(t, dir)
		rt.WritePackageManifest(t, dir, key, pm)
		expect(t, dir, opts, releaseverify.CheckImageContent, "iam: the image's content does not match its digest")
	})

	// Signature for another digest.
	t.Run("a signature for another digest", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway", SigKey: key, SBOMKey: key, ProvKey: key, SigDigest: "sha256:" + strings.Repeat("1", 64)}, {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckImageSignature, "gateway: the release key's signature does not verify")
	})
	t.Run("another signed image in place of the release's", func(t *testing.T) {
		dir, w := pkg(t, rt.Release{})
		ldir := filepath.Join(dir, "images", "iam")
		if err := os.RemoveAll(ldir); err != nil {
			t.Fatal(err)
		}
		rt.AddImage(t, ldir, rt.WithKey(rt.Image{Component: "iam", Seed: "an older iam"}, key))
		relist(t, dir, w)
		expect(t, dir, opts, releaseverify.CheckImageDigest, "iam: verified sha256:")
	})
	t.Run("the package names another image than the release manifest", func(t *testing.T) {
		dir, w := pkg(t, rt.Release{})
		pm := *w.Package
		pm.Images = append([]releaseverify.PackageImage(nil), pm.Images...)
		for i := range pm.Images {
			if pm.Images[i].Component == "iam" {
				pm.Images[i].Image = "registry.invalid/fair-iam@sha256:" + strings.Repeat("2", 64)
			}
		}
		rt.WritePackageManifest(t, dir, key, &pm)
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "package-manifest.json: iam is registry.invalid/fair-iam@sha256:2222")
	})
	t.Run("the package leaves out a release image", func(t *testing.T) {
		dir, w := pkg(t, rt.Release{})
		pm := *w.Package
		pm.Images = nil
		for _, i := range w.Package.Images {
			if i.Component != "gateway" {
				pm.Images = append(pm.Images, i)
			}
		}
		rt.WritePackageManifest(t, dir, key, &pm)
		expect(t, dir, opts, releaseverify.CheckPackageManifest, "package-manifest.json: does not list gateway")
	})

	// Missing attestation.
	t.Run("no SBOM attestation", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway", SigKey: key, ProvKey: key}, {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckSBOM, "gateway: no spdxjson attestation verifies with the release key")
	})
	t.Run("no provenance attestation", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway"}, {Component: "iam", SigKey: key, SBOMKey: key}}})
		expect(t, dir, opts, releaseverify.CheckProvenance, "iam: no slsaprovenance attestation verifies with the release key")
	})
	t.Run("a bundled image without provenance", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Extra: []rt.Image{{Component: "postgres", SigKey: key, SBOMKey: key}}})
		expect(t, dir, opts, releaseverify.CheckProvenance, "postgres: no slsaprovenance attestation verifies with the release key")
	})
	t.Run("attestations for another image", func(t *testing.T) {
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway", SigKey: key, SBOMKey: key, ProvKey: key, AttDigest: "sha256:" + strings.Repeat("3", 64)}, {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckSBOM, "gateway: no spdxjson attestation verifies with the release key")
	})
	t.Run("no layout for an image", func(t *testing.T) {
		dir, w := pkg(t, rt.Release{})
		if err := os.RemoveAll(filepath.Join(dir, "images", "postgres")); err != nil {
			t.Fatal(err)
		}
		relist(t, dir, w)
		expect(t, dir, opts, releaseverify.CheckImageSignature, "postgres: no images/postgres in the release")
	})

	// Attestation for another source.
	t.Run("provenance from another repository", func(t *testing.T) {
		pred := rt.DefaultProvenance("v1.2.3")
		pred["invocation"] = map[string]any{"configSource": map[string]any{"uri": "git+https://github.com/someone/FAIR-app@refs/tags/v1.2.3", "entryPoint": ".github/workflows/release.yml"}}
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway", Provenance: pred}, {Component: "iam"}}})
		expect(t, dir, opts, releaseverify.CheckProvenancePol, "gateway: no slsaprovenance attestation names the release builder and source")
	})
	t.Run("provenance from another builder", func(t *testing.T) {
		pred := rt.DefaultProvenance("v1.2.3")
		pred["builder"] = map[string]any{"id": "https://example.invalid/fixture"}
		dir, _ := pkg(t, rt.Release{Images: []rt.Image{{Component: "gateway"}, {Component: "iam", Provenance: pred}}})
		expect(t, dir, opts, releaseverify.CheckProvenancePol, "iam: no slsaprovenance attestation names the release builder and source")
	})

	// Downgrade: an older signed release manifest beside the package.
	t.Run("an older signed release manifest", func(t *testing.T) {
		old := filepath.Join(t.TempDir(), "old")
		rt.Build(t, old, rt.Release{Key: key, Release: "v1.1.0", Images: images()})
		dir, _ := pkg(t, rt.Release{})
		for _, f := range []string{"release-manifest.json", "release-manifest.json.sig"} {
			write(t, filepath.Join(dir, f), read(t, filepath.Join(old, f)))
		}
		rt.Resign(t, dir, key)
		expect(t, dir, opts, releaseverify.CheckRelease, "package-manifest.json: release v1.2.3, the release manifest names v1.1.0")
	})
}

func readPackage(t *testing.T, dir string) *releaseverify.PackageManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, releaseverify.PackageManifestFile)) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	pm, err := releaseverify.DecodePackageManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

package airgap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rformer/fair-app/internal/airgap"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releaseverify"
)

// TestZarfPackageLive reads a Zarf package `zarf package create` made from
// releasegen package zarf's zarf.yaml (FAIR_TEST_ZARF_PACKAGE), whose
// images were signed and attested with the PEM key FAIR_TEST_ZARF_KEY
// (imported into cosign) and are named by the release manifest
// FAIR_TEST_ZARF_MANIFEST (unsigned): the images come out of Zarf's own
// layout and verify with releaseverify, mirrors by signature alone. It
// proves the layout Zarf writes is one fairctl verify reads; without the
// variables it is skipped (the release pipeline makes the real package).
func TestZarfPackageLive(t *testing.T) {
	zarf, keyFile, manifest := os.Getenv("FAIR_TEST_ZARF_PACKAGE"), os.Getenv("FAIR_TEST_ZARF_KEY"), os.Getenv("FAIR_TEST_ZARF_MANIFEST")
	if zarf == "" || keyFile == "" || manifest == "" {
		t.Skip("set FAIR_TEST_ZARF_PACKAGE, FAIR_TEST_ZARF_KEY and FAIR_TEST_ZARF_MANIFEST to read a real Zarf package")
	}
	key, err := profilepkg.LoadPrivateKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "p")
	mb, err := os.ReadFile(manifest) // #nosec G304 G703 -- the test's input
	if err != nil {
		t.Fatal(err)
	}
	zb, err := os.ReadFile(zarf) // #nosec G304 G703 -- the test's input
	if err != nil {
		t.Fatal(err)
	}
	put(t, dir, releaseverify.ReleaseManifestFile, mb)
	put(t, dir, releaseverify.ReleaseManifestFile+".sig", sign(t, key, mb))
	put(t, dir, releaseverify.ReleaseKeyFile, publicPEM(t, key))
	put(t, dir, filepath.Base(zarf), zb)
	pm := packageManifest(t, dir, mb)
	writeSigned(t, dir, key, releaseverify.PackageManifestFile, pm)
	writeChecksums(t, dir, key)
	layout, cleanup, err := airgap.Layout(dir, &key.PublicKey, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	r := releaseverify.Verify(dir, releaseverify.Options{Key: &key.PublicKey, Package: true, Layout: layout})
	for _, s := range r.Steps {
		t.Log(s.Message)
	}
	if !r.Verified {
		t.Fatalf("refused: %+v", r.Refusal)
	}
}

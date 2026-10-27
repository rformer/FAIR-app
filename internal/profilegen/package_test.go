package profilegen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/settings"
)

const packagesDir = "../../profiles/packages"

func committedManifest(t *testing.T) *profilepkg.Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(packagesDir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	m, err := profilepkg.DecodeManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func buildPackages(t *testing.T, bindings string, previous *profilepkg.Manifest) map[string][]byte {
	t.Helper()
	files, err := BuildPackages(pinDir, profilesDir, bindings, settings.F001Defs(), previous)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Verification for T-06: two independent builds produce byte-identical
// packages, so every digest is reproducible.
func TestPackagesReproducible(t *testing.T) {
	a := buildPackages(t, bindingsDir, nil)
	b := buildPackages(t, bindingsDir, nil)
	if len(a) != 4 {
		t.Fatalf("built %d files, want 3 packages and a manifest", len(a))
	}
	for name := range a {
		if profilepkg.Digest(a[name]) != profilepkg.Digest(b[name]) {
			t.Errorf("%s differs between builds", name)
		}
	}
}

// The committed packages and manifest are what the generator produces;
// regenerate with `go run ./cmd/profilegen packages` (which refuses to change
// a pinned package without a version bump).
func TestPackagesUpToDate(t *testing.T) {
	want := buildPackages(t, bindingsDir, committedManifest(t))
	got := map[string][]byte{}
	entries, err := os.ReadDir(packagesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(packagesDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got[e.Name()] = b
	}
	for name, b := range want {
		if string(got[name]) != string(b) {
			t.Errorf("profiles/packages/%s is stale or missing; run go run ./cmd/profilegen packages", name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("profiles/packages/%s is not generated; run go run ./cmd/profilegen packages", name)
		}
	}
}

// shippedFile is the file of the package version profiles/packages.yaml
// ships for id, from the built manifest.
func shippedFile(t *testing.T, files map[string][]byte, id string) string {
	t.Helper()
	m, err := profilepkg.DecodeManifest(files[ManifestFile])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Packages {
		if e.ID == id {
			return e.File
		}
	}
	t.Fatalf("no package %s in the manifest", id)
	return ""
}

// The packages carry exactly the values the pkg/settings stand-in serves
// until the posture service (T-16) imports packages instead.
func TestPackagesMatchBuiltinProfiles(t *testing.T) {
	files := buildPackages(t, bindingsDir, nil)
	m, err := profilepkg.DecodeManifest(files[ManifestFile])
	if err != nil {
		t.Fatal(err)
	}
	builtin := settings.BuiltinProfiles()
	if len(m.Packages) != len(builtin) {
		t.Fatalf("%d packages, %d built-in profiles", len(m.Packages), len(builtin))
	}
	defs := settings.F001Defs()
	for _, want := range builtin {
		b := files[shippedFile(t, files, want.ID)]
		p, err := profilepkg.Decode(b)
		if err != nil {
			t.Fatalf("%s: %v", want.ID, err)
		}
		got, gotDefs, err := p.ToSettings()
		if err != nil {
			t.Fatal(err)
		}
		if got.Title != want.Title || got.Family != want.Family || !reflect.DeepEqual(got.Settings, want.Settings) {
			t.Errorf("%s: package %+v, stand-in %+v", want.ID, got, want)
		}
		if err := settings.ValidateProfile(got, defs); err != nil {
			t.Errorf("%s: %v", want.ID, err)
		}
		// The package's own definitions agree with the registered ones.
		for _, gd := range gotDefs {
			for _, d := range defs {
				if d.Key == gd.Key && (d.Kind != gd.Kind || d.Direction != gd.Direction || !reflect.DeepEqual(d.Order, gd.Order) ||
					!reflect.DeepEqual(d.Params, gd.Params) || d.BUScopable != gd.BUScopable ||
					!reflect.DeepEqual(d.Floor, gd.Floor) || !reflect.DeepEqual(d.FloorFamilies, gd.FloorFamilies)) {
					t.Errorf("%s/%s: package def %+v, registered %+v", want.ID, d.Key, gd, d)
				}
			}
		}
		// Every input is recorded with its digest.
		var paths []string
		for _, s := range p.Profile.Sources {
			paths = append(paths, s.Path)
			if len(s.SHA256) != 64 {
				t.Errorf("%s: source %s has no digest", want.ID, s.Path)
			}
		}
		if !strings.Contains(strings.Join(paths, " "), p.Profile.Base) || len(paths) < len(defs)+2 {
			t.Errorf("%s: sources %v", want.ID, paths)
		}
	}
}

// A pinned package cannot change under the same version.
func TestPackagesImmutable(t *testing.T) {
	m := committedManifest(t)
	m.Packages[0].SHA256 = strings.Repeat("0", 64)
	_, err := BuildPackages(pinDir, profilesDir, bindingsDir, settings.F001Defs(), m)
	if err == nil || !strings.Contains(err.Error(), "bump") {
		t.Fatalf("changed a pinned package: %v", err)
	}
}

// copyBindings copies the bindings to a temp dir, applying edits.
func copyBindings(t *testing.T, edit func(files map[string]string)) string {
	t.Helper()
	files := map[string]string{}
	entries, err := os.ReadDir(bindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(bindingsDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(b)
	}
	edit(files)
	dir := t.TempDir()
	for n, s := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The build fails closed: no package is produced from bindings that are
// incomplete, out of bounds, or drifted from their source.
func TestPackagesFailClosed(t *testing.T) {
	cases := map[string]func(f map[string]string){
		"missing binding": func(f map[string]string) { delete(f, "audit.enabled.yaml") },
		"drifted source": func(f map[string]string) {
			f["session.idle_timeout.yaml"] = strings.Replace(f["session.idle_timeout.yaml"], "fifteen (15) minutes", "thirty (30) minutes", 1)
		},
		"below hard floor": func(f map[string]string) {
			f["tls.min_version.yaml"] = strings.Replace(f["tls.min_version.yaml"], `allowed: ["1.2"] }
    platform_choice: "800-171`, `allowed: ["1.1", "1.2"] }
    platform_choice: "800-171`, 1)
		},
		"no origin": func(f map[string]string) {
			s := f["auth.jit_provisioning.yaml"]
			i := strings.LastIndex(s, "platform_choice:")
			f["auth.jit_provisioning.yaml"] = s[:i]
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyBindings(t, edit)
			if _, err := BuildPackages(pinDir, profilesDir, dir, settings.F001Defs(), nil); err == nil {
				t.Fatal("built packages")
			}
		})
	}
	// The copy itself builds the committed packages (the edits are what fail).
	dir := copyBindings(t, func(map[string]string) {})
	if got, want := buildPackages(t, dir, nil), buildPackages(t, bindingsDir, nil); !maps.EqualFunc(got, want, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatal("copied bindings build different packages")
	}
}

// Verification for T-06 (tamper test, end to end): the committed release
// signs and verifies; changing a value after signing is refused, re-signing
// the changed package does not match the manifest pin, and a release signed
// by any other key is refused.
func TestPackagesSignedReleaseTamper(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := buildPackages(t, bindingsDir, nil)
	sigs, err := profilepkg.SignRelease(key, ManifestFile, files)
	if err != nil {
		t.Fatal(err)
	}
	release := maps.Clone(files)
	maps.Copy(release, sigs)
	pkgs, err := profilepkg.VerifyRelease(&key.PublicKey, ManifestFile, release)
	if err != nil || len(pkgs) != 3 {
		t.Fatalf("%d packages: %v", len(pkgs), err)
	}

	fed := shippedFile(t, files, settings.ProfileFedRAMPModerate)
	weakened := []byte(strings.Replace(string(files[fed]), `"bound": "15m0s"`, `"bound": "1h0m0s"`, 1))
	if string(weakened) == string(files[fed]) {
		t.Fatal("test did not change the package")
	}
	tampered := maps.Clone(release)
	tampered[fed] = weakened
	if _, err := profilepkg.VerifyRelease(&key.PublicKey, ManifestFile, tampered); err == nil {
		t.Fatal("accepted a package changed after signing")
	}
	resigned := maps.Clone(tampered)
	resigned[fed+profilepkg.SigSuffix], _ = profilepkg.Sign(key, weakened)
	if _, err := profilepkg.VerifyRelease(&key.PublicKey, ManifestFile, resigned); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("accepted a re-signed package that is not pinned: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSigs, _ := profilepkg.SignRelease(other, ManifestFile, files)
	forged := maps.Clone(files)
	maps.Copy(forged, otherSigs)
	if _, err := profilepkg.VerifyRelease(&key.PublicKey, ManifestFile, forged); err == nil {
		t.Fatal("accepted a release signed by another key")
	}
}

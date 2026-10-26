// Command profilegen is the build-time profile tool (F-015 design §2, §4).
// Run it from the repository root.
//
//	profilegen profiles                    regenerate the in-repo OSCAL profiles under profiles/
//	profilegen packages                    rebuild profiles/packages/ (packages + manifest) from
//	                                       profiles/packages.yaml and bindings/
//	profilegen sign -key FILE -out DIR     copy the pinned packages and manifest to DIR with
//	                                       detached signatures (release pipeline)
//	profilegen verify -pub FILE -dir DIR   verify a signed release directory
//
// Signing keys are read from files (a mounted secret), never from flags or
// environment values.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rformer/fair-app/internal/profilegen"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/settings"
)

const packagesDir = "profiles/packages"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "profiles":
		err = profiles()
	case "packages":
		err = packages()
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		key := fs.String("key", "", "PEM ECDSA P-256 release signing key file")
		out := fs.String("out", "", "output directory")
		_ = fs.Parse(os.Args[2:])
		if *key == "" || *out == "" {
			usage()
		}
		err = sign(*key, *out)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		pub := fs.String("pub", "", "PEM release public key file")
		dir := fs.String("dir", "", "signed release directory")
		_ = fs.Parse(os.Args[2:])
		if *pub == "" || *dir == "" {
			usage()
		}
		err = verify(*pub, *dir)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "profilegen:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: profilegen profiles | packages | sign -key FILE -out DIR | verify -pub FILE -dir DIR   (run from the repository root)")
	os.Exit(2)
}

func profiles() error {
	files, err := profilegen.InRepoProfiles("third_party/oscal", "profiles")
	if err != nil {
		return err
	}
	return write("profiles", files)
}

func packages() error {
	var previous *profilepkg.Manifest
	if b, err := os.ReadFile(filepath.Join(packagesDir, profilegen.ManifestFile)); err == nil {
		if previous, err = profilepkg.DecodeManifest(b); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	files, err := profilegen.BuildPackages("third_party/oscal", "profiles", "bindings", settings.F001Defs(), previous)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(packagesDir, 0o750); err != nil {
		return err
	}
	// Packages dropped from packages.yaml (or superseded by a new version)
	// leave the directory; earlier releases keep their own copies.
	old, err := filepath.Glob(filepath.Join(packagesDir, "profile-*.json"))
	if err != nil {
		return err
	}
	for _, f := range old {
		if _, keep := files[filepath.Base(f)]; !keep {
			if err := os.Remove(f); err != nil {
				return err
			}
			fmt.Println("removed", f)
		}
	}
	return write(packagesDir, files)
}

func sign(keyFile, out string) error {
	key, err := profilepkg.LoadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	files, err := readDir(packagesDir)
	if err != nil {
		return err
	}
	sigs, err := profilepkg.SignRelease(key, profilegen.ManifestFile, files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	release := map[string][]byte{}
	for name, b := range files {
		if strings.HasSuffix(name, ".json") {
			release[name] = b
		}
	}
	for name, b := range sigs {
		release[name] = b
	}
	if err := write(out, release); err != nil {
		return err
	}
	if _, err := profilepkg.VerifyRelease(&key.PublicKey, profilegen.ManifestFile, release); err != nil {
		return fmt.Errorf("signed release does not verify: %w", err)
	}
	return nil
}

func verify(pubFile, dir string) error {
	pub, err := profilepkg.LoadPublicKey(pubFile)
	if err != nil {
		return err
	}
	files, err := readDir(dir)
	if err != nil {
		return err
	}
	pkgs, err := profilepkg.VerifyRelease(pub, profilegen.ManifestFile, files)
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		fmt.Printf("ok %s %s (%d settings)\n", p.Profile.ID, p.Profile.Version, len(p.Settings))
	}
	return nil
}

func readDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- operator-named directory
			if err != nil {
				return nil, err
			}
			files[e.Name()] = b
		}
	}
	return files, nil
}

func write(dir string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.WriteFile(p, files[n], 0o600); err != nil { // #nosec G703 -- names are generated or read from the directory itself
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}

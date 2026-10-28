package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rformer/fair-app/internal/profilepkg"
)

// T-35: the install-time export key pair, private key 0600, never
// overwritten.
func TestExportKey(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "export.key"), filepath.Join(dir, "export.pub")
	if err := exportKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	k, err := profilepkg.LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profilepkg.LoadPublicKey(pub)
	if err != nil || !p.Equal(&k.PublicKey) {
		t.Fatalf("public key: %v", err)
	}
	if fi, _ := os.Stat(priv); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v", fi.Mode().Perm())
	}
	before, _ := os.ReadFile(priv) // #nosec G304 -- the test's temporary directory
	if err := exportKey(priv, filepath.Join(dir, "other.pub")); err == nil {
		t.Fatal("an existing key was overwritten")
	}
	after, _ := os.ReadFile(priv) // #nosec G304 -- the test's temporary directory
	if string(after) != string(before) {
		t.Fatal("the key file changed")
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/changeevidence/ghreplay"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

// The recorded API and Flux events of internal/changeevidence.
const fixtures = "../../internal/changeevidence/testdata"

type env struct {
	dir, token, releasePub, evidenceKey string
	evidence                            *ecdsa.PublicKey
	replay                              *ghreplay.Replay
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writePEM(t *testing.T, file, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{dir: dir, token: filepath.Join(dir, "token"), releasePub: filepath.Join(dir, "cosign.pub"), evidenceKey: filepath.Join(dir, "evidence.key")}
	if err := os.WriteFile(e.token, []byte("ghp_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel := newKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(&rel.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, e.releasePub, "PUBLIC KEY", pubDER)
	ev := newKey(t)
	e.evidence = &ev.PublicKey
	evDER, err := x509.MarshalECPrivateKey(ev)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, e.evidenceKey, "EC PRIVATE KEY", evDER)

	if e.replay, err = ghreplay.Load(filepath.Join(fixtures, "github.json")); err != nil {
		t.Fatal(err)
	}
	// v0.2.0 signed with the release key, as release-sign.yml signs it.
	m, err := releasemanifest.Encode(&releasemanifest.Manifest{
		Format: releasemanifest.Format, Release: "v0.2.0",
		Images: map[string]string{"iam": "ghcr.io/acme/fair-iam@sha256:" + strings.Repeat("d", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte(fmt.Sprintf("%x  release-manifest.json\n%x  sbom-iam.spdx.json\n", sha256.Sum256(m), sha256.Sum256([]byte(`{"spdxVersion":"SPDX-2.3"}`))))
	msig, err := profilepkg.Sign(rel, m)
	if err != nil {
		t.Fatal(err)
	}
	ssig, err := profilepkg.Sign(rel, sums)
	if err != nil {
		t.Fatal(err)
	}
	for id, b := range map[string][]byte{"201": m, "202": msig, "203": sums, "204": ssig,
		"205": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})} {
		e.replay.Set("/repos/acme/fair/releases/assets/"+id, http.StatusOK, b)
	}
	return e
}

func (e *env) args(extra ...string) []string {
	return append([]string{
		"-repo", "acme/fair", "-fleet-repo", "acme/fleet", "-from", "2026-11-01", "-to", "2026-11-30",
		"-api", "https://api.github.test", "-token-file", e.token, "-release-pub", e.releasePub,
		"-checks", "testdata/variables.tf", "-flux-events", filepath.Join(fixtures, "flux"),
		"-key", e.evidenceKey, "-out", filepath.Join(e.dir, "out"),
	}, extra...)
}

func TestEvidence(t *testing.T) {
	e := setup(t)
	var stderr bytes.Buffer
	if err := run(context.Background(), e.args(), e.replay, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if m := e.replay.Misses(); len(m) > 0 {
		t.Fatalf("requests the fixture does not list: %v", m)
	}
	if !strings.Contains(stderr.String(), "21 findings") || !strings.Contains(stderr.String(), "  self_approval: 1") {
		t.Errorf("summary:\n%s", stderr.String())
	}
	for _, name := range []string{"change-evidence.json", "change-evidence.csv"} {
		p := filepath.Join(e.dir, "out", name)
		b, err := os.ReadFile(p) // #nosec G304 -- the test's output
		if err != nil {
			t.Fatal(err)
		}
		sig, err := os.ReadFile(p + ".sig") // #nosec G304 -- the test's output
		if err != nil {
			t.Fatal(err)
		}
		if err := profilepkg.VerifySignature(e.evidence, b, sig); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// The same report the package's golden files hold.
		golden := map[string]string{"change-evidence.json": "report.golden.json", "change-evidence.csv": "report.golden.csv"}[name]
		want, err := os.ReadFile(filepath.Join(fixtures, golden))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, want) {
			t.Errorf("%s differs from %s", name, golden)
		}
		if bytes.Contains(b, []byte("ghp_test")) {
			t.Errorf("%s holds the token", name)
		}
	}
}

func TestEvidenceInstance(t *testing.T) {
	e := setup(t)
	var stderr bytes.Buffer
	if err := run(context.Background(), e.args("-instance", "beta"), e.replay, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "out", "change-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"instance": "beta"`, "deployment_unapproved", "apply_failed", "acme/fleet#4"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("no %q", want)
		}
	}
	for _, other := range []string{`"instance": "alpha"`, "acme/fleet#3", "apply_self_approved"} {
		if bytes.Contains(b, []byte(other)) {
			t.Errorf("%q is another instance's", other)
		}
	}
}

func TestEvidenceRefuses(t *testing.T) {
	e := setup(t)
	bad := filepath.Join(e.dir, "bad-events")
	if err := os.MkdirAll(bad, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "e.json"), []byte(`{"severity":"info"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"key and unsigned": e.args("-unsigned"),
		"bad day":          e.args("-from", "2026-11"),
		"no token file":    e.args("-token-file", filepath.Join(e.dir, "none")),
		"plain http":       e.args("-api", "http://api.github.test"),
		"bad events":       e.args("-flux-events", bad),
		"no checks":        e.args("-checks", filepath.Join(fixtures, "github.json")),
		"extra argument":   e.args("x"),
	} {
		var stderr bytes.Buffer
		if err := run(context.Background(), args, e.replay, &stderr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"-repo", "acme/fair"}, e.replay, &stderr); err == nil {
		t.Error("no output or key: accepted")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "out")); !os.IsNotExist(err) {
		t.Error("a refused run wrote output")
	}
}

// -unsigned leaves the signing to releasegen sign -any -kms (ADR-018).
func TestEvidenceUnsigned(t *testing.T) {
	e := setup(t)
	args := e.args("-unsigned")
	for i, a := range args {
		if a == "-key" {
			args = append(args[:i:i], args[i+2:]...)
			break
		}
	}
	var stderr bytes.Buffer
	if err := run(context.Background(), args, e.replay, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	for _, name := range []string{"change-evidence.json", "change-evidence.csv"} {
		p := filepath.Join(e.dir, "out", name)
		if _, err := os.Stat(p); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(p + ".sig"); !os.IsNotExist(err) {
			t.Errorf("%s.sig written", name)
		}
	}
	if !strings.Contains(stderr.String(), "releasegen sign -any -kms") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
}

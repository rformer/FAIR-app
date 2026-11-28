package releaseverify_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

// TestVerifyMatchesVerifyRelease (T-11, design §3.5): releaseverify gives
// the verdicts scripts/verify-release.sh -offline gives, with the same
// messages, on scripts/release-fixture.sh's release (made with cosign) and
// its tampered variants, and on synthetic releases written by releasetest.
//
// It needs bash, cosign and sha256sum (and docker, openssl and curl for the
// fixture release); without them it skips, unless
// FAIR_TEST_RELEASE_FIXTURE=1 (CI job release-verify), where it fails.
// RELEASEGEN names a releasegen binary; otherwise the test builds one.
//
// The script trusts the directory's cosign.pub; the comparison pins that
// same key, so both verify against the same key in every case. The
// script checks no provenance policy, so the comparison runs without one;
// with the release policy, the fixture (built by no release workflow) is
// refused for its provenance, which the test also checks.
func TestVerifyMatchesVerifyRelease(t *testing.T) {
	required := os.Getenv("FAIR_TEST_RELEASE_FIXTURE") == "1"
	need := func(t *testing.T, tools ...string) {
		t.Helper()
		var missing []string
		for _, tool := range tools {
			if _, err := exec.LookPath(tool); err != nil {
				missing = append(missing, tool)
			}
		}
		if len(missing) == 0 {
			return
		}
		if required {
			t.Fatalf("FAIR_TEST_RELEASE_FIXTURE=1 but %s not found", strings.Join(missing, ", "))
		}
		t.Skipf("needs %s on PATH (set FAIR_TEST_RELEASE_FIXTURE=1 to require them)", strings.Join(missing, ", "))
	}
	need(t, "bash", "cosign", "sha256sum")
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	releasegen := os.Getenv("RELEASEGEN")
	if releasegen == "" {
		releasegen = filepath.Join(t.TempDir(), "releasegen")
		build := exec.CommandContext(ctx, "go", "build", "-o", releasegen, "./cmd/releasegen")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build releasegen: %v\n%s", err, out)
		}
	}
	env := append(os.Environ(), "RELEASEGEN="+releasegen)

	// compare runs both verifiers over dir. pinned is used when dir has no
	// readable cosign.pub.
	compare := func(t *testing.T, dir string, pinned *ecdsa.PublicKey, wantOK bool) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "verify-release.sh"), "-offline", dir)
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		scriptOK := err == nil
		var scriptOut []string
		for _, l := range strings.Split(stdout.String(), "\n") {
			if strings.HasPrefix(l, "ok - ") || l == releaseverify.Final {
				scriptOut = append(scriptOut, l)
			}
		}
		scriptFail := ""
		for _, l := range strings.Split(stderr.String(), "\n") {
			if m, ok := strings.CutPrefix(l, "FAIL - "); ok {
				scriptFail = m
			}
		}

		key := pinned
		if k, err := releaseverify.LoadPublicKey(filepath.Join(dir, "cosign.pub")); err == nil {
			key = k
		}
		rep := releaseverify.Verify(dir, releaseverify.Options{Key: key})
		var goOut []string
		for _, s := range rep.Steps {
			goOut = append(goOut, "ok - "+s.Message)
		}
		goFail := ""
		if rep.Refusal != nil {
			goFail = rep.Refusal.Message
		} else {
			goOut = append(goOut, releaseverify.Final)
		}

		if scriptOK != rep.Verified {
			t.Fatalf("verdicts differ: script %v (%q), releaseverify %v (%+v)\nscript stdout:\n%s\nstderr:\n%s", scriptOK, scriptFail, rep.Verified, rep.Refusal, stdout.String(), stderr.String())
		}
		if scriptOK != wantOK {
			t.Fatalf("both verifiers say %v, the case expects %v (%q)", scriptOK, wantOK, scriptFail)
		}
		if !slices.Equal(scriptOut, goOut) || scriptFail != goFail {
			t.Fatalf("messages differ:\nscript:        %q FAIL %q\nreleaseverify: %q FAIL %q (%s)", scriptOut, scriptFail, goOut, goFail, detail(rep))
		}
		t.Logf("both %s", verdict(rep))
	}
	clone := func(t *testing.T, src string) string {
		t.Helper()
		dst := filepath.Join(t.TempDir(), "t")
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
		return dst
	}

	t.Run("synthetic", func(t *testing.T) {
		key, other := rt.NewKey(t), rt.NewKey(t)
		build := func(t *testing.T, r rt.Release) string {
			t.Helper()
			r.Key = key
			dir := filepath.Join(t.TempDir(), "r")
			rt.Build(t, dir, r)
			return dir
		}
		img := func(i rt.Image) []rt.Image { return []rt.Image{{Component: "gateway"}, i} }
		another := "sha256:" + strings.Repeat("4", 64)
		cases := []struct {
			name string
			dir  func(t *testing.T) string
			ok   bool
		}{
			{"as signed", func(t *testing.T) string { return build(t, rt.Release{Images: img(rt.Image{Component: "iam"})}) }, true},
			{"a listed file changed", func(t *testing.T) string {
				dir := build(t, rt.Release{Files: map[string][]byte{"notes.md": []byte("notes\n")}})
				if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("other\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return dir
			}, false},
			{"no SHA256SUMS signature", func(t *testing.T) string {
				dir := build(t, rt.Release{})
				if err := os.Remove(filepath.Join(dir, "SHA256SUMS.sig")); err != nil {
					t.Fatal(err)
				}
				return dir
			}, false},
			{"no SHA256SUMS", func(t *testing.T) string {
				dir := build(t, rt.Release{})
				for _, f := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
					if err := os.Remove(filepath.Join(dir, f)); err != nil {
						t.Fatal(err)
					}
				}
				return dir
			}, true},
			{"an image signed by another key", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.WithKey(rt.Image{Component: "iam"}, other))})
			}, false},
			{"a signature for another digest", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam", SigKey: key, SBOMKey: key, ProvKey: key, SigDigest: another})})
			}, false},
			{"another signed image in place of the release's", func(t *testing.T) string {
				dir := build(t, rt.Release{Images: img(rt.Image{Component: "iam"})})
				l := filepath.Join(dir, "images", "iam")
				if err := os.RemoveAll(l); err != nil {
					t.Fatal(err)
				}
				rt.AddImage(t, l, rt.WithKey(rt.Image{Component: "iam", Seed: "older"}, key))
				return dir
			}, false},
			{"no SBOM attestation", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam", SigKey: key, ProvKey: key})})
			}, false},
			{"no provenance attestation", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam", SigKey: key, SBOMKey: key})})
			}, false},
			{"provenance signed by another key", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam", SigKey: key, SBOMKey: key, ProvKey: other})})
			}, false},
			{"attestations for another image", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam", SigKey: key, SBOMKey: key, ProvKey: key, AttDigest: another})})
			}, false},
			{"no layout for an image", func(t *testing.T) string {
				dir := build(t, rt.Release{Images: img(rt.Image{Component: "iam"})})
				if err := os.RemoveAll(filepath.Join(dir, "images", "iam")); err != nil {
					t.Fatal(err)
				}
				return dir
			}, false},
			{"mirrored image", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam"}), Mirrors: []rt.Image{rt.Image{Component: "cloudnative-pg"}}})
			}, true},
			{"mirrored image signed by another key", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam"}), Mirrors: []rt.Image{rt.Image{Component: "cloudnative-pg", SigKey: other}}})
			}, false},
			{"mirrored image signature for another image", func(t *testing.T) string {
				return build(t, rt.Release{Images: img(rt.Image{Component: "iam"}), Mirrors: []rt.Image{rt.Image{Component: "cloudnative-pg", SigKey: key, SigDigest: another}}})
			}, false},
			{"no layout for a mirrored image", func(t *testing.T) string {
				dir := build(t, rt.Release{Images: img(rt.Image{Component: "iam"}), Mirrors: []rt.Image{rt.Image{Component: "cloudnative-pg"}}})
				if err := os.RemoveAll(filepath.Join(dir, "images", "cloudnative-pg")); err != nil {
					t.Fatal(err)
				}
				return dir
			}, false},
			{"no cosign.pub", func(t *testing.T) string {
				dir := build(t, rt.Release{})
				if err := os.Remove(filepath.Join(dir, "cosign.pub")); err != nil {
					t.Fatal(err)
				}
				return dir
			}, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { compare(t, c.dir(t), &key.PublicKey, c.ok) })
		}
	})

	t.Run("fixture", func(t *testing.T) {
		need(t, "docker", "openssl", "curl")
		w := t.TempDir()
		for i, name := range []string{"a", "b"} {
			cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "release-fixture.sh"), filepath.Join(w, name))
			cmd.Dir = root
			cmd.Env = append(env, "FAIR_FIXTURE_REGISTRY_PORT="+[]string{"5057", "5058"}[i])
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("release-fixture.sh: %v\n%s", err, out)
			}
		}
		a, b := filepath.Join(w, "a"), filepath.Join(w, "b")
		keyA, err := releaseverify.LoadPublicKey(filepath.Join(a, "cosign.pub"))
		if err != nil {
			t.Fatal(err)
		}
		cp := func(t *testing.T, src, dst string) {
			t.Helper()
			bs, err := os.ReadFile(src) // #nosec G304 -- a test directory
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, bs, 0o600); err != nil { // #nosec G703 -- a test directory
				t.Fatal(err)
			}
		}
		cases := []struct {
			name   string
			tamper func(t *testing.T, dir string)
			ok     bool
		}{
			// The cases of scripts/verify-release-test.sh.
			{"the release as signed", func(*testing.T, string) {}, true},
			{"another key as cosign.pub", func(t *testing.T, dir string) {
				cp(t, filepath.Join(b, "cosign.pub"), filepath.Join(dir, "cosign.pub"))
			}, false},
			{"an edited release manifest", func(t *testing.T, dir string) {
				p := filepath.Join(dir, "release-manifest.json")
				bs, _ := os.ReadFile(p)                                                                                          // #nosec G304 -- a test directory
				if err := os.WriteFile(p, bytes.Replace(bs, []byte("v0.0.0-fixture"), []byte("v9.9.9"), 1), 0o600); err != nil { // #nosec G703 -- a test directory
					t.Fatal(err)
				}
			}, false},
			{"an image signed by another key", func(t *testing.T, dir string) {
				l := filepath.Join(dir, "images", "fixture")
				if err := os.RemoveAll(l); err != nil {
					t.Fatal(err)
				}
				if err := os.CopyFS(l, os.DirFS(filepath.Join(b, "images", "fixture"))); err != nil {
					t.Fatal(err)
				}
			}, false},
			{"no manifest signature", func(t *testing.T, dir string) { rm(t, filepath.Join(dir, "release-manifest.json.sig")) }, false},
			// Further variants.
			{"no cosign.pub", func(t *testing.T, dir string) { rm(t, filepath.Join(dir, "cosign.pub")) }, false},
			{"no SHA256SUMS signature", func(t *testing.T, dir string) { rm(t, filepath.Join(dir, "SHA256SUMS.sig")) }, false},
			{"SHA256SUMS signed by another key", func(t *testing.T, dir string) {
				cp(t, filepath.Join(b, "SHA256SUMS.sig"), filepath.Join(dir, "SHA256SUMS.sig"))
			}, false},
			{"no image layout", func(t *testing.T, dir string) {
				if err := os.RemoveAll(filepath.Join(dir, "images", "fixture")); err != nil {
					t.Fatal(err)
				}
			}, false},
			{"signatures left out of the layout", func(t *testing.T, dir string) { dropIndexKind(t, dir, "dev.cosignproject.cosign/sigs") }, false},
			{"attestations left out of the layout", func(t *testing.T, dir string) { dropIndexKind(t, dir, "dev.cosignproject.cosign/atts") }, false},
			{"provenance left out of the attestations", func(t *testing.T, dir string) { dropAttestation(t, dir, releaseverify.PredicateSLSA) }, false},
			{"SBOM left out of the attestations", func(t *testing.T, dir string) { dropAttestation(t, dir, releaseverify.PredicateSPDX) }, false},
			{"attestations signed by another key", func(t *testing.T, dir string) {
				swapKind(t, dir, filepath.Join(b, "images", "fixture"), "dev.cosignproject.cosign/atts")
			}, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				dir := clone(t, a)
				c.tamper(t, dir)
				compare(t, dir, keyA, c.ok)
			})
		}
		t.Run("the release policy refuses the fixture's provenance", func(t *testing.T) {
			rep := releaseverify.Verify(a, releaseverify.Options{Key: keyA, Provenance: releaseverify.ReleasePolicy()})
			if rep.Refusal == nil || rep.Refusal.Check != releaseverify.CheckProvenancePol {
				t.Fatalf("got %s", verdict(rep))
			}
		})
	})
}

func verdict(r *releaseverify.Report) string {
	if r.Verified {
		return "verified"
	}
	return "refused: " + r.Refusal.Message + detail(r)
}

func detail(r *releaseverify.Report) string {
	if r.Refusal == nil || r.Refusal.Detail == "" {
		return ""
	}
	return " (" + r.Refusal.Detail + ")"
}

func rm(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

type ociIndex struct {
	SchemaVersion int              `json:"schemaVersion"`
	MediaType     string           `json:"mediaType"`
	Manifests     []map[string]any `json:"manifests"`
}

func readIndex(t *testing.T, layout string) ociIndex {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(layout, "index.json")) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	var idx ociIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

func writeJSON(t *testing.T, p string, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func kindOf(m map[string]any) string {
	a, _ := m["annotations"].(map[string]any)
	k, _ := a["kind"].(string)
	return k
}

// dropIndexKind removes the cosign save entry of a kind from the fixture's
// layout.
func dropIndexKind(t *testing.T, dir, kind string) {
	t.Helper()
	l := filepath.Join(dir, "images", "fixture")
	idx := readIndex(t, l)
	idx.Manifests = slices.DeleteFunc(idx.Manifests, func(m map[string]any) bool { return kindOf(m) == kind })
	writeJSON(t, filepath.Join(l, "index.json"), idx)
}

// swapKind puts the other layout's entry of a kind (and its blobs) in place
// of the fixture's.
func swapKind(t *testing.T, dir, from, kind string) {
	t.Helper()
	l := filepath.Join(dir, "images", "fixture")
	src := readIndex(t, from)
	blobs, err := os.ReadDir(filepath.Join(from, "blobs", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range blobs {
		dst := filepath.Join(l, "blobs", "sha256", e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, "blobs", "sha256", e.Name())) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil { // #nosec G703 -- a test directory
			t.Fatal(err)
		}
	}
	idx := readIndex(t, l)
	for i, m := range idx.Manifests {
		if kindOf(m) != kind {
			continue
		}
		for _, n := range src.Manifests {
			if kindOf(n) == kind {
				idx.Manifests[i] = n
			}
		}
	}
	writeJSON(t, filepath.Join(l, "index.json"), idx)
}

// dropAttestation rewrites the fixture's attestation manifest without the
// layer of one predicate type (no signature changes: the remaining
// envelopes still verify).
func dropAttestation(t *testing.T, dir, predicateType string) {
	t.Helper()
	l := filepath.Join(dir, "images", "fixture")
	idx := readIndex(t, l)
	for i, m := range idx.Manifests {
		if kindOf(m) != "dev.cosignproject.cosign/atts" {
			continue
		}
		d := strings.TrimPrefix(m["digest"].(string), "sha256:")
		b, err := os.ReadFile(filepath.Join(l, "blobs", "sha256", d)) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		var man map[string]any
		if err := json.Unmarshal(b, &man); err != nil {
			t.Fatal(err)
		}
		layers := man["layers"].([]any)
		man["layers"] = slices.DeleteFunc(layers, func(x any) bool {
			a, _ := x.(map[string]any)["annotations"].(map[string]any)
			return a["predicateType"] == predicateType
		})
		nb, err := json.Marshal(man)
		if err != nil {
			t.Fatal(err)
		}
		h := sum(string(nb))
		if err := os.WriteFile(filepath.Join(l, "blobs", "sha256", h), nb, 0o600); err != nil {
			t.Fatal(err)
		}
		idx.Manifests[i]["digest"] = "sha256:" + h
		idx.Manifests[i]["size"] = len(nb)
	}
	writeJSON(t, filepath.Join(l, "index.json"), idx)
}

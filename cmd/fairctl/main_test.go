package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

type result struct {
	code           int
	stdout, stderr string
}

func fairctl(t *testing.T, vars map[string]string, args ...string) result {
	t.Helper()
	var out, errs bytes.Buffer
	code := run(args, &env{stdout: &out, stderr: &errs, getenv: func(k string) string { return vars[k] }})
	return result{code, out.String(), errs.String()}
}

// A package as T-10 will write it, signed with a test release key.
func testPackage(t *testing.T) (dir, keyFile string) {
	t.Helper()
	k := rt.NewKey(t)
	base := t.TempDir()
	dir = filepath.Join(base, "fair-v1.2.3-airgap")
	rt.Build(t, dir, rt.Release{
		Key: k, Package: true,
		Images: []rt.Image{{Component: "gateway"}, {Component: "iam"}},
		Extra:  []rt.Image{{Component: "postgres"}},
		Files:  map[string][]byte{"tools/fairctl-linux-amd64": []byte("fairctl")},
	})
	keyFile = filepath.Join(base, "release.pub") // pinned: kept apart from the package
	if err := os.WriteFile(keyFile, rt.PublicPEM(t, k), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, keyFile
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "formats", "fairctl-verify.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("fairctl-verify.schema.json", sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("fairctl-verify.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func noEscapes(t *testing.T, r result) {
	t.Helper()
	if strings.ContainsAny(r.stdout+r.stderr, "\x1b\r\b") {
		t.Fatalf("control characters in the output:\n%q\n%q", r.stdout, r.stderr)
	}
}

// T-11 (AC-07, AC-54): fairctl verify prints plain lines, exits 0 on a
// verified package and 1 on a refused one, and prints one JSON document
// with -output json.
func TestVerifyCommand(t *testing.T) {
	dir, key := testPackage(t)
	s := schema(t)

	r := fairctl(t, nil, "verify", "-key", key, dir)
	if r.code != exitOK {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	noEscapes(t, r)
	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	if len(lines) != 7 || lines[len(lines)-1] != releaseverify.Final || r.stderr != "" {
		t.Fatalf("output:\n%s\nstderr: %s", r.stdout, r.stderr)
	}
	for _, l := range lines[:len(lines)-1] {
		if !strings.HasPrefix(l, "ok - ") {
			t.Fatalf("line %q", l)
		}
	}

	if r := fairctl(t, map[string]string{"NO_COLOR": "1"}, "verify", "-color", "-key", key, dir); r.code != exitOK {
		t.Fatalf("exit %d", r.code)
	} else {
		noEscapes(t, r)
	}
	if r := fairctl(t, nil, "verify", "-color", "-key", key, dir); !strings.Contains(r.stdout, "\x1b[32mok\x1b[0m") {
		t.Fatalf("-color: %q", r.stdout)
	}

	j := fairctl(t, nil, "verify", "-output", "json", "-key", key, dir)
	if j.code != exitOK {
		t.Fatalf("json exit %d: %s", j.code, j.stderr)
	}
	noEscapes(t, j)
	validate(t, s, j.stdout)
	var doc struct {
		Command  string `json:"command"`
		Release  string `json:"release"`
		Verified bool   `json:"verified"`
		Images   []any  `json:"images"`
	}
	if err := json.Unmarshal([]byte(j.stdout), &doc); err != nil || doc.Command != "verify" || !doc.Verified || doc.Release != "v1.2.3" || len(doc.Images) != 3 {
		t.Fatalf("json %+v (%v):\n%s", doc, err, j.stdout)
	}

	// Refused: a tool in the package substituted.
	if err := os.WriteFile(filepath.Join(dir, "tools", "fairctl-linux-amd64"), []byte("substituted"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = fairctl(t, nil, "verify", "-key", key, dir)
	if r.code != exitRefused || !strings.Contains(r.stderr, "FAIL - SHA256SUMS: a file does not match") || strings.Contains(r.stdout, releaseverify.Final) {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	noEscapes(t, r)
	j = fairctl(t, nil, "verify", "-output", "json", "-key", key, dir)
	if j.code != exitRefused {
		t.Fatalf("json exit %d", j.code)
	}
	validate(t, s, j.stdout)
	var ref struct {
		Verified bool               `json:"verified"`
		Refusal  releaseverify.Step `json:"refusal"`
	}
	if err := json.Unmarshal([]byte(j.stdout), &ref); err != nil || ref.Verified || ref.Refusal.Check != releaseverify.CheckChecksums || ref.Refusal.Subject != "tools/fairctl-linux-amd64" {
		t.Fatalf("json %+v (%v)", ref, err)
	}
}

// The package's own cosign.pub is not trusted: only the pinned key is.
func TestVerifyPinnedKey(t *testing.T) {
	dir, _ := testPackage(t)
	_, otherKey := testPackage(t)
	r := fairctl(t, nil, "verify", "-key", otherKey, dir)
	if r.code != exitRefused || !strings.Contains(r.stderr, "FAIL - cosign.pub: not the pinned release key") {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// A release directory that is not an air-gap package, or whose provenance
// does not come from the release workflow, is refused.
func TestVerifyRequiresPackageAndProvenance(t *testing.T) {
	k := rt.NewKey(t)
	base := t.TempDir()
	key := filepath.Join(base, "release.pub")
	if err := os.WriteFile(key, rt.PublicPEM(t, k), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(base, "release")
	rt.Build(t, plain, rt.Release{Key: k})
	if r := fairctl(t, nil, "verify", "-key", key, plain); r.code != exitRefused || !strings.Contains(r.stderr, "FAIL - no package-manifest.json in") {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	pred := rt.DefaultProvenance("v1.2.3")
	pred["builder"] = map[string]any{"id": "https://example.invalid/fixture"}
	fixture := filepath.Join(base, "fixture")
	rt.Build(t, fixture, rt.Release{Key: k, Package: true, Images: []rt.Image{{Component: "fixture", Provenance: pred}}})
	if r := fairctl(t, nil, "verify", "-key", key, fixture); r.code != exitRefused || !strings.Contains(r.stderr, "names the release builder and source") {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestUsage(t *testing.T) {
	dir, key := testPackage(t)
	notKey := filepath.Join(t.TempDir(), "not-a-key")
	if err := os.WriteFile(notKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no command":      {},
		"unknown command": {"install-everything"},
		"no key":          {"verify", dir},
		"no package":      {"verify", "-key", key},
		"two packages":    {"verify", "-key", key, dir, dir},
		"bad output":      {"verify", "-output", "yaml", "-key", key, dir},
		"unknown flag":    {"verify", "-insecure", "-key", key, dir},
		"unreadable key":  {"verify", "-key", filepath.Join(t.TempDir(), "missing.pub"), dir},
		"not a key":       {"verify", "-key", notKey, dir},
		"not a directory": {"verify", "-key", key, key},
		"version args":    {"version", "x"},
	} {
		if r := fairctl(t, nil, args...); r.code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, r.code, exitUsage)
		} else {
			noEscapes(t, r)
		}
	}
	if r := fairctl(t, nil, "help"); r.code != exitOK || !strings.Contains(r.stdout, "fairctl verify -key FILE") {
		t.Errorf("help: %d %q", r.code, r.stdout)
	}
	if r := fairctl(t, nil, "version"); r.code != exitOK || !strings.HasPrefix(r.stdout, "fairctl dev") {
		t.Errorf("version: %d %q", r.code, r.stdout)
	}
}

func validate(t *testing.T, s *jsonschema.Schema, doc string) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, doc)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("does not match fairctl-verify.schema.json: %v\n%s", err, doc)
	}
}

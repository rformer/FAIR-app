package oscal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	oscalpin "github.com/rformer/fair-app/third_party/oscal"
)

const pinDir = "../../third_party/oscal"

type manifest struct {
	OSCALVersion string `json:"oscal_version"`
	Files        []struct {
		Path   string `json:"path"`
		Source string `json:"source"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

func readManifest(t *testing.T) manifest {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(oscalpin.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Every pinned file is byte-for-byte what MANIFEST.json says, and the
// embedded schema is the pinned file.
func TestPinnedFilesMatchManifest(t *testing.T) {
	m := readManifest(t)
	if m.OSCALVersion != Version {
		t.Fatalf("manifest pins OSCAL %s, package says %s", m.OSCALVersion, Version)
	}
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(pinDir, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			t.Errorf("%s: sha256 %s, manifest says %s", f.Path, got, f.SHA256)
		}
		if strings.HasPrefix(f.Path, "schemas/oscal_complete_schema") && !bytes.Equal(b, oscalpin.CompleteSchema) {
			t.Errorf("embedded schema differs from %s", f.Path)
		}
	}
}

// canonical decodes JSON into generic values so documents compare by
// content, not key order or whitespace. Date-times compare as instants: Go
// writes "2026-10-22T11:30:00.00000-00:00" back as "2026-10-22T11:30:00Z".
func canonical(t *testing.T, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var norm func(any) any
	norm = func(n any) any {
		switch x := n.(type) {
		case map[string]any:
			for k, e := range x {
				x[k] = norm(e)
			}
		case []any:
			for i, e := range x {
				x[i] = norm(e)
			}
		case string:
			if ts, err := time.Parse(time.RFC3339Nano, x); err == nil && strings.Contains(x, "T") {
				return "instant:" + ts.UTC().Format(time.RFC3339Nano)
			}
		}
		return n
	}
	return norm(v)
}

// Verification for T-01: NIST's published documents for every supported
// model validate, decode and re-encode without losing anything.
func TestRoundTripNISTContent(t *testing.T) {
	want := map[string]Kind{
		"nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json":                                    Catalog,
		"nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json":                  Profile,
		"nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json": Catalog,
		"examples/catalog/basic-catalog.json":                                                 Catalog,
		"examples/profile/basic-profile.json":                                                 Profile,
		"examples/component-definition/example-component-definition.json":                     ComponentDefinition,
		"examples/assessment-results/ifa_assessment-results-example.json":                     AssessmentResults,
		"examples/poam/ifa_plan-of-action-and-milestones.json":                                POAM,
	}
	seen := 0
	for _, f := range readManifest(t).Files {
		kind, ok := want[f.Path]
		if !ok {
			continue
		}
		seen++
		t.Run(filepath.Base(f.Path), func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(pinDir, f.Path))
			if err != nil {
				t.Fatal(err)
			}
			doc, got, err := Parse(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != kind {
				t.Fatalf("kind = %s, want %s", got, kind)
			}
			out, err := Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !reflect.DeepEqual(canonical(t, in), canonical(t, out)) {
				t.Fatal("round trip changed the document")
			}
		})
	}
	if seen != len(want) {
		t.Fatalf("round-tripped %d files, want %d (manifest and test disagree)", seen, len(want))
	}
}

func TestValidateRejects(t *testing.T) {
	base, err := os.ReadFile(filepath.Join(pinDir, "examples/catalog/basic-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(cat map[string]any)) []byte {
		var doc map[string]any
		_ = json.Unmarshal(base, &doc)
		f(doc["catalog"].(map[string]any))
		b, _ := json.Marshal(doc)
		return b
	}
	meta := func(cat map[string]any) map[string]any { return cat["metadata"].(map[string]any) }
	cases := map[string][]byte{
		"not json":            []byte("{"),
		"empty object":        []byte("{}"),
		"two roots":           []byte(`{"catalog": {}, "profile": {}}`),
		"unsupported model":   []byte(`{"system-security-plan": {}}`),
		"missing uuid":        mutate(func(c map[string]any) { delete(c, "uuid") }),
		"bad uuid":            mutate(func(c map[string]any) { c["uuid"] = "not-a-uuid" }),
		"missing metadata":    mutate(func(c map[string]any) { delete(c, "metadata") }),
		"bad last-modified":   mutate(func(c map[string]any) { meta(c)["last-modified"] = "yesterday" }),
		"unknown field":       mutate(func(c map[string]any) { c["extra"] = true }),
		"empty title":         mutate(func(c map[string]any) { meta(c)["title"] = "" }),
		"wrong oscal-version": mutate(func(c map[string]any) { meta(c)["oscal-version"] = 12 }),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(doc); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
	if _, kind, err := Parse(base); err != nil || kind != Catalog {
		t.Fatalf("unmodified catalog: %v %v", kind, err)
	}
}

// Marshal refuses to emit a document that does not validate (AC-47).
func TestMarshalRefusesInvalid(t *testing.T) {
	doc, _, err := Parse(mustRead(t, "examples/catalog/basic-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Catalog.UUID = "not-a-uuid"
	if _, err := Marshal(doc); err == nil {
		t.Fatal("marshalled an invalid document")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pinDir, p)) // #nosec G304 -- pinned files named by the test
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// inlineDatatypes replaces every "$ref" to a "...Datatype" definition with
// that datatype's constraints, so schemas that differ only in whether they
// inline datatype references compare equal.
func inlineDatatypes(schema map[string]any) any {
	defs := schema["definitions"].(map[string]any)
	var walk func(any) any
	walk = func(n any) any {
		switch v := n.(type) {
		case map[string]any:
			out := make(map[string]any, len(v))
			for k, x := range v {
				out[k] = walk(x)
			}
			if ref, ok := out["$ref"].(string); ok && strings.HasPrefix(ref, "#/definitions/") && strings.HasSuffix(ref, "Datatype") {
				dt := walk(defs[strings.TrimPrefix(ref, "#/definitions/")]).(map[string]any)
				merged := map[string]any{}
				for k, x := range dt {
					if k != "description" && k != "title" && k != "$comment" {
						merged[k] = x
					}
				}
				for k, x := range out {
					if k != "$ref" {
						merged[k] = x
					}
				}
				return merged
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, x := range v {
				out[i] = walk(x)
			}
			return out
		}
		return n
	}
	return walk(schema)
}

// The types come from go-oscal, generated from its own copy of the schema.
// That copy must be equivalent to the pinned one, or types and validation
// could disagree. Re-checked on every go-oscal upgrade.
func TestPinnedSchemaMatchesTypesSource(t *testing.T) {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-m", "-json", "github.com/defenseunicorns/go-oscal").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	var mod struct{ Dir string }
	if err := json.Unmarshal(out, &mod); err != nil || mod.Dir == "" {
		t.Skipf("go-oscal module not in the module cache: %v", err)
	}
	theirs, err := os.ReadFile(filepath.Join(mod.Dir, "src", "internal", "schemas", "oscal_complete_schema-"+strings.ReplaceAll(Version, ".", "-")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	if err := json.Unmarshal(oscalpin.CompleteSchema, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(theirs, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inlineDatatypes(a), inlineDatatypes(b)) {
		t.Fatal("go-oscal's schema is not equivalent to the pinned OSCAL schema")
	}
}

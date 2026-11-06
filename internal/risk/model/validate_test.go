package model_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// Every corpus case gets the verdict it states, invalid ones with a problem
// at the stated pointer; valid documents come back canonical and are fixed
// points.
func TestCorpus(t *testing.T) {
	cases := modeltest.Corpus()
	if len(cases) < 80 {
		t.Fatalf("corpus has %d cases", len(cases))
	}
	for _, c := range cases {
		doc, problems := model.Validate(c.Kind, c.Doc)
		if c.Valid {
			if len(problems) > 0 {
				t.Errorf("%s: %v", c.Name, problems)
				continue
			}
			again, p := model.Validate(c.Kind, doc.Canonical)
			if len(p) > 0 || !bytes.Equal(again.Canonical, doc.Canonical) || again.Digest != doc.Digest {
				t.Errorf("%s: canonical form is not a fixed point: %s / %v", c.Name, doc.Canonical, p)
			}
			if b, _ := canon.Canonicalize(doc.Canonical); !bytes.Equal(b, doc.Canonical) {
				t.Errorf("%s: not canonical: %s", c.Name, doc.Canonical)
			}
			continue
		}
		if doc != nil {
			t.Errorf("%s: accepted: %s", c.Name, doc.Canonical)
			continue
		}
		if !slices.ContainsFunc(problems, func(p model.Problem) bool { return p.Pointer == c.Pointer }) {
			t.Errorf("%s: no problem at %q: %v", c.Name, c.Pointer, problems)
		}
	}
}

// Every rule problem is reported, not just the first.
func TestAllProblemsReported(t *testing.T) {
	d := modeltest.Scenario()
	modeltest.Set(d, "/name", "")
	modeltest.Set(d, "/lef/tef/contact_frequency/min", "50")
	modeltest.Set(d, "/primary_loss/response/rationale", "")
	modeltest.Set(d, "/control_sets/1/current", true)
	raw, _ := json.Marshal(d)
	_, problems := model.Validate("scenario", raw)
	for _, want := range []string{"/name", "/lef/tef/contact_frequency", "/primary_loss/response/rationale", "/control_sets"} {
		if !slices.ContainsFunc(problems, func(p model.Problem) bool { return p.Pointer == want }) {
			t.Errorf("no problem at %s: %v", want, problems)
		}
	}
}

func TestCanonicalForm(t *testing.T) {
	d := modeltest.Scenario()
	// JSON numbers and unordered threat effects canonicalise.
	modeltest.Set(d, "/lef/tef/contact_frequency/min", 2.0)
	modeltest.Set(d, "/lef/tef/contact_frequency/ml", json.Number("6.000"))
	modeltest.Set(d, "/lef/tef/contact_frequency/max", "1.2e1")
	modeltest.Set(d, "/threat_effects", []any{"confidentiality", "availability"})
	modeltest.Set(d, "/owner", strings.ToUpper(d["owner"].(string)))
	raw, _ := json.MarshalIndent(d, "", "  ")
	doc, problems := model.Validate("scenario", raw)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	base, _ := json.Marshal(modeltest.Scenario())
	want, _ := model.Validate("scenario", base)
	if doc.Digest != want.Digest {
		t.Fatalf("equivalent documents differ:\n%s\n%s", doc.Canonical, want.Canonical)
	}
	if !bytes.Contains(doc.Canonical, []byte(`"max":"12","min":"2","ml":"6"`)) {
		t.Errorf("decimals not canonical: %s", doc.Canonical)
	}
	// Any change of value changes the digest.
	modeltest.Set(d, "/lef/tef/contact_frequency/max", "13")
	raw, _ = json.Marshal(d)
	changed, _ := model.Validate("scenario", raw)
	if changed.Digest == doc.Digest {
		t.Fatal("digest unchanged")
	}
	// Pins are reported with their places.
	var got []string
	for _, p := range doc.Pins {
		got = append(got, p.Kind+"@"+p.Pointer)
	}
	want2 := []string{"asset@/asset", "threat_community@/threat_community", "control@/control_sets/0/controls/0",
		"control@/control_sets/1/controls/0", "control@/control_sets/1/controls/1"}
	if !slices.Equal(got, want2) {
		t.Errorf("pins %v", got)
	}
}

func TestLimits(t *testing.T) {
	d := modeltest.Asset()
	d["description"] = strings.Repeat("x", model.MaxDocumentBytes)
	raw, _ := json.Marshal(d)
	if _, p := model.Validate("asset", raw); len(p) != 1 || p[0].Pointer != "" {
		t.Fatalf("oversized document: %v", p)
	}
	d["description"] = strings.Repeat("é", model.MaxText) // characters, not bytes
	raw, _ = json.Marshal(d)
	if _, p := model.Validate("asset", raw); len(p) > 0 {
		t.Fatalf("10,000 characters refused: %v", p)
	}
}

// The published schemas agree with the validator: they accept every valid
// case and refuse every structural one.
func TestSchemasAgree(t *testing.T) {
	c := jsonschema.NewCompiler()
	err := fs.WalkDir(model.SchemaFiles, "schema", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := model.SchemaFiles.ReadFile(path)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return err
		}
		return c.AddResource(doc.(map[string]any)["$id"].(string), doc)
	})
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]*jsonschema.Schema{}
	for _, k := range model.Kinds {
		if schemas[k], err = c.Compile(model.SchemaRef(k)); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	for _, cs := range modeltest.Corpus() {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(cs.Doc))
		if err != nil {
			if cs.Valid {
				t.Errorf("%s: %v", cs.Name, err)
			}
			continue
		}
		verr := schemas[cs.Kind].Validate(inst)
		switch {
		case cs.Valid && verr != nil:
			t.Errorf("%s: schema refuses a valid document: %v", cs.Name, verr)
		case cs.Structural && verr == nil:
			t.Errorf("%s: schema accepts a structurally invalid document", cs.Name)
		}
	}
}

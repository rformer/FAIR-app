package framework

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "formats", name)) // #nosec G304 -- the repository's own schemas
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The published schemas agree with the parsers on valid and refused files.
func TestSchemas(t *testing.T) {
	for _, c := range []struct {
		schema     string
		parse      func([]byte) error
		ok, refuse []string
	}{
		{"fair-framework-v1.schema.json", func(b []byte) error { _, err := ParseSimple(b); return err },
			[]string{`{"format": "fair.framework.v1", "family": {"key": "iso-27001", "title": "ISO"}, "version": {"label": "2022", "title": "ISO 2022", "published": "2022-10-25"},
				"requirements": [{"identifier": "A.5", "title": "Org"}, {"identifier": "A.5.1", "label": "5.1", "title": "Policies", "statement": "x", "parent": "A.5"}]}`},
			[]string{`{"format": "fair.framework.v1", "family": {"key": "ISO", "title": "ISO"}, "version": {"label": "1", "title": "x"}, "requirements": [{"identifier": "a", "title": "x"}]}`,
				`{"format": "fair.framework.v1", "family": {"key": "iso", "title": "ISO"}, "version": {"label": "1", "title": "x"}, "requirements": [{"identifier": "a", "title": "x", "rating": 3}]}`,
				`{"format": "fair.framework.v1", "family": {"key": "iso", "title": "ISO"}, "version": {"label": "1", "title": "x"}, "requirements": []}`}},
		{"fair-crosswalk-v1.schema.json", func(b []byte) error { _, err := ParseCrosswalk(b); return err },
			[]string{`{"format": "fair.crosswalk.v1", "title": "x", "label": "1", "source": {"family": "a", "version": "1"}, "target": {"family": "b", "version": "1"},
				"relationships": [{"source": "a-1", "target": "b-1", "relationship": "intersects"}]}`},
			[]string{`{"format": "fair.crosswalk.v1", "title": "x", "label": "1", "source": {"family": "a", "version": "1"}, "target": {"family": "b", "version": "1"},
				"relationships": [{"source": "a-1", "target": "b-1", "relationship": "related"}]}`,
				`{"format": "fair.crosswalk.v1", "title": "x", "label": "1", "source": {"family": "a", "version": "1"}, "target": {"family": "b", "version": "1"}, "relationships": []}`}},
	} {
		s := compile(t, c.schema)
		for _, raw := range c.ok {
			inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(raw))
			if err := s.Validate(inst); err != nil {
				t.Errorf("%s refused a valid file: %v", c.schema, err)
			}
			if err := c.parse([]byte(raw)); err != nil {
				t.Errorf("%s: the parser refused a valid file: %v", c.schema, err)
			}
		}
		for _, raw := range c.refuse {
			inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(raw))
			if err := s.Validate(inst); err == nil {
				t.Errorf("%s accepted %s", c.schema, raw)
			}
			if err := c.parse([]byte(raw)); err == nil {
				t.Errorf("%s: the parser accepted %s", c.schema, raw)
			}
		}
	}
}

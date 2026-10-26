// Package oscal reads and writes OSCAL documents (F-015 T-01; AC-04, AC-47).
//
// Types come from github.com/defenseunicorns/go-oscal, generated from NIST's
// complete OSCAL schema, corrected where they disagree with it (types.go);
// this package is the only place that imports them, so the library can be
// swapped. Validation uses the schema pinned in
// third_party/oscal (OSCAL 1.2.3), not the library's copy; a test proves the
// two are equivalent.
//
// Parse validates against the schema and then decodes strictly (unknown
// fields are errors), so a field the types cannot hold fails loudly instead
// of being dropped. Marshal re-validates its output, as exports must
// (AC-47). Only the models F-015 uses are accepted.
package oscal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	oscalpin "github.com/rformer/fair-app/third_party/oscal"
)

// Version is the pinned OSCAL version.
const Version = "1.2.3"

// Kind is an OSCAL model, named by its JSON root key.
type Kind string

// The models F-015 reads or writes.
const (
	Catalog             Kind = "catalog"
	Profile             Kind = "profile"
	ComponentDefinition Kind = "component-definition"
	AssessmentResults   Kind = "assessment-results"
	POAM                Kind = "plan-of-action-and-milestones"
)

var kinds = []Kind{Catalog, Profile, ComponentDefinition, AssessmentResults, POAM}

// ErrInvalid wraps every schema or structure failure.
var ErrInvalid = errors.New("oscal: invalid document")

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiled() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(oscalpin.CompleteSchema))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat() // OSCAL relies on date-time, uri and similar formats
		const url = "oscal_complete_schema.json"
		if err := c.AddResource(url, doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile(url)
	})
	return schema, schemaErr
}

// Validate checks data against the pinned schema and returns the document's
// kind. It rejects documents with zero or several roots, and models outside
// the supported set.
func Validate(data []byte) (Kind, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	root, ok := inst.(map[string]any)
	if !ok || len(root) != 1 {
		return "", fmt.Errorf("%w: want one model at the root", ErrInvalid)
	}
	var kind Kind
	for k := range root {
		kind = Kind(k)
	}
	if !slices.Contains(kinds, kind) {
		return "", fmt.Errorf("%w: model %q is not supported", ErrInvalid, kind)
	}
	s, err := compiled()
	if err != nil {
		return "", fmt.Errorf("oscal: pinned schema: %w", err)
	}
	if err := s.Validate(inst); err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalid, strings.TrimSpace(err.Error()))
	}
	return kind, nil
}

// Parse validates data and decodes it.
func Parse(data []byte) (*Document, Kind, error) {
	kind, err := Validate(data)
	if err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return &doc, kind, nil
}

// Marshal encodes doc and validates the result against the pinned schema.
func Marshal(doc *Document) ([]byte, error) {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := Validate(b); err != nil {
		return nil, fmt.Errorf("oscal: refusing to emit an invalid document: %w", err)
	}
	return b, nil
}

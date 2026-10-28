// Package compliance holds the platform's NIST SP 800-53 Rev 5 control
// implementation statements (F-015 T-38; F-001 T-43 follows) and turns them
// into the OSCAL component definition F-014 publishes.
//
// Each feature's statements live in compliance/statements/<feature>.yaml:
// per control, the statement, the responsibility in each deployment mode
// (ADR-005), what the customer does where it is shared, and the evidence
// (code paths and tests). Check verifies a file against the repository;
// ComponentDefinition builds the OSCAL document, which oscal.Marshal
// validates against the pinned schema.
package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/oscal"
)

// Modes are the deployment modes a responsibility is stated for.
var Modes = []string{"saas", "self-hosted", "air-gapped"}

// Responsibilities.
const (
	Provider = "provider"
	Shared   = "shared"
	Customer = "customer"
)

// CatalogHref is the control catalog the statements implement (the pinned
// NIST content, T-01).
const CatalogHref = "https://raw.githubusercontent.com/usnistgov/oscal-content/v1.6.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

// Statements is one feature's file.
type Statements struct {
	Feature  string    `yaml:"feature"`
	Title    string    `yaml:"title"`
	Status   string    `yaml:"status"` // draft or approved
	Controls []Control `yaml:"controls"`
}

// Control is one implemented requirement.
type Control struct {
	ID             string            `yaml:"id"` // OSCAL control id, e.g. cm-2.2
	Responsibility map[string]string `yaml:"responsibility"`
	Statement      string            `yaml:"statement"`
	Customer       string            `yaml:"customer"`
	Evidence       struct {
		Code  []string `yaml:"code"`
		Tests []string `yaml:"tests"` // "<package dir>:<test name>"
	} `yaml:"evidence"`
}

// Load decodes a statements file strictly (unknown fields are errors).
func Load(b []byte) (*Statements, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var s Statements
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("compliance: %w", err)
	}
	return &s, nil
}

var controlIDRE = regexp.MustCompile(`^[a-z]{2}-[0-9]+(\.[0-9]+)?$`)

// Check verifies s against the repository at root: well-formed controls,
// each once; a responsibility for every mode, and the customer's part
// wherever it is not the provider's alone; and evidence that exists.
func Check(s *Statements, root string) error {
	var errs []error
	if s.Feature == "" || s.Title == "" || (s.Status != "draft" && s.Status != "approved") {
		errs = append(errs, errors.New("feature, title and status (draft or approved) are required"))
	}
	seen := map[string]bool{}
	for _, c := range s.Controls {
		bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(c.ID+": "+format, a...)) }
		if !controlIDRE.MatchString(c.ID) {
			bad("not an OSCAL control id")
		}
		if seen[c.ID] {
			bad("stated twice")
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Statement) == "" {
			bad("no statement")
		}
		providerOnly := true
		for _, m := range Modes {
			switch c.Responsibility[m] {
			case Provider:
			case Shared, Customer:
				providerOnly = false
			default:
				bad("responsibility in %s mode must be provider, shared or customer", m)
			}
		}
		if len(c.Responsibility) != len(Modes) {
			bad("responsibility must name exactly the modes %v", Modes)
		}
		if !providerOnly && strings.TrimSpace(c.Customer) == "" {
			bad("shared or customer responsibility without the customer's part")
		}
		if providerOnly && c.Customer != "" {
			bad("a customer part for a provider-only control")
		}
		if len(c.Evidence.Code) == 0 || len(c.Evidence.Tests) == 0 {
			bad("evidence needs code and tests")
		}
		for _, p := range c.Evidence.Code {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
				bad("evidence %s does not exist", p)
			}
		}
		for _, ref := range c.Evidence.Tests {
			if !testExists(root, ref) {
				bad("evidence test %s does not exist", ref)
			}
		}
	}
	return errors.Join(errs...)
}

func testExists(root, ref string) bool {
	dir, name, ok := strings.Cut(ref, ":")
	if !ok {
		return false
	}
	files, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*_test.go"))
	re := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(name) + `\(t \*testing\.T\)`)
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && re.Match(b) { // #nosec G304 -- the repository's own test files
			return true
		}
	}
	return false
}

// ComponentDefinition builds the OSCAL component definition of the
// platform component (componentUUID) from the features' statements, with
// the given version and last-modified time. Identifiers are UUIDv5 names,
// so the same input gives the same document.
func ComponentDefinition(componentUUID, version string, modified time.Time, features ...*Statements) ([]byte, error) {
	var impls []any
	for _, s := range features {
		var reqs []any
		for _, c := range s.Controls {
			props := []any{}
			for _, m := range Modes {
				props = append(props, map[string]any{"name": "responsibility-" + m, "ns": "urn:fair-app:compliance", "value": c.Responsibility[m]})
			}
			req := map[string]any{
				"uuid":        oscal.UUIDv5("urn:fair-app:compliance:" + s.Feature + ":" + c.ID),
				"control-id":  c.ID,
				"description": strings.TrimSpace(c.Statement),
				"props":       props,
			}
			if c.Customer != "" {
				req["remarks"] = "Customer responsibility: " + strings.TrimSpace(c.Customer)
			}
			reqs = append(reqs, req)
		}
		impls = append(impls, map[string]any{
			"uuid":                     oscal.UUIDv5("urn:fair-app:compliance:" + s.Feature),
			"source":                   CatalogHref,
			"description":              s.Feature + " " + s.Title + " (" + s.Status + ").",
			"props":                    []any{map[string]any{"name": "feature", "ns": "urn:fair-app:compliance", "value": s.Feature}},
			"implemented-requirements": reqs,
		})
	}
	slices.SortFunc(impls, func(a, b any) int {
		return strings.Compare(a.(map[string]any)["uuid"].(string), b.(map[string]any)["uuid"].(string))
	})
	doc := map[string]any{"component-definition": map[string]any{
		"uuid": oscal.UUIDv5("urn:fair-app:compliance:component-definition:" + version),
		"metadata": map[string]any{
			"title":         "FAIR Risk Platform component definition",
			"last-modified": modified.UTC().Format(time.RFC3339),
			"version":       version,
			"oscal-version": oscal.Version,
		},
		"components": []any{map[string]any{
			"uuid":                    componentUUID,
			"type":                    "software",
			"title":                   "FAIR Risk Platform",
			"description":             "The FAIR Risk Platform, a FAIR cyber-risk quantification platform deployed on Kubernetes.",
			"control-implementations": impls,
		}},
	}}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := oscal.Validate(b); err != nil {
		return nil, fmt.Errorf("compliance: the component definition does not validate: %w", err)
	}
	return b, nil
}

package compliance

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/oscal"
)

const root = "../.."

// platformComponent is posture.PlatformComponentUUID (asserted by
// internal/posture TestPlatformComponentUUID; this package does not import
// posture, which depends on the database).
var platformComponent = oscal.UUIDv5("urn:fair-app:posture:component/fair-platform")

func load(t *testing.T, feature string) *Statements {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "compliance", "statements", feature+".yaml")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mapping is a feature's "## Control mapping" line, as OSCAL control ids.
func mapping(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "specs", "features", dir, "requirements.md")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## Control mapping[^\n]*\n([^\n]+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no control mapping")
	}
	var out []string
	for _, c := range regexp.MustCompile(`\b([A-Z]{2})-(\d+)(?:\((\d+)\))?`).FindAllStringSubmatch(string(m[1]), -1) {
		id := strings.ToLower(c[1]) + "-" + c[2]
		if c[3] != "" {
			id += "." + c[3]
		}
		out = append(out, id)
	}
	return out
}

// F-015 T-38: the statements cover exactly F-015's control mapping, every
// claim's evidence exists, and they build a valid OSCAL component
// definition for the platform component.
func TestF015Statements(t *testing.T) {
	s := load(t, "F-015")
	if err := Check(s, root); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range s.Controls {
		ids = append(ids, c.ID)
	}
	want := mapping(t, "F-015-security-posture-profiles")
	slices.Sort(ids)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("stated %v\nmapping %v", ids, want)
	}

	b, err := ComponentDefinition(platformComponent, "0.1.0", time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), s)
	if err != nil {
		t.Fatal(err)
	}
	doc, kind, err := oscal.Parse(b)
	if err != nil || kind != oscal.ComponentDefinition {
		t.Fatalf("%v %v", kind, err)
	}
	comps := *doc.ComponentDefinition.Components
	if len(comps) != 1 || comps[0].UUID != platformComponent {
		t.Fatalf("components %+v", comps)
	}
	impl := (*comps[0].ControlImplementations)[0]
	if len(impl.ImplementedRequirements) != len(want) || impl.Source != CatalogHref {
		t.Fatalf("%d implemented requirements from %s", len(impl.ImplementedRequirements), impl.Source)
	}
	again, _ := ComponentDefinition(platformComponent, "0.1.0", time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), s)
	if !bytes.Equal(b, again) {
		t.Fatal("the component definition is not deterministic")
	}
}

func TestCheckRefuses(t *testing.T) {
	good := func() *Statements {
		s := &Statements{Feature: "F-X", Title: "x", Status: "draft"}
		c := Control{ID: "cm-2", Responsibility: map[string]string{"saas": Provider, "self-hosted": Shared, "air-gapped": Shared},
			Statement: "s", Customer: "c"}
		c.Evidence.Code = []string{"internal/compliance"}
		c.Evidence.Tests = []string{"internal/compliance:TestCheckRefuses"}
		s.Controls = []Control{c}
		return s
	}
	if err := Check(good(), root); err != nil {
		t.Fatalf("a good file refused: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(*Statements)
		want   string
	}{
		"bad id":           {func(s *Statements) { s.Controls[0].ID = "CM-2(2)" }, "not an OSCAL control id"},
		"duplicate":        {func(s *Statements) { s.Controls = append(s.Controls, s.Controls[0]) }, "stated twice"},
		"missing mode":     {func(s *Statements) { delete(s.Controls[0].Responsibility, "air-gapped") }, "air-gapped mode"},
		"unknown value":    {func(s *Statements) { s.Controls[0].Responsibility["saas"] = "vendor" }, "saas mode"},
		"no customer part": {func(s *Statements) { s.Controls[0].Customer = "" }, "without the customer's part"},
		"missing code":     {func(s *Statements) { s.Controls[0].Evidence.Code = []string{"internal/nowhere.go"} }, "does not exist"},
		"missing test":     {func(s *Statements) { s.Controls[0].Evidence.Tests = []string{"internal/compliance:TestNothing"} }, "evidence test"},
		"no statement":     {func(s *Statements) { s.Controls[0].Statement = " " }, "no statement"},
		"bad status":       {func(s *Statements) { s.Status = "final" }, "status"},
	} {
		s := good()
		c.mutate(s)
		if err := Check(s, root); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := Load([]byte("feature: F-X\nunknown: 1\n")); err == nil {
		t.Error("an unknown field was accepted")
	}
}

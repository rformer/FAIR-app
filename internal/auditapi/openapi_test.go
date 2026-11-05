package auditapi

import (
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/pkg/audit"
)

// The published OpenAPI document and the routes served are the same set,
// and every operation documents its permission and the events it records.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi/audit.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Permission  string           `yaml:"x-permission"`
			Parameters  []map[string]any `yaml:"parameters"`
			AuditEvents *[]string        `yaml:"x-audit-events"`
			AuditNote   string           `yaml:"x-audit-note"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for path, ops := range doc.Paths {
		for method, op := range ops {
			m := strings.ToUpper(method)
			documented = append(documented, m+" "+Prefix+path)
			if op.Permission == "" {
				t.Errorf("%s %s: no x-permission", m, path)
			}
			if m != "GET" && !slices.ContainsFunc(op.Parameters, func(p map[string]any) bool {
				return p["$ref"] == "#/components/parameters/IdempotencyKey"
			}) {
				t.Errorf("%s %s: mutation without Idempotency-Key", m, path)
			}
			// Reads of the trail are audited too (F-002 AC-20).
			if err := audit.CheckDeclaredEvents(op.AuditEvents, op.AuditNote); err != nil {
				t.Errorf("%s %s: %v", m, path, err)
			}
		}
	}
	sort.Strings(documented)
	if served := Routes(); !slices.Equal(documented, served) {
		t.Fatalf("OpenAPI\n %v\nroutes\n %v", documented, served)
	}
}

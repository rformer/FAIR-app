package gateway

import (
	"os"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// The published OpenAPI document and the gateway's own routes are the same
// set, and every state-changing operation documents the CSRF header.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi/gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Permission string           `yaml:"x-permission"`
			Parameters []map[string]any `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for path, ops := range doc.Paths {
		for method, op := range ops {
			m := strings.ToUpper(method)
			documented = append(documented, m+" /api/v1"+path)
			if op.Permission == "" {
				t.Errorf("%s %s: no x-permission", m, path)
			}
			if m != "GET" && !slices.ContainsFunc(op.Parameters, func(p map[string]any) bool {
				return p["$ref"] == "#/components/parameters/CSRF"
			}) {
				t.Errorf("%s %s: state change without the CSRF header", m, path)
			}
		}
	}
	served := Routes()
	slices.Sort(documented)
	slices.Sort(served)
	if !slices.Equal(documented, served) {
		t.Fatalf("documented %v\nserved %v", documented, served)
	}
}

package iamapi

import (
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// The published OpenAPI document and the routes served are the same set,
// and every mutation documents its Idempotency-Key and permission.
// Unauthenticated routes (discovery) are served by internal/authn.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi/iam.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for path, ops := range doc.Paths {
		for method, node := range ops {
			if method == "parameters" { // path-level, shared by its operations
				continue
			}
			var op struct {
				Permission      string           `yaml:"x-permission"`
				Unauthenticated bool             `yaml:"x-unauthenticated"`
				Parameters      []map[string]any `yaml:"parameters"`
			}
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			if op.Unauthenticated {
				continue
			}
			m := strings.ToUpper(method)
			documented = append(documented, m+" /api/v1"+path)
			if op.Permission == "" {
				t.Errorf("%s %s: no x-permission", m, path)
			}
			if m != "GET" && !slices.ContainsFunc(op.Parameters, func(p map[string]any) bool {
				return p["$ref"] == "#/components/parameters/IdempotencyKey"
			}) {
				t.Errorf("%s %s: mutation without Idempotency-Key", m, path)
			}
		}
	}
	sort.Strings(documented)
	if served := Routes(); !slices.Equal(documented, served) {
		t.Fatalf("OpenAPI\n %v\nroutes\n %v", documented, served)
	}
}

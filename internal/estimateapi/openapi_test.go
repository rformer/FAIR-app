package estimateapi

import (
	"os"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/pkg/audit"
)

// The published OpenAPI document and the routes served are the same set,
// every operation names its handler and its permission, and every mutation
// either takes an Idempotency-Key and declares its events, or is declared
// exempt (and served without the key).
func TestOpenAPIMatchesRoutes(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi/estimate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string           `yaml:"operationId"`
			Permission  string           `yaml:"x-permission"`
			Parameters  []map[string]any `yaml:"parameters"`
			AuditEvents *[]string        `yaml:"x-audit-events"`
			AuditNote   string           `yaml:"x-audit-note"`
			Exempt      string           `yaml:"x-idempotency-exempt"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	served := map[string]route{}
	for _, r := range routes {
		served[r.method+" "+r.path] = r
	}
	var documented []string
	for path, ops := range doc.Paths {
		for method, op := range ops {
			m := strings.ToUpper(method)
			key := m + " " + path
			documented = append(documented, key)
			r := served[key]
			if op.Permission == "" {
				t.Errorf("%s: no x-permission", key)
			}
			if r.h != nil && op.OperationID != funcName(r) {
				t.Errorf("%s: operationId %q, handler %q", key, op.OperationID, funcName(r))
			}
			if m == "GET" {
				continue
			}
			if (op.Exempt != "") != r.exempt {
				t.Errorf("%s: x-idempotency-exempt %q, served exempt %v", key, op.Exempt, r.exempt)
			}
			if r.exempt {
				continue
			}
			if !slices.ContainsFunc(op.Parameters, func(p map[string]any) bool { return p["$ref"] == "#/components/parameters/IdempotencyKey" }) {
				t.Errorf("%s: mutation without Idempotency-Key", key)
			}
			if err := audit.CheckDeclaredEvents(op.AuditEvents, op.AuditNote); err != nil {
				t.Errorf("%s: %v", key, err)
			}
		}
	}
	sort.Strings(documented)
	if s := Routes(); !slices.Equal(documented, s) {
		t.Fatalf("OpenAPI\n %v\nroutes\n %v", documented, s)
	}
}

// funcName is the handler's method name, which operationId must be.
func funcName(r route) string {
	name := runtime.FuncForPC(reflect.ValueOf(r.h).Pointer()).Name()
	return strings.TrimSuffix(name[strings.LastIndex(name, ".")+1:], "-fm")
}

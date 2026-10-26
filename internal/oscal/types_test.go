package oscal

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	oscalpin "github.com/rformer/fair-app/third_party/oscal"
)

// TestTypesMatchSchema walks Document's Go types and the pinned schema
// together from each supported model's root. Every schema property must have
// a Go field and every Go field a schema property; otherwise documents lose
// data on decode (or could emit fields the schema forbids). This is how the
// go-oscal local-definitions collision was found; it guards upgrades.
func TestTypesMatchSchema(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(oscalpin.CompleteSchema, &s); err != nil {
		t.Fatal(err)
	}
	defs := s["definitions"].(map[string]any)
	resolve := func(n map[string]any) map[string]any {
		for {
			ref, ok := n["$ref"].(string)
			if !ok {
				return n
			}
			n = defs[strings.TrimPrefix(ref, "#/definitions/")].(map[string]any)
		}
	}
	seen := map[string]bool{}
	var problems []string
	var walk func(rt reflect.Type, n map[string]any, path string)
	walk = func(rt reflect.Type, n map[string]any, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		n = resolve(n)
		if items, ok := n["items"].(map[string]any); ok {
			n = resolve(items)
		}
		props, ok := n["properties"].(map[string]any)
		if !ok || rt.Kind() != reflect.Struct {
			return
		}
		names := make([]string, 0, len(props))
		for p := range props {
			names = append(names, p)
		}
		slices.Sort(names)
		// The same Go type may be checked against several schema shapes.
		key := rt.String() + "|" + strings.Join(names, ",")
		if seen[key] {
			return
		}
		seen[key] = true
		fields := map[string]reflect.StructField{}
		for i := range rt.NumField() {
			f := rt.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			fields[name] = f
		}
		for _, p := range names {
			f, ok := fields[p]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: schema property %q missing from %s", path, p, rt))
				continue
			}
			walk(f.Type, props[p].(map[string]any), path+"/"+p)
		}
		for name := range fields {
			if _, ok := props[name]; !ok {
				problems = append(problems, fmt.Sprintf("%s: Go field %q (%s) is not in the schema", path, name, rt))
			}
		}
	}
	doc := reflect.TypeOf(Document{})
	for _, k := range kinds {
		var field reflect.StructField
		for i := range doc.NumField() {
			if name, _, _ := strings.Cut(doc.Field(i).Tag.Get("json"), ","); name == string(k) {
				field = doc.Field(i)
			}
		}
		node, ok := defs["oscal-complete-oscal-"+map[Kind]string{
			Catalog: "catalog:catalog", Profile: "profile:profile", ComponentDefinition: "component-definition:component-definition",
			AssessmentResults: "ar:assessment-results", POAM: "poam:plan-of-action-and-milestones",
		}[k]].(map[string]any)
		if field.Type == nil || !ok {
			t.Fatalf("%s: no Document field or schema definition", k)
		}
		walk(field.Type, node, string(k))
	}
	slices.Sort(problems)
	for _, p := range problems {
		t.Error(p)
	}
	if len(seen) < 50 {
		t.Fatalf("walked only %d types; the audit is not reaching the model trees", len(seen))
	}
}

package profilegen

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/oscal"
)

const pinDir = "../../third_party/oscal"

func loader(t *testing.T) *PinnedLoader {
	t.Helper()
	l, err := NewPinnedLoader(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func source(t *testing.T, l *PinnedLoader, path string) string {
	t.Helper()
	u, ok := l.SourceOf(path)
	if !ok {
		t.Fatalf("%s is not pinned", path)
	}
	return u
}

// outline lists every group and control as "<parent>/<kind>:<id>" in
// document order: the catalog's structure.
func outline(n obj, parent string, out *[]string) {
	for _, g := range list(n["groups"]) {
		g := g.(obj)
		*out = append(*out, parent+"/group:"+str(g["id"]))
		outline(g, str(g["id"]), out)
	}
	for _, c := range list(n["controls"]) {
		c := c.(obj)
		*out = append(*out, parent+"/control:"+str(c["id"]))
		outline(c, str(c["id"]), out)
	}
}

// Reference-resolver artifacts that squash removes. FedRAMP's resolver
// (libOSCAL-Java, via XML) rewrites links to controls outside the baseline as
// absolute paths on its author's machine ("file:/home/...xml#cm-13"), both in
// link hrefs and in Markdown prose, and escapes brackets in plain text
// ("\[PIN\]"). The meaningful content is the fragment and the bracket.
var (
	fileLink       = regexp.MustCompile(`file:[^\s)"#]*#`)
	markdownEscape = strings.NewReplacer(`\[`, `[`, `\]`, `]`)
)

// squash normalizes reference-resolver artifacts: it collapses whitespace in
// every string (not significant in OSCAL text; NIST's resolver adds a leading
// space before parameter insertions that the source catalog lacks), reduces
// "file:...#id" links to "#id", and unescapes brackets.
func squash(v any) any {
	switch x := v.(type) {
	case string:
		x = markdownEscape.Replace(fileLink.ReplaceAllString(x, "#"))
		return strings.Join(strings.Fields(x), " ")
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = squash(e)
		}
		return out
	case obj:
		out := obj{}
		for k, e := range x {
			out[k] = squash(e)
		}
		return out
	}
	return v
}

// contents maps every group and control id to its JSON without nested
// groups or controls. With exact, strings are compared verbatim.
func contents(n obj, out map[string]string, exact bool) {
	for _, k := range []string{"groups", "controls"} {
		for _, x := range list(n[k]) {
			x := x.(obj)
			flat := obj{}
			for kk, v := range x {
				if kk != "groups" && kk != "controls" {
					flat[kk] = v
				}
			}
			var v any = flat
			if !exact {
				v = squash(flat)
			}
			b, _ := json.Marshal(v) // map keys marshal sorted: canonical
			out[k+":"+str(x["id"])] = string(b)
			contents(x, out, exact)
		}
	}
}

// whitespaceOnly counts entries that differ verbatim but match once
// normalized, so the report shows how much the normalization absorbs.
func whitespaceOnly(ours, ref obj) int {
	ea, eb := map[string]string{}, map[string]string{}
	contents(ours, ea, true)
	contents(ref, eb, true)
	n := 0
	for id, want := range eb {
		if ea[id] != want {
			n++
		}
	}
	return n
}

// conformance compares a resolved catalog with a reference resolution:
// structure, and every group's and control's full content. Metadata, uuid
// and back-matter are resolver-specific and not compared.
func conformance(ours, ref obj) []string {
	var diffs []string
	var a, b []string
	outline(ours, "", &a)
	outline(ref, "", &b)
	if !reflect.DeepEqual(a, b) {
		diffs = append(diffs, fmt.Sprintf("structure differs: %d entries vs reference %d (first: %s)", len(a), len(b), firstDiff(a, b)))
	}
	ca, cb := map[string]string{}, map[string]string{}
	contents(ours, ca, false)
	contents(ref, cb, false)
	for id, want := range cb {
		got, ok := ca[id]
		switch {
		case !ok:
			diffs = append(diffs, id+": missing")
		case got != want:
			i := 0
			for i < len(got) && i < len(want) && got[i] == want[i] {
				i++
			}
			from := max(0, i-120)
			diffs = append(diffs, fmt.Sprintf("%s: content differs at byte %d\n   got:  …%.240s\n   want: …%.240s", id, i, got[from:], want[from:]))
		}
	}
	for id := range ca {
		if _, ok := cb[id]; !ok {
			diffs = append(diffs, id+": not in the reference")
		}
	}
	return diffs
}

func firstDiff(a, b []string) string {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return fmt.Sprintf("#%d %s vs %s", i, a[i], b[i])
		}
	}
	return "length"
}

// Verification for T-02: our resolution of each pinned profile matches the
// published resolved catalog, and the output validates against the pinned
// OSCAL schema.
func TestConformance(t *testing.T) {
	l := loader(t)
	cases := []struct{ name, profile, reference string }{
		{"NIST example: basic", "examples/profile/basic_profile.json", "examples/profile/basic-resolved-profile_catalog.json"},
		{"NIST example: select with id", "examples/profile/basic_select_with_id_profile.json", "examples/profile/basic_select_with_id-resolved-profile_catalog.json"},
		{"NIST example: select with match", "examples/profile/basic_select_with_match_profile.json", "examples/profile/basic_select_with_match-resolved-profile_catalog.json"},
		{"NIST SP 800-53r5 Moderate", "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json", "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json"},
		{"FedRAMP rev5 Moderate", "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json", "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Resolve(l, source(t, l, c.profile))
			if err != nil {
				t.Fatal(err)
			}
			ref, err := l.Load(source(t, l, c.reference))
			if err != nil {
				t.Fatal(err)
			}
			diffs := conformance(got["catalog"].(obj), ref["catalog"].(obj))
			if len(diffs) == 0 {
				t.Logf("conforms; %d groups/controls differ only by normalized artifacts", whitespaceOnly(got["catalog"].(obj), ref["catalog"].(obj)))
			}
			for i, d := range diffs {
				if i == 8 {
					t.Errorf("... and %d more", len(diffs)-8)
					break
				}
				t.Error(d)
			}
			b, _ := json.Marshal(got)
			if kind, err := oscal.Validate(b); err != nil || kind != oscal.Catalog {
				t.Errorf("resolved catalog does not validate: %v", err)
			}
		})
	}
}

// fakeLoader serves documents from a map, for the negative cases.
type fakeLoader map[string]obj

func (f fakeLoader) Load(u string) (map[string]any, error) {
	if d, ok := f[u]; ok {
		return deepCopy(d).(obj), nil
	}
	return nil, fmt.Errorf("not pinned: %s", u)
}

func profileDoc(imp obj, modify obj) obj {
	p := obj{"uuid": "11111111-1111-4111-8111-111111111111", "metadata": obj{"title": "t", "last-modified": "2026-01-01T00:00:00Z", "version": "1", "oscal-version": "1.2.3"},
		"imports": []any{imp}}
	if modify != nil {
		p["modify"] = modify
	}
	return obj{"profile": p}
}

func TestResolveRejects(t *testing.T) {
	cat := obj{"catalog": obj{"uuid": "22222222-2222-4222-8222-222222222222", "metadata": obj{"title": "c"},
		"controls": []any{obj{"id": "c-1", "title": "one", "params": []any{obj{"id": "c-1_prm"}}, "controls": []any{obj{"id": "c-1.1", "title": "child"}}}}}}
	base := "https://example.test/"
	cases := map[string]struct {
		docs fakeLoader
		want string
	}{
		"unpinned import": {fakeLoader{base + "p.json": profileDoc(obj{"href": "missing.json", "include-all": obj{}}, nil)}, "not pinned"},
		"import cycle": {fakeLoader{
			base + "p.json": profileDoc(obj{"href": "q.json", "include-all": obj{}}, nil),
			base + "q.json": profileDoc(obj{"href": "p.json", "include-all": obj{}}, nil)}, "import cycle"},
		"unknown control id":   {fakeLoader{base + "p.json": profileDoc(obj{"href": "c.json", "include-controls": []any{obj{"with-ids": []any{"nope"}}}}, nil), base + "c.json": cat}, "does not have"},
		"child without parent": {fakeLoader{base + "p.json": profileDoc(obj{"href": "c.json", "include-controls": []any{obj{"with-ids": []any{"c-1.1"}}}}, nil), base + "c.json": cat}, "parent control is not"},
		"unknown parameter": {fakeLoader{base + "p.json": profileDoc(obj{"href": "c.json", "include-all": obj{}},
			obj{"set-parameters": []any{obj{"param-id": "nope", "label": "x"}}}), base + "c.json": cat}, "no parameter"},
		"alter unselected control": {fakeLoader{base + "p.json": profileDoc(obj{"href": "c.json", "include-all": obj{}},
			obj{"alters": []any{obj{"control-id": "zz", "adds": []any{obj{"props": []any{obj{"name": "a", "value": "b"}}}}}}}), base + "c.json": cat}, "not in the resolved catalog"},
		"remove matching nothing": {fakeLoader{base + "p.json": profileDoc(obj{"href": "c.json", "include-all": obj{}},
			obj{"alters": []any{obj{"control-id": "c-1", "removes": []any{obj{"by-id": "nope"}}}}}), base + "c.json": cat}, "matches nothing"},
		"unknown back-matter import": {fakeLoader{base + "p.json": profileDoc(obj{"href": "#33333333-3333-4333-8333-333333333333", "include-all": obj{}}, nil)}, "no back-matter resource"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Resolve(c.docs, base+"p.json")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestResolveIsDeterministic(t *testing.T) {
	l := loader(t)
	u := source(t, l, "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json")
	a, err := Resolve(l, u)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(l, u)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("two resolutions of the same inputs differ")
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{{"s1.1.*", "s1.1.2", true}, {"s*.2", "s2.1.2", true}, {"s*.2", "s2.1.1", false}, {"ac-2*", "ac-2.13", true}, {"ac-?", "ac-2", true}} {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.pat, c.s, got)
		}
	}
	if !errors.Is(nil, nil) {
		t.Fatal("unreachable")
	}
}

// set-parameters: label, values and select replace; props, links,
// constraints and guidelines add to what the catalog has; an answered
// parameter loses the catalog's open select.
func TestSetParametersSemantics(t *testing.T) {
	base := "https://example.test/"
	cat := obj{"catalog": obj{"uuid": "22222222-2222-4222-8222-222222222222", "metadata": obj{"title": "c"},
		"controls": []any{obj{"id": "c-1", "title": "one", "params": []any{obj{
			"id": "c-1_prm", "label": "old", "select": obj{"choice": []any{"a", "b"}},
			"constraints": []any{obj{"description": "catalog"}}, "props": []any{obj{"name": "p", "value": "1"}},
		}}}}}}
	docs := fakeLoader{base + "c.json": cat, base + "p.json": profileDoc(obj{"href": "c.json", "include-all": obj{}},
		obj{"set-parameters": []any{obj{"param-id": "c-1_prm", "label": "new",
			"constraints": []any{obj{"description": "profile"}}, "props": []any{obj{"name": "q", "value": "2"}}}}})}
	got, err := Resolve(docs, base+"p.json")
	if err != nil {
		t.Fatal(err)
	}
	p := list(list(got["catalog"].(obj)["controls"])[0].(obj)["params"])[0].(obj)
	b, _ := json.Marshal(p)
	want := `{"constraints":[{"description":"catalog"},{"description":"profile"}],"id":"c-1_prm","label":"new","props":[{"name":"p","value":"1"},{"name":"q","value":"2"}]}`
	if string(b) != want {
		t.Fatalf("param after set-parameters:\n got  %s\n want %s", b, want)
	}
}

// The value T-03's bindings transcribe from: FedRAMP's AC-11 lock time.
func TestFedRAMPModerateAC11Constraint(t *testing.T) {
	l := loader(t)
	got, err := Resolve(l, source(t, l, "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	var walk func(n obj)
	walk = func(n obj) {
		for _, p := range list(n["params"]) {
			if str(p.(obj)["id"]) == "ac-11_odp.02" {
				for _, c := range list(p.(obj)["constraints"]) {
					found = append(found, str(c.(obj)["description"]))
				}
			}
		}
		for _, k := range []string{"groups", "controls"} {
			for _, x := range list(n[k]) {
				walk(x.(obj))
			}
		}
	}
	walk(got["catalog"].(obj))
	if len(found) != 1 || found[0] != "fifteen (15) minutes" {
		t.Fatalf("ac-11_odp.02 constraints = %q", found)
	}
}

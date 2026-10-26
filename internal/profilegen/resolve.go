package profilegen

import (
	"crypto/sha1" // #nosec G505 -- RFC 9562 UUIDv5 name hashing, not a security function
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Tool is recorded in resolved catalogs as metadata prop "resolution-tool".
const Tool = "FAIR profilegen"

type obj = map[string]any

// Resolve resolves the profile at source URL u into a catalog document
// ({"catalog": ...}). The result is deterministic for the same inputs.
func Resolve(l Loader, u string) (map[string]any, error) {
	r := &resolver{l: l, stack: map[string]bool{}}
	cat, err := r.profile(u)
	if err != nil {
		return nil, err
	}
	return obj{"catalog": cat}, nil
}

type resolver struct {
	l     Loader
	stack map[string]bool // import-cycle detection
}

// selection is one import's source catalog and selected control ids.
type selection struct {
	catalog  obj
	selected map[string]bool
}

func (r *resolver) profile(u string) (obj, error) {
	if r.stack[u] {
		return nil, fmt.Errorf("profilegen: import cycle at %s", u)
	}
	r.stack[u] = true
	defer delete(r.stack, u)

	doc, err := r.l.Load(u)
	if err != nil {
		return nil, err
	}
	p, ok := doc["profile"].(obj)
	if !ok {
		return nil, fmt.Errorf("profilegen: %s is not a profile", u)
	}

	var sels []selection
	var backMatter []any
	for _, imp := range list(p["imports"]) {
		imp := imp.(obj)
		src, err := r.importHref(u, p, str(imp["href"]))
		if err != nil {
			return nil, err
		}
		cat, err := r.source(src)
		if err != nil {
			return nil, err
		}
		sel, err := selectControls(cat, imp)
		if err != nil {
			return nil, fmt.Errorf("profilegen: %s: %w", u, err)
		}
		sels = append(sels, selection{catalog: cat, selected: sel})
		backMatter = append(backMatter, resources(cat)...)
	}

	cat, err := merge(sels, p["merge"])
	if err != nil {
		return nil, fmt.Errorf("profilegen: %s: %w", u, err)
	}
	if m, ok := p["modify"].(obj); ok {
		if err := modify(cat, m); err != nil {
			return nil, fmt.Errorf("profilegen: %s: %w", u, err)
		}
	}

	meta := deepCopy(p["metadata"]).(obj)
	meta["oscal-version"] = "1.2.3"
	meta["props"] = append(list(meta["props"]), obj{"name": "resolution-tool", "value": Tool})
	meta["links"] = append(list(meta["links"]), obj{"href": u, "rel": "source-profile"})
	cat["metadata"] = meta
	cat["uuid"] = uuidV5(str(p["uuid"]) + "|" + u)
	backMatter = append(backMatter, resources(p)...)
	if bm := dedupeResources(backMatter); len(bm) > 0 {
		cat["back-matter"] = obj{"resources": bm}
	}
	return cat, nil
}

// importHref resolves an import href, following "#uuid" back-matter
// references to the resource's link.
func (r *resolver) importHref(base string, p obj, href string) (string, error) {
	if !strings.HasPrefix(href, "#") {
		return resolveHref(base, href)
	}
	id := strings.TrimPrefix(href, "#")
	for _, res := range resources(p) {
		res := res.(obj)
		if str(res["uuid"]) != id {
			continue
		}
		links := list(res["rlinks"])
		// Prefer an OSCAL JSON rendition when several are listed.
		slices.SortStableFunc(links, func(a, b any) int {
			return boolRank(strings.HasSuffix(str(b.(obj)["href"]), ".json")) - boolRank(strings.HasSuffix(str(a.(obj)["href"]), ".json"))
		})
		for _, l := range links {
			if h := str(l.(obj)["href"]); h != "" {
				return resolveHref(base, h)
			}
		}
		return "", fmt.Errorf("profilegen: back-matter resource %s has no rlink", id)
	}
	return "", fmt.Errorf("profilegen: import %s matches no back-matter resource", href)
}

// source loads an import: a catalog, or a profile resolved recursively.
func (r *resolver) source(u string) (obj, error) {
	doc, err := r.l.Load(u)
	if err != nil {
		return nil, err
	}
	if c, ok := doc["catalog"].(obj); ok {
		return deepCopy(c).(obj), nil
	}
	if _, ok := doc["profile"]; ok {
		return r.profile(u)
	}
	return nil, fmt.Errorf("profilegen: %s is neither a catalog nor a profile", u)
}

// selectControls applies include-all / include-controls and then
// exclude-controls, returning the selected control ids.
func selectControls(cat obj, imp obj) (map[string]bool, error) {
	type ctl struct {
		id       string
		children []string // descendant control ids
	}
	var all []ctl
	var walk func(n obj) []string
	walk = func(n obj) []string {
		var ids []string
		for _, g := range list(n["groups"]) {
			ids = append(ids, walk(g.(obj))...)
		}
		for _, c := range list(n["controls"]) {
			c := c.(obj)
			kids := walk(c)
			all = append(all, ctl{id: str(c["id"]), children: kids})
			ids = append(ids, str(c["id"]))
			ids = append(ids, kids...)
		}
		return ids
	}
	walk(cat)
	byID := map[string]ctl{}
	for _, c := range all {
		byID[c.id] = c
	}

	apply := func(sel obj, set map[string]bool, add bool) error {
		var hits []string
		for _, id := range list(sel["with-ids"]) {
			if _, ok := byID[str(id)]; !ok {
				return fmt.Errorf("selects control %q, which the catalog does not have", str(id))
			}
			hits = append(hits, str(id))
		}
		for _, m := range list(sel["matching"]) {
			pat := str(m.(obj)["pattern"])
			for _, c := range all {
				if globMatch(pat, c.id) {
					hits = append(hits, c.id)
				}
			}
		}
		withChildren := str(sel["with-child-controls"]) == "yes"
		for _, id := range hits {
			set[id] = add
			if withChildren {
				for _, k := range byID[id].children {
					set[k] = add
				}
			}
		}
		return nil
	}

	set := map[string]bool{}
	if _, ok := imp["include-all"]; ok {
		for _, c := range all {
			set[c.id] = true
		}
	}
	for _, sel := range list(imp["include-controls"]) {
		if err := apply(sel.(obj), set, true); err != nil {
			return nil, err
		}
	}
	for _, sel := range list(imp["exclude-controls"]) {
		if err := apply(sel.(obj), set, false); err != nil {
			return nil, err
		}
	}
	out := map[string]bool{}
	for id, in := range set {
		if in {
			out[id] = true
		}
	}
	return out, nil
}

// globMatch implements OSCAL "matching" patterns: "*" matches any run of
// characters (dots included) and "?" any single character.
func globMatch(pattern, s string) bool {
	ok, err := path.Match(pattern, s) // control ids never contain "/"
	return err == nil && ok
}

// merge builds the resolved catalog body from the selections.
func merge(sels []selection, m any) (obj, error) {
	mode := "as-is"
	if mm, ok := m.(obj); ok {
		switch {
		case mm["flat"] != nil:
			mode = "flat"
		case mm["as-is"] == true:
			mode = "as-is"
		case mm["custom"] != nil:
			return nil, fmt.Errorf("merge.custom is not supported")
		}
		if c, ok := mm["combine"].(obj); ok && str(c["method"]) != "" && str(c["method"]) != "merge" {
			return nil, fmt.Errorf("combine method %q is not supported", str(c["method"]))
		}
	}
	out := obj{}
	seen := map[string]bool{}
	for _, s := range sels {
		var err error
		if mode == "flat" {
			err = flatten(s.catalog, s.selected, out, seen)
		} else {
			err = keepStructure(s.catalog, s.selected, out, seen)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// keepStructure copies the selected controls with their groups and parents
// (merge as-is). A selected control under an unselected parent control is an
// error: the subset does not re-home orphans.
func keepStructure(src obj, sel map[string]bool, dst obj, seen map[string]bool) error {
	for _, k := range []string{"params", "props", "links", "parts"} {
		if v, ok := src[k]; ok && dst[k] == nil {
			dst[k] = deepCopy(v)
		}
	}
	for _, g := range list(src["groups"]) {
		g := g.(obj)
		ng := obj{}
		for k, v := range g {
			if k != "groups" && k != "controls" {
				ng[k] = deepCopy(v)
			}
		}
		if err := keepStructure(g, sel, ng, seen); err != nil {
			return err
		}
		if ng["groups"] != nil || ng["controls"] != nil {
			dst["groups"] = append(list(dst["groups"]), ng)
		}
	}
	for _, c := range list(src["controls"]) {
		c := c.(obj)
		id := str(c["id"])
		if !sel[id] {
			if hasSelected(c, sel) {
				return fmt.Errorf("control %s is selected but its parent control is not", firstSelected(c, sel))
			}
			continue
		}
		if seen[id] {
			return fmt.Errorf("control %s is imported twice", id)
		}
		seen[id] = true
		nc := obj{}
		for k, v := range c {
			if k != "controls" {
				nc[k] = deepCopy(v)
			}
		}
		if err := keepStructure(obj{"controls": c["controls"]}, sel, nc, seen); err != nil {
			return err
		}
		dst["controls"] = append(list(dst["controls"]), nc)
	}
	return nil
}

// flatten copies every selected control to the top level, without groups or
// nesting (merge flat).
func flatten(src obj, sel map[string]bool, dst obj, seen map[string]bool) error {
	var walk func(n obj) error
	walk = func(n obj) error {
		for _, g := range list(n["groups"]) {
			if err := walk(g.(obj)); err != nil {
				return err
			}
		}
		for _, c := range list(n["controls"]) {
			c := c.(obj)
			id := str(c["id"])
			if sel[id] {
				if seen[id] {
					return fmt.Errorf("control %s is imported twice", id)
				}
				seen[id] = true
				nc := obj{}
				for k, v := range c {
					if k != "controls" {
						nc[k] = deepCopy(v)
					}
				}
				dst["controls"] = append(list(dst["controls"]), nc)
			}
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(src)
}

func hasSelected(c obj, sel map[string]bool) bool { return firstSelected(c, sel) != "" }

func firstSelected(c obj, sel map[string]bool) string {
	for _, k := range list(c["controls"]) {
		k := k.(obj)
		if sel[str(k["id"])] {
			return str(k["id"])
		}
		if id := firstSelected(k, sel); id != "" {
			return id
		}
	}
	return ""
}

// modify applies set-parameters and alters.
func modify(cat obj, m obj) error {
	params := map[string]obj{}
	controls := map[string]obj{}
	var index func(n obj)
	index = func(n obj) {
		for _, p := range list(n["params"]) {
			params[str(p.(obj)["id"])] = p.(obj)
		}
		for _, g := range list(n["groups"]) {
			index(g.(obj))
		}
		for _, c := range list(n["controls"]) {
			controls[str(c.(obj)["id"])] = c.(obj)
			index(c.(obj))
		}
	}
	index(cat)

	for _, sp := range list(m["set-parameters"]) {
		sp := sp.(obj)
		id := str(sp["param-id"])
		p, ok := params[id]
		if !ok {
			return fmt.Errorf("set-parameters: no parameter %q in the resolved catalog", id)
		}
		// A profile that answers a parameter (values, select or constraints)
		// supersedes the catalog's open choice: values and select are
		// alternatives in OSCAL, and FedRAMP's published resolution drops a
		// catalog select whenever FedRAMP constrains the parameter.
		if sp["values"] != nil || sp["select"] != nil || sp["constraints"] != nil {
			delete(p, "values")
			delete(p, "select")
		}
		for k, v := range sp {
			switch k {
			case "param-id":
			case "props", "links", "constraints", "guidelines": // added to what the catalog has
				p[k] = append(list(p[k]), list(deepCopy(v))...)
			default: // label, usage, values, select, ... replace
				p[k] = deepCopy(v)
			}
		}
	}

	for _, a := range list(m["alters"]) {
		a := a.(obj)
		id := str(a["control-id"])
		c, ok := controls[id]
		if !ok {
			return fmt.Errorf("alters: control %q is not in the resolved catalog", id)
		}
		for _, rm := range list(a["removes"]) {
			rm := rm.(obj)
			if !removeMatching(c, rm) {
				return fmt.Errorf("alters: %s removes %v, which matches nothing", id, rm)
			}
		}
		for _, add := range list(a["adds"]) {
			if err := addTo(c, add.(obj)); err != nil {
				return fmt.Errorf("alters: %s: %w", id, err)
			}
		}
	}
	return nil
}

var childKinds = []string{"params", "props", "links", "parts"}

// removeMatching removes every param, prop, link or part below c that matches
// the remove's by-id / by-name / by-class / by-ns / by-item-name criteria.
func removeMatching(c obj, rm obj) bool {
	removed := false
	var walk func(n obj)
	walk = func(n obj) {
		for _, kind := range childKinds {
			items := list(n[kind])
			if items == nil {
				continue
			}
			kept := items[:0:0]
			for _, it := range items {
				it := it.(obj)
				if matchesRemove(kind, it, rm) {
					removed = true
					continue
				}
				walk(it)
				kept = append(kept, it)
			}
			if len(kept) == 0 {
				delete(n, kind)
			} else {
				n[kind] = kept
			}
		}
	}
	walk(c)
	return removed
}

func matchesRemove(kind string, it obj, rm obj) bool {
	ok := false
	check := func(field, want string) bool {
		if want == "" {
			return true
		}
		ok = true
		return str(it[field]) == want
	}
	itemName := str(rm["by-item-name"])
	if itemName != "" && itemName != strings.TrimSuffix(kind, "s") {
		return false
	}
	if itemName != "" {
		ok = true
	}
	return check("id", str(rm["by-id"])) && check("name", str(rm["by-name"])) &&
		check("class", str(rm["by-class"])) && check("ns", str(rm["by-ns"])) && ok
}

// addTo applies one "adds": with by-id, relative to the element with that id
// (before/after as siblings, starting/ending as children); without, to the
// control itself (starting/ending).
func addTo(c obj, add obj) error {
	pos := str(add["position"])
	if pos == "" {
		pos = "ending"
	}
	target := c
	var parent obj
	// by-id may name the control itself, which is the same as omitting it.
	if by := str(add["by-id"]); by != "" && by != str(c["id"]) {
		var found bool
		target, parent, found = findByID(c, by)
		if !found {
			return fmt.Errorf("adds: no element %q", by)
		}
	}
	for _, kind := range childKinds {
		items := list(deepCopy(add[kind]))
		if items == nil {
			continue
		}
		switch pos {
		case "starting":
			target[kind] = append(items, list(target[kind])...)
		case "ending":
			target[kind] = append(list(target[kind]), items...)
		case "before", "after":
			if parent == nil {
				return fmt.Errorf("adds: position %s needs by-id", pos)
			}
			sibs := list(parent[kind])
			i := slices.IndexFunc(sibs, func(s any) bool { return s.(obj)["id"] == target["id"] })
			if i < 0 {
				return fmt.Errorf("adds: %s %q is not a %s element; cannot insert %s beside it", pos, target["id"], kind, kind)
			}
			if pos == "after" {
				i++
			}
			parent[kind] = slices.Insert(sibs, i, items...)
		default:
			return fmt.Errorf("adds: unknown position %q", pos)
		}
	}
	if t, ok := add["title"]; ok {
		target["title"] = t
	}
	return nil
}

// findByID finds the param, part, prop or link with the given id below c,
// and the object containing it.
func findByID(c obj, id string) (obj, obj, bool) {
	for _, kind := range childKinds {
		for _, it := range list(c[kind]) {
			it := it.(obj)
			if str(it["id"]) == id {
				return it, c, true
			}
			if t, p, ok := findByID(it, id); ok {
				return t, p, true
			}
		}
	}
	return nil, nil, false
}

func resources(n obj) []any {
	bm, _ := n["back-matter"].(obj)
	return list(bm["resources"])
}

func dedupeResources(rs []any) []any {
	seen := map[string]bool{}
	var out []any
	for _, r := range rs {
		id := str(r.(obj)["uuid"])
		if !seen[id] {
			seen[id] = true
			out = append(out, deepCopy(r))
		}
	}
	return out
}

// uuidV5 derives a stable RFC 9562 version-5 UUID from name, so resolved
// catalogs are reproducible (T-06).
func uuidV5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8} // URL namespace
	h := sha1.New()                                                                                              // #nosec G401 -- RFC 9562 UUIDv5 name hashing, not a security function
	h.Write(ns)
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func deepCopy(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // values come from JSON and always re-encode
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

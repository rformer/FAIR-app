package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Error is a SCIM error response (RFC 7644 §3.12).
type Error struct {
	Status   int
	ScimType string // invalidFilter, tooMany, uniqueness, mutability, invalidSyntax, invalidPath, noTarget, invalidValue, invalidVers, sensitive
	Detail   string
}

func (e *Error) Error() string { return fmt.Sprintf("scim: %d %s: %s", e.Status, e.ScimType, e.Detail) }

func bad(scimType, format string, a ...any) *Error {
	return &Error{Status: http.StatusBadRequest, ScimType: scimType, Detail: fmt.Sprintf(format, a...)}
}

// PatchOp is one PATCH operation (RFC 7644 §3.5.2).
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// patchPath is a PATCH target: attrPath, or valuePath with an optional
// sub-attribute (emails[type eq "work"].value).
type patchPath struct {
	path
	Filter filter
}

func parsePatchPath(s string) (patchPath, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, '[')
	if i < 0 {
		p, err := parsePath(s)
		if err != nil {
			return patchPath{}, bad("invalidPath", "%v", err)
		}
		return patchPath{path: p}, nil
	}
	// The closing bracket, outside quoted strings.
	j, inStr := -1, false
	for k := i + 1; k < len(s); k++ {
		switch {
		case s[k] == '\\' && inStr:
			k++
		case s[k] == '"':
			inStr = !inStr
		case s[k] == ']' && !inStr:
			j = k
		}
		if j >= 0 {
			break
		}
	}
	if j < 0 {
		return patchPath{}, bad("invalidPath", "unclosed [ in %q", s)
	}
	p, err := parsePath(s[:i])
	if err != nil || p.Sub != "" {
		return patchPath{}, bad("invalidPath", "invalid path %q", s)
	}
	f, err := parseFilter(s[i+1 : j])
	if err != nil {
		return patchPath{}, bad("invalidPath", "%v", err)
	}
	rest := s[j+1:]
	if rest != "" {
		if !strings.HasPrefix(rest, ".") || !attrName(rest[1:]) {
			return patchPath{}, bad("invalidPath", "invalid path %q", s)
		}
		p.Sub = rest[1:]
	}
	return patchPath{path: p, Filter: f}, nil
}

// patcher applies operations to a resource document of a kind.
type patcher struct{ k kind }

// container returns the map holding p's attribute (the extension object
// for an extension URN), creating it when create is set.
func (pt patcher) container(doc map[string]any, p path, create bool) (map[string]any, error) {
	if p.URN == "" || strings.EqualFold(p.URN, pt.k.Schema.ID) {
		return doc, nil
	}
	urn, ok := pt.k.extension(p.URN)
	if !ok {
		return nil, bad("invalidPath", "unknown schema %q", p.URN)
	}
	if v, ok := lookup(doc, urn); ok {
		if m, isMap := v.(map[string]any); isMap {
			return m, nil
		}
	}
	if !create {
		return nil, nil
	}
	m := map[string]any{}
	doc[urn] = m
	addSchema(doc, urn)
	return m, nil
}

func addSchema(doc map[string]any, urn string) {
	list, _ := doc["schemas"].([]any)
	for _, s := range list {
		if str, ok := s.(string); ok && strings.EqualFold(str, urn) {
			return
		}
	}
	doc["schemas"] = append(list, urn)
}

// set stores v under the attribute's canonical name, dropping other
// spellings of it.
func set(m map[string]any, name string, v any) {
	for k := range m {
		if strings.EqualFold(k, name) && k != name {
			delete(m, k)
		}
	}
	m[name] = v
}

func del(m map[string]any, name string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
		}
	}
}

// coerce converts what clients send loosely: "True"/"False" for booleans
// (Entra ID).
func coerce(a Attr, v any) any {
	if a.Type == "boolean" {
		if s, ok := v.(string); ok {
			switch strings.ToLower(s) {
			case "true":
				return true
			case "false":
				return false
			}
		}
	}
	if m, ok := v.(map[string]any); ok && len(a.Sub) > 0 {
		for k, sv := range m {
			if sa, found := a.sub(k); found {
				m[k] = coerce(sa, sv)
			}
		}
	}
	return v
}

// Apply applies the operations to doc in order.
func (pt patcher) Apply(doc map[string]any, ops []PatchOp) error {
	if len(ops) == 0 {
		return bad("invalidSyntax", "no Operations")
	}
	for i, op := range ops {
		var v any
		if len(op.Value) > 0 {
			if err := json.Unmarshal(op.Value, &v); err != nil {
				return bad("invalidSyntax", "operation %d: value: %v", i+1, err)
			}
		}
		if err := pt.apply(doc, strings.ToLower(op.Op), op.Path, v); err != nil {
			var e *Error
			if errors.As(err, &e) {
				e.Detail = fmt.Sprintf("operation %d: %s", i+1, e.Detail)
			}
			return err
		}
	}
	return nil
}

func (pt patcher) apply(doc map[string]any, op, rawPath string, v any) error {
	switch op {
	case "add", "replace", "remove":
	default:
		return bad("invalidSyntax", "unknown op %q", op)
	}
	if rawPath == "" {
		if op == "remove" {
			return bad("noTarget", "remove needs a path")
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return bad("invalidSyntax", "%s without a path takes an object", op)
		}
		for key, val := range obj {
			if strings.EqualFold(key, "schemas") {
				continue
			}
			if urn, ext := pt.k.extension(key); ext {
				sub, ok := val.(map[string]any)
				if !ok {
					return bad("invalidValue", "%s takes an object", key)
				}
				for sk, sv := range sub {
					if err := pt.apply(doc, op, urn+":"+sk, sv); err != nil {
						return err
					}
				}
				continue
			}
			if err := pt.apply(doc, op, key, val); err != nil {
				return err
			}
		}
		return nil
	}
	pp, err := parsePatchPath(rawPath)
	if err != nil {
		return err
	}
	a, known := pt.k.attr(pp.URN, pp.Name)
	if !known {
		return bad("invalidPath", "unknown attribute %q", pp.Name)
	}
	if a.mutability() == "readOnly" {
		return bad("mutability", "%s is read-only", a.Name)
	}
	target := a
	if pp.Sub != "" {
		sa, ok := a.sub(pp.Sub)
		if !ok {
			return bad("invalidPath", "unknown sub-attribute %q of %s", pp.Sub, a.Name)
		}
		if sa.mutability() == "readOnly" {
			return bad("mutability", "%s.%s is read-only", a.Name, sa.Name)
		}
		target = sa
	}
	if v != nil {
		v = coerce(target, v)
	}
	c, err := pt.container(doc, pp.path, op != "remove")
	if err != nil {
		return err
	}
	if c == nil { // removing from an extension that is not there
		return nil
	}
	if pp.Filter != nil {
		return pt.filtered(c, a, pp, op, v)
	}
	switch {
	case op == "remove" && pp.Sub == "" && a.Multi && v != nil:
		// Remove the listed values (Entra ID, Okta: path "members" with a value).
		arr, _ := lookupArr(c, a.Name)
		for _, rm := range asList(v) {
			arr = without(arr, rm)
		}
		set(c, a.Name, arr)
	case op == "remove" && pp.Sub == "":
		del(c, a.Name)
	case op == "remove":
		cur, _ := lookup(c, a.Name)
		if a.Multi {
			for _, el := range asList(cur) {
				if m, ok := el.(map[string]any); ok {
					del(m, pp.Sub)
				}
			}
		} else if m, ok := cur.(map[string]any); ok {
			del(m, pp.Sub)
		}
	case pp.Sub != "":
		if a.Multi {
			// A sub-attribute of every element.
			cur, _ := lookup(c, a.Name)
			for _, el := range asList(cur) {
				if m, ok := el.(map[string]any); ok {
					set(m, target.Name, v)
				}
			}
			return nil
		}
		cur, _ := lookup(c, a.Name)
		m, ok := cur.(map[string]any)
		if !ok {
			m = map[string]any{}
			set(c, a.Name, m)
		}
		set(m, target.Name, v)
	case a.Multi && op == "add":
		arr, _ := lookupArr(c, a.Name)
		for _, nv := range asList(v) {
			if !containsValue(arr, nv) {
				arr = append(arr, nv)
			}
		}
		set(c, a.Name, onePrimary(arr))
	case a.Multi:
		set(c, a.Name, onePrimary(asList(v)))
	case a.Type == "complex" && op == "add":
		// add merges a complex attribute's sub-attributes.
		nm, ok := v.(map[string]any)
		if !ok {
			return bad("invalidValue", "%s takes an object", a.Name)
		}
		cur, _ := lookup(c, a.Name)
		m, ok := cur.(map[string]any)
		if !ok {
			m = map[string]any{}
		}
		for k, sv := range nm {
			set(m, k, sv)
		}
		set(c, a.Name, m)
	default:
		set(c, a.Name, v)
	}
	return nil
}

// filtered applies op to the elements of a multi-valued attribute that
// match pp's filter.
func (pt patcher) filtered(c map[string]any, a Attr, pp patchPath, op string, v any) error {
	if !a.Multi || a.Type != "complex" {
		return bad("invalidPath", "%s is not a multi-valued complex attribute", a.Name)
	}
	in := scope{k: pt.k, parent: &a}
	arr, _ := lookupArr(c, a.Name)
	var out []any
	hit := false
	for _, el := range arr {
		m, ok := el.(map[string]any)
		if !ok || !in.eval(pp.Filter, m) {
			out = append(out, el)
			continue
		}
		hit = true
		switch {
		case op == "remove" && pp.Sub == "":
			continue // drop the element
		case op == "remove":
			del(m, pp.Sub)
		case pp.Sub != "":
			set(m, pp.Sub, v)
		default: // replace or add the matched element's attributes
			nm, ok := v.(map[string]any)
			if !ok {
				return bad("invalidValue", "%s[...] takes an object", a.Name)
			}
			if op == "replace" {
				m = map[string]any{}
			}
			for k, sv := range nm {
				set(m, k, sv)
			}
			el = m
		}
		out = append(out, el)
	}
	if !hit {
		switch {
		case op == "remove":
			return nil // already gone
		case pp.Sub != "":
			// emails[type eq "work"].value with no work email: create it
			// (Entra ID), when the filter is a single equality.
			if cmp, ok := pp.Filter.(compare); ok && cmp.Op == "eq" && cmp.Path.Sub == "" {
				out = append(out, map[string]any{cmp.Path.Name: cmp.Value, pp.Sub: v})
				break
			}
			return bad("noTarget", "no %s matches the filter", a.Name)
		default:
			return bad("noTarget", "no %s matches the filter", a.Name)
		}
	}
	set(c, a.Name, onePrimary(out))
	return nil
}

func lookupArr(m map[string]any, name string) ([]any, bool) {
	v, ok := lookup(m, name)
	if !ok {
		return nil, false
	}
	return asList(v), true
}

func asList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return append([]any(nil), x...)
	}
	return []any{v}
}

// key is what identifies a multi-valued element: its value (and type).
func key(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		b, _ := json.Marshal(v)
		return string(b)
	}
	val, _ := lookup(m, "value")
	typ, _ := lookup(m, "type")
	b, _ := json.Marshal([]any{val, typ})
	return string(b)
}

func containsValue(arr []any, v any) bool {
	k := key(v)
	for _, el := range arr {
		if key(el) == k {
			return true
		}
	}
	return false
}

// without removes the elements whose value equals rm's value.
func without(arr []any, rm any) []any {
	want, _ := rm.(map[string]any)
	wv, _ := lookup(want, "value")
	var out []any
	for _, el := range arr {
		if m, ok := el.(map[string]any); ok {
			if v, _ := lookup(m, "value"); v == wv && wv != nil {
				continue
			}
		}
		out = append(out, el)
	}
	return out
}

// onePrimary keeps primary on the last element that claims it.
func onePrimary(arr []any) []any {
	last := -1
	for i, el := range arr {
		if m, ok := el.(map[string]any); ok {
			if p, _ := lookup(m, "primary"); p == true {
				last = i
			}
		}
	}
	for i, el := range arr {
		if m, ok := el.(map[string]any); ok && i != last {
			if p, _ := lookup(m, "primary"); p == true {
				set(m, "primary", false)
			}
		}
	}
	if arr == nil {
		return []any{}
	}
	return arr
}

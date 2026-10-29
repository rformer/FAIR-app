package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// maxResource bounds a stored resource document.
const maxResource = 64 << 10

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// etag of a version (weak, RFC 7644 §3.14).
func etag(v int) string { return `W/"` + strconv.Itoa(v) + `"` }

// parseETag reads If-Match: a weak or strong version tag, or "*" (nil).
func parseETag(s string) (*int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return nil, true
	}
	s = strings.TrimPrefix(s, "W/")
	s = strings.Trim(s, `"`)
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return nil, false
	}
	return &n, true
}

// render is the resource as clients see it.
func render(k kind, rec record, base string) map[string]any {
	out := make(map[string]any, len(rec.Resource)+4)
	for key, v := range rec.Resource {
		out[key] = v
	}
	out["id"] = rec.ID
	schemas := []any{k.Schema.ID}
	for _, e := range k.Extensions {
		if _, ok := lookup(out, e.ID); ok {
			schemas = append(schemas, e.ID)
		}
	}
	out["schemas"] = schemas
	loc := base + k.Endpoint + "/" + rec.ID
	out["meta"] = map[string]any{"resourceType": k.Name, "created": rec.Created.UTC().Format(time.RFC3339Nano),
		"lastModified": rec.Updated.UTC().Format(time.RFC3339Nano), "location": loc, "version": etag(rec.Version)}
	rel := make([]any, 0, len(rec.Rel))
	for _, r := range rec.Rel {
		m, _ := r.(map[string]any)
		if m == nil {
			continue
		}
		e := map[string]any{"value": m["value"], "display": m["display"]}
		if k.Name == "Group" {
			e["$ref"] = base + "/Users/" + fmt.Sprint(m["value"])
			e["type"] = "User"
		} else {
			e["$ref"] = base + "/Groups/" + fmt.Sprint(m["value"])
			e["type"] = "direct"
		}
		rel = append(rel, e)
	}
	if k.Name == "Group" {
		out["members"] = rel
	} else {
		out["groups"] = rel
	}
	return out
}

// prepare checks a client's resource and returns what is stored: known
// attributes under their canonical names and checked against their types,
// extension objects, and anything else the client sent as is; read-only
// attributes (id, meta, groups) are ignored, as are members (returned
// separately for groups).
func prepare(k kind, in map[string]any) (map[string]any, []string, error) {
	out := map[string]any{}
	var members []string
	if sc, ok := lookup(in, "schemas"); ok {
		list, isArr := sc.([]any)
		if !isArr {
			return nil, nil, bad("invalidSyntax", "schemas must be a list")
		}
		core := false
		for _, s := range list {
			if str, _ := s.(string); strings.EqualFold(str, k.Schema.ID) {
				core = true
			}
		}
		if !core {
			return nil, nil, bad("invalidSyntax", "schemas must include %s", k.Schema.ID)
		}
	}
	for key, v := range in {
		switch {
		case strings.EqualFold(key, "schemas"), strings.EqualFold(key, "id"), strings.EqualFold(key, "meta"):
			continue
		case k.Name == "Group" && strings.EqualFold(key, "members"):
			for _, m := range asList(v) {
				mm, ok := m.(map[string]any)
				val, _ := lookup(mm, "value")
				id, isStr := val.(string)
				if !ok || !isStr || !uuidRE.MatchString(id) {
					return nil, nil, bad("invalidValue", "members must be users given by id")
				}
				if t, _ := lookup(mm, "type"); t != nil && !strings.EqualFold(fmt.Sprint(t), "User") {
					return nil, nil, bad("invalidValue", "only users can be members")
				}
				members = append(members, strings.ToLower(id))
			}
			continue
		}
		if urn, ext := k.extension(key); ext {
			sub, ok := v.(map[string]any)
			if !ok {
				return nil, nil, bad("invalidValue", "%s must be an object", urn)
			}
			clean := map[string]any{}
			for sk, sv := range sub {
				a, known := k.attr(urn, sk)
				if !known {
					clean[sk] = sv
					continue
				}
				cv, err := checkValue(a, sv)
				if err != nil {
					return nil, nil, err
				}
				if a.mutability() != "readOnly" {
					clean[a.Name] = cv
				}
			}
			out[urn] = clean
			continue
		}
		a, known := k.attr("", key)
		if !known {
			out[key] = v // e.g. another extension: kept as sent
			continue
		}
		if a.mutability() == "readOnly" || a.mutability() == "writeOnly" {
			continue // ignored (RFC 7644 §3.3), and passwords are never stored
		}
		cv, err := checkValue(a, v)
		if err != nil {
			return nil, nil, err
		}
		if cv != nil {
			out[a.Name] = cv
		}
	}
	if b, _ := json.Marshal(out); len(b) > maxResource {
		return nil, nil, &Error{Status: http.StatusRequestEntityTooLarge, Detail: "the resource is larger than 64 KiB"}
	}
	return out, members, nil
}

// checkValue checks v against a's type (coercing "true"/"false").
func checkValue(a Attr, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	v = coerce(a, v)
	if a.Multi {
		arr, ok := v.([]any)
		if !ok {
			return nil, bad("invalidValue", "%s must be a list", a.Name)
		}
		single := a
		single.Multi = false
		for i, el := range arr {
			cv, err := checkValue(single, el)
			if err != nil {
				return nil, err
			}
			arr[i] = cv
		}
		return onePrimary(arr), nil
	}
	ok := true
	switch a.Type {
	case "string", "reference", "dateTime", "binary":
		_, ok = v.(string)
	case "boolean":
		_, ok = v.(bool)
	case "integer", "decimal":
		_, ok = v.(float64)
	case "complex":
		var m map[string]any
		if m, ok = v.(map[string]any); ok {
			for sk, sv := range m {
				if sa, found := a.sub(sk); found {
					if _, err := checkValue(sa, sv); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if !ok {
		return nil, bad("invalidValue", "%s must be a %s", a.Name, a.Type)
	}
	return v, nil
}

// userFieldsOf derives what the database indexes from a user resource.
func userFieldsOf(res map[string]any, subjectAttr string) (userFields, error) {
	var f userFields
	if v, _ := lookup(res, "userName"); v != nil {
		f.UserName, _ = v.(string)
	}
	f.UserName = strings.TrimSpace(f.UserName)
	if f.UserName == "" {
		return f, bad("invalidValue", "userName is required")
	}
	if v, _ := lookup(res, "externalId"); v != nil {
		f.ExternalID, _ = v.(string)
	}
	f.Active = true
	if v, ok := lookup(res, "active"); ok && v == false {
		f.Active = false
	}
	// The primary email, else the first, else a userName that is one.
	emails, _ := lookupArr(res, "emails")
	for _, e := range emails {
		m, _ := e.(map[string]any)
		val, _ := lookup(m, "value")
		s, _ := val.(string)
		if s == "" {
			continue
		}
		if p, _ := lookup(m, "primary"); p == true || f.Email == "" {
			f.Email = s
		}
	}
	if f.Email == "" && strings.Contains(f.UserName, "@") {
		f.Email = f.UserName
	}
	if f.Email == "" {
		return f, bad("invalidValue", "an email is required (emails, or a userName that is an address)")
	}
	if v, _ := lookup(res, "displayName"); v != nil {
		f.DisplayName, _ = v.(string)
	}
	if f.DisplayName == "" {
		if n, ok := lookup(res, "name"); ok {
			m, _ := n.(map[string]any)
			formatted, _ := lookup(m, "formatted")
			if s, _ := formatted.(string); s != "" {
				f.DisplayName = s
			} else {
				given, _ := lookup(m, "givenName")
				family, _ := lookup(m, "familyName")
				f.DisplayName = strings.TrimSpace(fmt.Sprint(orEmpty(given)) + " " + fmt.Sprint(orEmpty(family)))
			}
		}
	}
	if f.DisplayName == "" {
		f.DisplayName = f.UserName
	}
	switch subjectAttr {
	case "externalId":
		f.Subject = f.ExternalID
	default:
		f.Subject = f.UserName
	}
	return f, nil
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

// project applies attributes / excludedAttributes (RFC 7644 §3.9) to a
// rendered resource; id and schemas are always returned.
func project(doc map[string]any, attributes, excluded []path) map[string]any {
	if len(attributes) == 0 && len(excluded) == 0 {
		return doc
	}
	keep := func(key string) bool {
		if strings.EqualFold(key, "id") || strings.EqualFold(key, "schemas") {
			return true
		}
		if len(attributes) > 0 {
			for _, p := range attributes {
				if strings.EqualFold(p.Name, key) || strings.EqualFold(p.URN, key) {
					return true
				}
			}
			return false
		}
		for _, p := range excluded {
			if strings.EqualFold(p.Name, key) && p.Sub == "" && p.URN == "" {
				return false
			}
		}
		return true
	}
	out := map[string]any{}
	for k, v := range doc {
		if keep(k) {
			out[k] = v
		}
	}
	return out
}

func parsePaths(s string) ([]path, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []path
	for _, part := range strings.Split(s, ",") {
		p, err := parsePath(strings.TrimSpace(part))
		if err != nil {
			return nil, bad("invalidPath", "%v", err)
		}
		out = append(out, p)
	}
	return out, nil
}

package framework

import (
	"fmt"
	"path"
	"slices"
	"strings"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"

	"github.com/rformer/fair-app/internal/oscal"
)

// F-013 T-03 (F-013-AC-02; design §3.2): an OSCAL profile (a baseline)
// resolved to the requirements it selects from one catalog version. v1
// resolves the selection: include-all, include-controls by with-ids and
// matching patterns, with-child-controls, exclude-controls; set-parameters
// are recorded as values. Alters are not applied (the baseline names
// requirements; their text is the catalog's), and the notes say so. A
// profile importing another profile is resolved through it (depth at most
// MaxProfileDepth). Nothing is fetched: the caller resolves each import's
// href to a catalog version or a profile already in the platform.

// Baseline is a resolved profile.
type Baseline struct {
	Key        string            `json:"key"`
	Title      string            `json:"title"`
	Selected   []string          `json:"selected"`
	Parameters map[string]string `json:"parameters"`
	Notes      []string          `json:"notes"`
}

// Import is what an import's href names: a catalog version, or another
// profile (raw OSCAL) to resolve through.
type Import struct {
	Catalog *Version
	Profile []byte
}

// Lookup resolves an import href (and its back-matter resource's title and
// rlinks, when it is a fragment) to what it names in the platform.
type Lookup func(href string, resource *oscaltypes.Resource) (*Import, error)

// ParseProfile validates raw and resolves it. The baseline's catalog is
// the one the profile's imports reach; every import must reach the same
// catalog version.
func ParseProfile(raw []byte, key string, lookup Lookup) (*Baseline, *Version, error) {
	b, v, err := resolve(raw, lookup, 0)
	if err != nil {
		return nil, nil, err
	}
	b.Key = key
	c := &checker{}
	if !keyRE.MatchString(key) {
		c.add("/key", "is lower-case letters, digits and hyphens, at most 63")
	}
	c.text("/title", b.Title, 1, 300)
	if len(b.Selected) == 0 {
		c.add("/imports", "selects no requirement")
	}
	if err := c.err(); err != nil {
		return nil, nil, err
	}
	return b, v, nil
}

func resolve(raw []byte, lookup Lookup, depth int) (*Baseline, *Version, error) {
	if depth > MaxProfileDepth {
		return nil, nil, Problems{{Pointer: "/profile/imports", Message: fmt.Sprintf("profiles import profiles more than %d deep", MaxProfileDepth)}}
	}
	if len(raw) > MaxFile {
		return nil, nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	doc, kind, err := oscal.Parse(raw)
	if err != nil {
		return nil, nil, Problems{{Pointer: "", Message: "not a valid OSCAL " + oscal.Version + " document: " + clip(err.Error(), 500)}}
	}
	if kind != oscal.Profile || doc.Profile == nil {
		return nil, nil, Problems{{Pointer: "", Message: fmt.Sprintf("an OSCAL %s, not a profile", kind)}}
	}
	p := doc.Profile
	out := &Baseline{Title: p.Metadata.Title, Parameters: map[string]string{}}
	var catalog *Version
	selected := map[string]bool{}
	c := &checker{}
	for i, imp := range p.Imports {
		ptr := fmt.Sprintf("/profile/imports/%d", i)
		var res *oscaltypes.Resource
		if strings.HasPrefix(imp.Href, "#") && p.BackMatter != nil && p.BackMatter.Resources != nil {
			for j := range *p.BackMatter.Resources {
				r := &(*p.BackMatter.Resources)[j]
				if r.UUID == strings.TrimPrefix(imp.Href, "#") {
					res = r
				}
			}
		}
		target, err := lookup(imp.Href, res)
		if err != nil {
			c.add(ptr+"/href", "%v", err)
			continue
		}
		var avail []Requirement
		var of *Version
		switch {
		case target.Catalog != nil:
			of, avail = target.Catalog, target.Catalog.Requirements
		case target.Profile != nil:
			sub, subCat, err := resolve(target.Profile, lookup, depth+1)
			if err != nil {
				return nil, nil, err
			}
			of = subCat
			for _, r := range subCat.Requirements {
				if slices.Contains(sub.Selected, r.Identifier) {
					avail = append(avail, r)
				}
			}
			for k, v := range sub.Parameters {
				out.Parameters[k] = v
			}
		default:
			c.add(ptr+"/href", "%v", errNotCatalog)
			continue
		}
		if catalog != nil && (of.Family.Key != catalog.Family.Key || of.Label != catalog.Label) {
			c.add(ptr+"/href", "imports another catalog than the profile's first import; a baseline selects from one catalog")
			continue
		}
		catalog = of
		children := map[string][]string{}
		for _, r := range avail {
			if r.Parent != "" {
				children[r.Parent] = append(children[r.Parent], r.Identifier)
			}
		}
		pick := func(sel *[]oscaltypes.SelectControlById, into map[string]bool, at string) {
			if sel == nil {
				return
			}
			for k, s := range *sel {
				var ids []string
				if s.WithIds != nil {
					for _, id := range *s.WithIds {
						if !slices.ContainsFunc(avail, func(r Requirement) bool { return r.Identifier == id }) {
							c.add(fmt.Sprintf("%s/%d/with-ids", at, k), "names %q, which the imported catalog does not have", id)
							continue
						}
						ids = append(ids, id)
					}
				}
				if s.Matching != nil {
					for _, m := range *s.Matching {
						for _, r := range avail {
							if ok, err := path.Match(m.Pattern, r.Identifier); err == nil && ok {
								ids = append(ids, r.Identifier)
							} else if err != nil {
								c.add(fmt.Sprintf("%s/%d/matching", at, k), "the pattern %q is not a pattern", m.Pattern)
								break
							}
						}
					}
				}
				for _, id := range ids {
					into[id] = true
					if s.WithChildControls == "yes" {
						var down func(string)
						down = func(x string) {
							for _, ch := range children[x] {
								into[ch] = true
								down(ch)
							}
						}
						down(id)
					}
				}
			}
		}
		include := map[string]bool{}
		if imp.IncludeAll != nil {
			for _, r := range avail {
				include[r.Identifier] = true
			}
		}
		pick(imp.IncludeControls, include, ptr+"/include-controls")
		exclude := map[string]bool{}
		pick(imp.ExcludeControls, exclude, ptr+"/exclude-controls")
		for id := range include {
			if !exclude[id] {
				selected[id] = true
			}
		}
	}
	if p.Modify != nil {
		if p.Modify.SetParameters != nil {
			for _, sp := range *p.Modify.SetParameters {
				if sp.Values != nil && len(*sp.Values) > 0 {
					out.Parameters[sp.ParamId] = strings.Join(*sp.Values, "; ")
				}
			}
		}
		if p.Modify.Alters != nil && len(*p.Modify.Alters) > 0 {
			out.Notes = append(out.Notes, fmt.Sprintf("%d alterations were not applied: the baseline selects requirements; their text is the catalog's", len(*p.Modify.Alters)))
		}
	}
	if p.Merge != nil && p.Merge.Custom != nil {
		out.Notes = append(out.Notes, "the custom grouping was not applied")
	}
	if err := c.err(); err != nil {
		return nil, nil, err
	}
	if catalog == nil {
		return nil, nil, Problems{{Pointer: "/profile/imports", Message: "the profile imports nothing"}}
	}
	for _, r := range catalog.Requirements { // catalog order
		if selected[r.Identifier] {
			out.Selected = append(out.Selected, r.Identifier)
		}
	}
	return out, catalog, nil
}

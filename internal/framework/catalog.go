package framework

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"

	"github.com/rformer/fair-app/internal/oscal"
)

// F-013 T-03 (F-013-AC-01; design §3.1): an OSCAL catalog as a framework
// version. Every control and enhancement is a requirement: its id, its
// label prop, title, the statement parts flattened in order (labels kept,
// parameters shown as [Assignment: …] or [Selection: …]), its enclosing
// control as parent, and whether it is withdrawn with the controls it was
// incorporated into. Groups (families) are not requirements.

var insertRE = regexp.MustCompile(`\{\{\s*insert:\s*param,\s*([^\s}]+)\s*\}\}`)

// ParseCatalog validates raw against the pinned OSCAL schema and reads the
// catalog as a version of family (the importer names the family; OSCAL has
// no stable family key).
func ParseCatalog(raw []byte, family Family) (*Version, error) {
	if len(raw) > MaxFile {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	doc, kind, err := oscal.Parse(raw)
	if err != nil {
		return nil, Problems{{Pointer: "", Message: "not a valid OSCAL " + oscal.Version + " document: " + clip(err.Error(), 500)}}
	}
	if kind != oscal.Catalog || doc.Catalog == nil {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("an OSCAL %s, not a catalog", kind)}}
	}
	cat := doc.Catalog
	v := &Version{Family: family, Label: cat.Metadata.Version, Title: cat.Metadata.Title, Format: "oscal"}
	if cat.Metadata.Published != nil {
		v.Published = cat.Metadata.Published.Format("2006-01-02")
	}
	params := map[string]oscaltypes.Parameter{}
	collectParams(cat.Params, params)
	walkGroups(cat.Groups, params)
	walkControls(cat.Controls, params)

	var add func(cs *[]oscaltypes.Control, parent string)
	add = func(cs *[]oscaltypes.Control, parent string) {
		if cs == nil {
			return
		}
		for _, ctl := range *cs {
			r := Requirement{Identifier: ctl.ID, Title: strings.TrimSpace(ctl.Title), Parent: parent}
			if ctl.Props != nil {
				for _, p := range *ctl.Props {
					switch {
					case p.Name == "label" && p.Class == "" && r.Label == "":
						r.Label = p.Value
					case p.Name == "label" && p.Class == "sp800-53a" && r.Label == "":
						r.Label = p.Value
					case p.Name == "status" && p.Value == "withdrawn":
						r.Withdrawn = true
					}
				}
			}
			if ctl.Links != nil {
				for _, l := range *ctl.Links {
					if l.Rel == "incorporated-into" || l.Rel == "incorporated_into" || l.Rel == "moved-to" {
						if id := strings.TrimPrefix(l.Href, "#"); id != "" && id != l.Href {
							r.IncorporatedInto = append(r.IncorporatedInto, id)
						}
					}
				}
			}
			r.Statement = statement(ctl.Parts, params)
			v.Requirements = append(v.Requirements, r)
			add(ctl.Controls, ctl.ID)
		}
	}
	var groups func(gs *[]oscaltypes.Group)
	groups = func(gs *[]oscaltypes.Group) {
		if gs == nil {
			return
		}
		for _, g := range *gs {
			add(g.Controls, "")
			groups(g.Groups)
		}
	}
	add(cat.Controls, "")
	groups(cat.Groups)

	c := &checker{}
	checkVersion(v, c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return v, nil
}

func collectParams(ps *[]oscaltypes.Parameter, into map[string]oscaltypes.Parameter) {
	if ps == nil {
		return
	}
	for _, p := range *ps {
		if p.ID != "" {
			into[p.ID] = p
		}
	}
}

func walkGroups(gs *[]oscaltypes.Group, into map[string]oscaltypes.Parameter) {
	if gs == nil {
		return
	}
	for _, g := range *gs {
		collectParams(g.Params, into)
		walkControls(g.Controls, into)
		walkGroups(g.Groups, into)
	}
}

func walkControls(cs *[]oscaltypes.Control, into map[string]oscaltypes.Parameter) {
	if cs == nil {
		return
	}
	for _, c := range *cs {
		collectParams(c.Params, into)
		walkControls(c.Controls, into)
	}
}

// statement flattens a control's statement parts: each item's label and
// prose on its own line, indented by depth; parameters replaced.
func statement(parts *[]oscaltypes.Part, params map[string]oscaltypes.Parameter) string {
	if parts == nil {
		return ""
	}
	var b strings.Builder
	var walk func(ps *[]oscaltypes.Part, depth int)
	walk = func(ps *[]oscaltypes.Part, depth int) {
		if ps == nil {
			return
		}
		for _, p := range *ps {
			if p.Name != "statement" && p.Name != "item" {
				continue
			}
			label := ""
			if p.Props != nil {
				for _, pr := range *p.Props {
					if pr.Name == "label" {
						label = pr.Value
						break
					}
				}
			}
			prose := strings.TrimSpace(insertRE.ReplaceAllStringFunc(p.Prose, func(m string) string {
				return placeholder(params, insertRE.FindStringSubmatch(m)[1])
			}))
			next := depth // only a part that prints text indents its items
			if label != "" || prose != "" {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				b.WriteString(strings.Repeat("  ", depth))
				if label != "" {
					b.WriteString(label + " ")
				}
				b.WriteString(prose)
				next = depth + 1
			}
			walk(p.Parts, next)
		}
	}
	walk(parts, 0)
	return strings.TrimRight(b.String(), " \n")
}

// placeholder is how a parameter reads in a statement.
func placeholder(params map[string]oscaltypes.Parameter, id string) string {
	p, ok := params[id]
	if !ok {
		return "[Assignment: " + id + "]"
	}
	if p.Select != nil && p.Select.Choice != nil {
		how := "Selection"
		if p.Select.HowMany == "one-or-more" {
			how = "Selection (one or more)"
		}
		var choices []string
		for _, ch := range *p.Select.Choice {
			choices = append(choices, strings.TrimSpace(insertRE.ReplaceAllString(ch, "…")))
		}
		return "[" + how + ": " + strings.Join(choices, "; ") + "]"
	}
	if p.Label != "" {
		return "[Assignment: " + p.Label + "]"
	}
	if p.Guidelines != nil && len(*p.Guidelines) > 0 {
		return "[Assignment: " + strings.TrimSpace((*p.Guidelines)[0].Prose) + "]"
	}
	return "[Assignment: " + id + "]"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// errNotCatalog is a profile import that names no imported catalog.
var errNotCatalog = errors.New("framework: the profile imports no catalog in the platform")

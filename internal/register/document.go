package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
)

// F-007 T-04 (F-007-AC-01 to AC-04; design §3.1): a risk's document. The
// service checks its structure here; the database checks it again with
// everything it refers to (register.check_risk: the owner's scope, the
// scenarios, the pins, the category, the previous version). The structural
// problems are the same on both sides, by pointer and message
// (TestRegisterValidationParity).

// MaxDocumentBytes bounds a risk or treatment document (as the database).
const MaxDocumentBytes = 256 << 10

// MaxScenarios bounds a risk's scenarios: an exposure aggregate has at most
// 200 members (F-005).
const MaxScenarios = 200

// Pin is the analysis that stands for a linked scenario (design §3.3).
type Pin struct {
	RunID      string `json:"run_id"`
	ControlSet string `json:"control_set"`
	Reason     string `json:"reason,omitempty"`
}

// Link is a scenario of a risk, with its pin if any.
type Link struct {
	ScenarioID string `json:"scenario_id"`
	Pin        *Pin   `json:"pin,omitempty"`
}

// Risk is a risk's document (schema_version 1).
type Risk struct {
	SchemaVersion int     `json:"schema_version"`
	Title         string  `json:"title"`
	Description   string  `json:"description,omitempty"`
	Owner         string  `json:"owner"`
	Category      *string `json:"category,omitempty"`
	State         string  `json:"state"`
	CloseReason   string  `json:"close_reason,omitempty"`
	Scenarios     []Link  `json:"scenarios"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type checker struct{ out model.Problems }

func (c *checker) add(ptr, msg string) {
	if ptr == "" {
		ptr = "/"
	}
	c.out = append(c.out, model.Problem{Pointer: ptr, Message: msg})
}

func (c *checker) unknown(o map[string]any, ptr string, allowed ...string) {
	keys := make([]string, 0, len(o))
	for k := range o {
		if !slices.Contains(allowed, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		c.add(ptr+"/"+k, "is not a known field")
	}
}

// text checks a text field as register.text does.
func (c *checker) text(v any, present bool, ptr string, max int, required bool) {
	if !present || v == nil {
		if required {
			c.add(ptr, "is required")
		}
		return
	}
	s, ok := v.(string)
	if !ok {
		c.add(ptr, "is not text")
		return
	}
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > max {
		c.add(ptr, fmt.Sprintf("is 1 to %d characters", max))
	}
}

func isUUID(v any) bool {
	s, ok := v.(string)
	return ok && uuidRE.MatchString(s)
}

// Validate checks a risk document's structure: the canonical form and its
// digest, or every structural problem by pointer.
func Validate(raw []byte) ([]byte, string, model.Problems) {
	if len(raw) > MaxDocumentBytes {
		return nil, "", model.Problems{{Pointer: "/", Message: fmt.Sprintf("is larger than %d bytes", MaxDocumentBytes)}}
	}
	parsed, err := canon.Parse(raw)
	if err != nil {
		return nil, "", model.Problems{{Pointer: "/", Message: "is not JSON the platform accepts: " + err.Error()}}
	}
	var c checker
	d, ok := parsed.(map[string]any)
	if !ok {
		return nil, "", model.Problems{{Pointer: "/", Message: "is not a JSON object"}}
	}
	c.unknown(d, "", "schema_version", "title", "description", "owner", "category", "state", "close_reason", "scenarios")
	if v, ok := d["schema_version"].(json.Number); !ok || v.String() != "1" {
		c.add("/schema_version", "is 1")
	}
	title, has := d["title"]
	c.text(title, has, "/title", 200, true)
	desc, has := d["description"]
	c.text(desc, has, "/description", 5000, false)
	if !isUUID(d["owner"]) {
		c.add("/owner", "is a user id")
	}
	if cat, has := d["category"]; has && cat != nil && !isUUID(cat) {
		c.add("/category", "is a category id")
	}
	state, _ := d["state"].(string)
	if state != "open" && state != "closed" {
		c.add("/state", "is open or closed")
	}
	reason, has := d["close_reason"]
	if state == "closed" {
		c.text(reason, has, "/close_reason", 1000, true)
	} else if has && reason != nil {
		c.add("/close_reason", "is given only when the risk is closed")
	}
	links, ok := d["scenarios"].([]any)
	if !ok {
		c.add("/scenarios", "is a list")
		return nil, "", c.out
	}
	if len(links) > MaxScenarios {
		c.add("/scenarios", fmt.Sprintf("has at most %d scenarios", MaxScenarios))
		return nil, "", c.out
	}
	seen := map[string]bool{}
	for i, l := range links {
		ptr := fmt.Sprintf("/scenarios/%d", i)
		o, ok := l.(map[string]any)
		if !ok {
			c.add(ptr, "is an object")
			continue
		}
		c.unknown(o, ptr, "scenario_id", "pin")
		if !isUUID(o["scenario_id"]) {
			c.add(ptr+"/scenario_id", "is a scenario id")
			continue
		}
		id := o["scenario_id"].(string)
		if seen[id] {
			c.add(ptr+"/scenario_id", "is linked twice")
			continue
		}
		seen[id] = true
		pin, has := o["pin"]
		if !has || pin == nil {
			continue
		}
		p, ok := pin.(map[string]any)
		if !ok {
			c.add(ptr+"/pin", "is an object")
			continue
		}
		c.unknown(p, ptr+"/pin", "run_id", "control_set", "reason")
		if !isUUID(p["run_id"]) {
			c.add(ptr+"/pin/run_id", "is a run id")
			continue
		}
		if _, ok := p["control_set"].(string); !ok {
			c.add(ptr+"/pin/control_set", "is not a control set of the run")
		}
		if r, has := p["reason"]; has && r != nil {
			c.text(r, true, ptr+"/pin/reason", 1000, false)
		}
	}
	if len(c.out) > 0 {
		return nil, "", c.out
	}
	b, err := canon.Marshal(parsed)
	if err != nil {
		return nil, "", model.Problems{{Pointer: "/", Message: err.Error()}}
	}
	return b, canon.Digest(b), nil
}

// Decode reads a stored (canonical) risk document.
func Decode(b []byte) (Risk, error) {
	var r Risk
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return r, dec.Decode(&r)
}

// Encode is the canonical form of a risk document and its digest.
func Encode(r Risk) ([]byte, string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	b, err := canon.Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	return b, canon.Digest(b), nil
}

// WithState is a stored risk document with its state set (open, or closed
// with reason as its close_reason) and nothing else changed: closing and
// reopening (AC-04).
func WithState(stored []byte, state, reason string) ([]byte, string, error) {
	v, err := canon.Parse(stored)
	if err != nil {
		return nil, "", err
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("register: the stored document is not an object")
	}
	d["state"] = state
	delete(d, "close_reason")
	if state == "closed" {
		d["close_reason"] = reason
	}
	b, err := canon.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	return b, canon.Digest(b), nil
}

// Change is one difference between two versions of a document, by pointer.
type Change struct {
	Pointer string `json:"pointer"`
	Kind    string `json:"kind"` // added, removed, changed
	From    any    `json:"from,omitempty"`
	To      any    `json:"to,omitempty"`
}

// Diff lists every added, removed and changed member between two stored
// documents, by pointer; arrays compare element by element.
func Diff(from, to []byte) ([]Change, error) {
	a, err := canon.Parse(from)
	if err != nil {
		return nil, err
	}
	b, err := canon.Parse(to)
	if err != nil {
		return nil, err
	}
	out := []Change{}
	diff("", a, b, &out)
	return out, nil
}

func diff(ptr string, a, b any, out *[]Change) {
	switch x := a.(type) {
	case map[string]any:
		if y, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range x {
				keys[k] = true
			}
			for k := range y {
				keys[k] = true
			}
			sorted := make([]string, 0, len(keys))
			for k := range keys {
				sorted = append(sorted, k)
			}
			slices.Sort(sorted)
			for _, k := range sorted {
				p := ptr + "/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
				va, ina := x[k]
				vb, inb := y[k]
				switch {
				case !ina:
					*out = append(*out, Change{Pointer: p, Kind: "added", To: vb})
				case !inb:
					*out = append(*out, Change{Pointer: p, Kind: "removed", From: va})
				default:
					diff(p, va, vb, out)
				}
			}
			return
		}
	case []any:
		if y, ok := b.([]any); ok {
			for i := 0; i < max(len(x), len(y)); i++ {
				p := fmt.Sprintf("%s/%d", ptr, i)
				switch {
				case i >= len(x):
					*out = append(*out, Change{Pointer: p, Kind: "added", To: y[i]})
				case i >= len(y):
					*out = append(*out, Change{Pointer: p, Kind: "removed", From: x[i]})
				default:
					diff(p, x[i], y[i], out)
				}
			}
			return
		}
	}
	ja, _ := canon.Marshal(a)
	jb, _ := canon.Marshal(b)
	if !bytes.Equal(ja, jb) {
		if ptr == "" {
			ptr = "/"
		}
		*out = append(*out, Change{Pointer: ptr, Kind: "changed", From: a, To: b})
	}
}

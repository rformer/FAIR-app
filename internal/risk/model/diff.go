package model

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// Change kinds in a diff (AC-17; design §6.3).
const (
	ChangeAdded   = "added"
	ChangeRemoved = "removed"
	ChangeChanged = "changed"
)

// Change is one difference between two documents, at a JSON pointer. An
// estimate is compared, and shown, whole: its old and new range.
type Change struct {
	Pointer string `json:"pointer"`
	Op      string `json:"op"`
	From    any    `json:"from,omitempty"`
	To      any    `json:"to,omitempty"`
}

// PinChange is a pin that changed between two documents.
type PinChange struct {
	Pointer     string `json:"pointer"`
	Kind        string `json:"kind"`
	FromID      string `json:"from_id,omitempty"`
	FromVersion int64  `json:"from_version,omitempty"`
	ToID        string `json:"to_id,omitempty"`
	ToVersion   int64  `json:"to_version,omitempty"`
}

// Diff is the structural difference between two versions of a document.
type Diff struct {
	Changes []Change    `json:"changes"`
	Pins    []PinChange `json:"pins"`
}

// DiffDocuments compares two valid documents of a kind (canonical bytes, as
// stored): every added, removed and changed member, by pointer, and the
// pins that changed.
func DiffDocuments(kind string, from, to []byte) (Diff, error) {
	a, err := canon.Parse(from)
	if err != nil {
		return Diff{}, err
	}
	b, err := canon.Parse(to)
	if err != nil {
		return Diff{}, err
	}
	d := Diff{Changes: []Change{}, Pins: []PinChange{}}
	diffValue("", a, b, &d.Changes)
	fa, pa := Validate(kind, from)
	fb, pb := Validate(kind, to)
	if pa != nil || pb != nil {
		return Diff{}, fmt.Errorf("model: diff of an invalid document")
	}
	pins := func(doc *Document) map[string]PinRef {
		m := map[string]PinRef{}
		for _, p := range doc.Pins {
			m[p.Pointer] = p
		}
		return m
	}
	ma, mb := pins(fa), pins(fb)
	var ptrs []string
	for p := range ma {
		ptrs = append(ptrs, p)
	}
	for p := range mb {
		if _, ok := ma[p]; !ok {
			ptrs = append(ptrs, p)
		}
	}
	slices.Sort(ptrs)
	for _, p := range ptrs {
		x, inA := ma[p]
		y, inB := mb[p]
		if inA && inB && x.ID == y.ID && x.Version == y.Version {
			continue
		}
		c := PinChange{Pointer: p}
		if inA {
			c.Kind, c.FromID, c.FromVersion = x.Kind, x.ID, x.Version
		}
		if inB {
			c.Kind, c.ToID, c.ToVersion = y.Kind, y.ID, y.Version
		}
		d.Pins = append(d.Pins, c)
	}
	return d, nil
}

// isEstimate reports whether a value is an estimate: compared whole.
func isEstimate(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"min", "ml", "max", "unit"} {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func same(a, b any) bool {
	x, err1 := canon.Marshal(a)
	y, err2 := canon.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func diffValue(ptr string, a, b any, out *[]Change) {
	if same(a, b) {
		return
	}
	if isEstimate(a) || isEstimate(b) {
		*out = append(*out, Change{Pointer: ptr, Op: ChangeChanged, From: a, To: b})
		return
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			break
		}
		keys := make([]string, 0, len(x)+len(y))
		for k := range x {
			keys = append(keys, k)
		}
		for k := range y {
			if _, ok := x[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			p := ptr + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(k)
			va, inA := x[k]
			vb, inB := y[k]
			switch {
			case !inA:
				*out = append(*out, Change{Pointer: p, Op: ChangeAdded, To: vb})
			case !inB:
				*out = append(*out, Change{Pointer: p, Op: ChangeRemoved, From: va})
			default:
				diffValue(p, va, vb, out)
			}
		}
		return
	case []any:
		y, ok := b.([]any)
		if !ok {
			break
		}
		for i := 0; i < max(len(x), len(y)); i++ {
			p := ptr + "/" + strconv.Itoa(i)
			switch {
			case i >= len(x):
				*out = append(*out, Change{Pointer: p, Op: ChangeAdded, To: y[i]})
			case i >= len(y):
				*out = append(*out, Change{Pointer: p, Op: ChangeRemoved, From: x[i]})
			default:
				diffValue(p, x[i], y[i], out)
			}
		}
		return
	}
	*out = append(*out, Change{Pointer: ptr, Op: ChangeChanged, From: a, To: b})
}

// SetPinVersion returns a document with the pin at pointer moved to
// version (for adopting a newer library version, AC-10). The result is not
// canonical; validate it.
func SetPinVersion(doc []byte, pointer string, version int64) ([]byte, error) {
	v, err := canon.Parse(doc)
	if err != nil {
		return nil, err
	}
	cur := v
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return nil, fmt.Errorf("model: no pin at %s", pointer)
			}
			cur = c[i]
		default:
			return nil, fmt.Errorf("model: no pin at %s", pointer)
		}
	}
	m, ok := cur.(map[string]any)
	if !ok || m["id"] == nil || m["version"] == nil {
		return nil, fmt.Errorf("model: no pin at %s", pointer)
	}
	m["version"] = version
	return canon.Marshal(v)
}

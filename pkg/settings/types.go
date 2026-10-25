// Package settings is the security settings registry and change evaluator.
//
// Phase 0 (F-001 T-00b) is an in-process implementation of the F-015 contract
// — setting definitions, strictness ordering, built-in profiles, hard floor,
// and the change rules from F-015 R-06/R-07/R-08 — backed by an in-memory
// store. F-015 T-16 replaces the store and approvals with the posture service
// without changing this API.
package settings

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind is a setting's value type.
type Kind int

const (
	KindDuration Kind = iota // time.Duration
	KindInt                  // int
	KindBool                 // bool
	KindEnum                 // string, one of Def.Order
)

// Direction says which values are stricter.
type Direction int

const (
	LowerIsStricter  Direction = iota // durations/ints: smaller is stricter
	HigherIsStricter                  // durations/ints: larger is stricter
	TrueIsStricter                    // bools
	FalseIsStricter                   // bools
	OrderedEnum                       // enums: Def.Order lists weakest → strictest
)

// Def declares a registered security setting (F-015 AC-01).
type Def struct {
	Key         string
	Kind        Kind
	Direction   Direction
	Order       []string // OrderedEnum only: weakest → strictest
	BUScopable  bool
	Description string
	Params      []string // mapped OSCAL parameter IDs, e.g. "ac-11_odp.01"
	Controls    []string // control IDs shown in warnings, e.g. "AC-11"

	// Floor is the hard floor (F-015 R-08). Nil means no floor. FloorFamilies,
	// when non-empty, limits the floor to profiles of those families.
	Floor         any
	FloorFamilies []Family
}

// ErrType is returned for values of the wrong type for a setting.
var ErrType = errors.New("settings: value has wrong type")

// Validate checks that v is a legal value for d.
func (d Def) Validate(v any) error {
	switch d.Kind {
	case KindDuration:
		if x, ok := v.(time.Duration); !ok || x < 0 {
			return fmt.Errorf("%w: %s wants a non-negative duration", ErrType, d.Key)
		}
	case KindInt:
		if x, ok := v.(int); !ok || x < 0 {
			return fmt.Errorf("%w: %s wants a non-negative int", ErrType, d.Key)
		}
	case KindBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%w: %s wants a bool", ErrType, d.Key)
		}
	case KindEnum:
		s, ok := v.(string)
		if !ok || !slices.Contains(d.Order, s) {
			return fmt.Errorf("%w: %s wants one of %v", ErrType, d.Key, d.Order)
		}
	default:
		return fmt.Errorf("%w: %s has unknown kind", ErrType, d.Key)
	}
	return nil
}

// Compare returns -1 if a is weaker than b, 0 if equal, +1 if a is stricter.
func (d Def) Compare(a, b any) (int, error) {
	if err := d.Validate(a); err != nil {
		return 0, err
	}
	if err := d.Validate(b); err != nil {
		return 0, err
	}
	switch d.Kind {
	case KindDuration:
		return orient(cmp3(int64(a.(time.Duration)), int64(b.(time.Duration))), d.Direction)
	case KindInt:
		return orient(cmp3(int64(a.(int)), int64(b.(int))), d.Direction)
	case KindBool:
		ai, bi := btoi(a.(bool)), btoi(b.(bool))
		switch d.Direction {
		case TrueIsStricter:
			return cmp3(int64(ai), int64(bi)), nil
		case FalseIsStricter:
			return cmp3(int64(bi), int64(ai)), nil
		}
	case KindEnum:
		if d.Direction == OrderedEnum {
			return cmp3(int64(slices.Index(d.Order, a.(string))), int64(slices.Index(d.Order, b.(string)))), nil
		}
	}
	return 0, fmt.Errorf("settings: %s has incompatible kind/direction", d.Key)
}

// orient converts a natural numeric comparison into a strictness comparison.
func orient(natural int, dir Direction) (int, error) {
	switch dir {
	case HigherIsStricter:
		return natural, nil
	case LowerIsStricter:
		return -natural, nil
	}
	return 0, errors.New("settings: numeric setting needs LowerIsStricter or HigherIsStricter")
}

// Strictest returns the strictest of the given values (F-015 AC-35).
func (d Def) Strictest(vals ...any) (any, error) {
	if len(vals) == 0 {
		return nil, errors.New("settings: no values")
	}
	best := vals[0]
	for _, v := range vals[1:] {
		c, err := d.Compare(v, best)
		if err != nil {
			return nil, err
		}
		if c > 0 {
			best = v
		}
	}
	return best, nil
}

func cmp3(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

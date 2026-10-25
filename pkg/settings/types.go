// Package settings is the minimal security-settings module from F-001 T-00b.
//
// It exposes the same interface F-015 will provide (settings.Set with
// apply / warn / dual-approval paths, profile-bounded values, a hard floor),
// backed by an in-memory store and the three built-in profiles for F-001's
// own keys. F-015 T-16 replaces the store, profiles and approvals with the
// posture service; callers do not change.
package settings

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
)

// Type is a setting's value type.
type Type string

const (
	TypeDuration Type = "duration"
	TypeInt      Type = "int"
	TypeBool     Type = "bool"
	TypeEnum     Type = "enum"
)

// Direction says which way is stricter for ordered types.
type Direction string

const (
	LowerIsStricter  Direction = "lower_is_stricter"
	HigherIsStricter Direction = "higher_is_stricter"
)

// Def declares a security-relevant setting (F-015 AC-01 shape).
type Def struct {
	Key  string
	Type Type
	// Direction applies to duration and int.
	Direction Direction
	// StrictBool is the stricter boolean value (bool only).
	StrictBool bool
	// Enum lists values from weakest to strictest (enum only).
	Enum []string
	// Floor, if set, is the weakest value any profile, change or exception
	// may hold (hard floor, ADR-006 Amendment 1). Weaker values are refused.
	Floor string
	// AlwaysDualApproveLoosen forces dual approval for any loosening even
	// within bounds (e.g. post-install break-glass enablement, AC-41).
	AlwaysDualApproveLoosen bool
	// Controls are the NIST SP 800-53r5 controls/parameters the setting implements.
	Controls []string
	// Owner is the feature that registered the key.
	Owner string
}

// ErrInvalidValue is returned for values that do not parse for the setting's type.
var ErrInvalidValue = errors.New("settings: invalid value")

// Normalize parses v for d's type and returns its canonical string form.
func (d Def) Normalize(v string) (string, error) {
	switch d.Type {
	case TypeDuration:
		dur, err := time.ParseDuration(v)
		if err != nil || dur < 0 {
			return "", fmt.Errorf("%w: %s wants a non-negative duration, got %q", ErrInvalidValue, d.Key, v)
		}
		return dur.String(), nil
	case TypeInt:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: %s wants an integer, got %q", ErrInvalidValue, d.Key, v)
		}
		return strconv.FormatInt(n, 10), nil
	case TypeBool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return "", fmt.Errorf("%w: %s wants true/false, got %q", ErrInvalidValue, d.Key, v)
		}
		return strconv.FormatBool(b), nil
	case TypeEnum:
		if !slices.Contains(d.Enum, v) {
			return "", fmt.Errorf("%w: %s wants one of %v, got %q", ErrInvalidValue, d.Key, d.Enum, v)
		}
		return v, nil
	}
	return "", fmt.Errorf("%w: %s has unknown type %q", ErrInvalidValue, d.Key, d.Type)
}

// rank maps a normalized value to a number where larger means stricter.
func (d Def) rank(v string) (float64, error) {
	switch d.Type {
	case TypeDuration:
		dur, err := time.ParseDuration(v)
		if err != nil {
			return 0, err
		}
		if d.Direction == LowerIsStricter {
			return -float64(dur), nil
		}
		return float64(dur), nil
	case TypeInt:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, err
		}
		if d.Direction == LowerIsStricter {
			return -float64(n), nil
		}
		return float64(n), nil
	case TypeBool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return 0, err
		}
		if b == d.StrictBool {
			return 1, nil
		}
		return 0, nil
	case TypeEnum:
		i := slices.Index(d.Enum, v)
		if i < 0 {
			return 0, fmt.Errorf("unknown enum value %q", v)
		}
		return float64(i), nil
	}
	return 0, fmt.Errorf("unknown type %q", d.Type)
}

// Compare returns +1 if a is stricter than b, -1 if weaker, 0 if equal.
// Both values must already be valid for d.
func (d Def) Compare(a, b string) int {
	ra, errA := d.rank(a)
	rb, errB := d.rank(b)
	if errA != nil || errB != nil {
		panic(fmt.Sprintf("settings: compare on unnormalized values %q, %q for %s", a, b, d.Key))
	}
	switch {
	case ra > rb:
		return 1
	case ra < rb:
		return -1
	}
	return 0
}

// Weaker reports whether a is weaker than b.
func (d Def) Weaker(a, b string) bool { return d.Compare(a, b) < 0 }

// Strictest returns the strictest of the given values (F-015 AC-35).
func (d Def) Strictest(vals ...string) string {
	best := vals[0]
	for _, v := range vals[1:] {
		if d.Compare(v, best) > 0 {
			best = v
		}
	}
	return best
}

// Validate checks the definition is internally consistent.
func (d Def) Validate() error {
	if d.Key == "" {
		return errors.New("settings: def without key")
	}
	switch d.Type {
	case TypeDuration, TypeInt:
		if d.Direction != LowerIsStricter && d.Direction != HigherIsStricter {
			return fmt.Errorf("settings: %s needs a direction", d.Key)
		}
	case TypeEnum:
		if len(d.Enum) < 2 {
			return fmt.Errorf("settings: %s enum needs at least two values", d.Key)
		}
	case TypeBool:
	default:
		return fmt.Errorf("settings: %s has unknown type %q", d.Key, d.Type)
	}
	if d.Floor != "" {
		if _, err := d.Normalize(d.Floor); err != nil {
			return fmt.Errorf("settings: %s floor: %w", d.Key, err)
		}
	}
	return nil
}

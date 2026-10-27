package settings

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
	"time"
)

// F-015 T-13 (design §3, AC-35): property tests for the strictness
// comparators and strictest-of. Values are drawn from small ranges so that
// ties are common. The seed is fixed so a failure reproduces; set
// FAIR_PROPERTY_SEED to explore others.

// propertyDefs are the kind/direction combinations the comparators support
// (set is deferred until a setting needs it).
func propertyDefs(r *rand.Rand) []Def {
	order := []string{"off", "flag", "warn", "reauthenticate", "block", "deny"}[:2+r.IntN(5)]
	return []Def{
		{Key: "p.duration_lower", Kind: KindDuration, Direction: LowerIsStricter},
		{Key: "p.duration_higher", Kind: KindDuration, Direction: HigherIsStricter},
		{Key: "p.int_lower", Kind: KindInt, Direction: LowerIsStricter},
		{Key: "p.int_higher", Kind: KindInt, Direction: HigherIsStricter},
		{Key: "p.bool_true", Kind: KindBool, Direction: TrueIsStricter},
		{Key: "p.bool_false", Kind: KindBool, Direction: FalseIsStricter},
		{Key: "p.enum", Kind: KindEnum, Direction: OrderedEnum, Order: order},
	}
}

// randomValue draws a valid value for d.
func randomValue(r *rand.Rand, d Def) any {
	switch d.Kind {
	case KindDuration:
		units := []time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour}
		return time.Duration(r.IntN(6)) * units[r.IntN(len(units))]
	case KindInt:
		return r.IntN(8)
	case KindBool:
		return r.IntN(2) == 1
	default:
		return d.Order[r.IntN(len(d.Order))]
	}
}

func propertyRand(t *testing.T) *rand.Rand {
	t.Helper()
	seed := uint64(20261026)
	if s := os.Getenv("FAIR_PROPERTY_SEED"); s != "" {
		_, _ = fmt.Sscan(s, &seed)
	}
	t.Logf("property seed %d", seed)
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) // #nosec G404 -- seeded, reproducible test data
}

func mustCompare(t *testing.T, d Def, a, b any) int {
	t.Helper()
	c, err := d.Compare(a, b)
	if err != nil {
		t.Fatalf("%s: Compare(%v, %v): %v", d.Key, a, b, err)
	}
	if c < -1 || c > 1 {
		t.Fatalf("%s: Compare(%v, %v) = %d, want -1, 0 or 1", d.Key, a, b, c)
	}
	return c
}

// The comparator is a total preorder on valid values: reflexive, total,
// antisymmetric and transitive, and it matches each direction's meaning.
func TestComparatorTotalOrder(t *testing.T) {
	r := propertyRand(t)
	for range 200 {
		for _, d := range propertyDefs(r) {
			a, b, c := randomValue(r, d), randomValue(r, d), randomValue(r, d)
			if mustCompare(t, d, a, a) != 0 {
				t.Fatalf("%s: %v is not as strict as itself", d.Key, a)
			}
			ab, ba := mustCompare(t, d, a, b), mustCompare(t, d, b, a)
			if ab != -ba {
				t.Fatalf("%s: Compare(%v,%v)=%d but Compare(%v,%v)=%d", d.Key, a, b, ab, b, a, ba)
			}
			if (ab == 0) != (a == b) {
				t.Fatalf("%s: Compare(%v,%v)=%d; equal strictness must mean equal values", d.Key, a, b, ab)
			}
			if ab >= 0 && mustCompare(t, d, b, c) >= 0 && mustCompare(t, d, a, c) < 0 {
				t.Fatalf("%s: %v ≥ %v ≥ %v but not %v ≥ %v", d.Key, a, b, c, a, c)
			}
			// Meaning of each direction.
			var want int
			switch x := a.(type) {
			case time.Duration:
				want = cmpNatural(int64(x), int64(b.(time.Duration)))
			case int:
				want = cmpNatural(int64(x), int64(b.(int)))
			case bool:
				want = cmpNatural(int64(btoi(x)), int64(btoi(b.(bool))))
			case string:
				want = cmpNatural(int64(slices.Index(d.Order, x)), int64(slices.Index(d.Order, b.(string))))
			}
			if d.Direction == LowerIsStricter || d.Direction == FalseIsStricter {
				want = -want
			}
			if ab != want {
				t.Fatalf("%s (%v): Compare(%v, %v) = %d, want %d", d.Key, d.Direction, a, b, ab, want)
			}
		}
	}
}

func cmpNatural(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Strictest-of (AC-35) returns one of its inputs, at least as strict as every
// input, whatever their order; adding values never makes it weaker.
func TestStrictestOf(t *testing.T) {
	r := propertyRand(t)
	for range 200 {
		for _, d := range propertyDefs(r) {
			vals := make([]any, 1+r.IntN(6))
			for i := range vals {
				vals[i] = randomValue(r, d)
			}
			s, err := d.Strictest(vals...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(vals, s) {
				t.Fatalf("%s: strictest %v is not one of %v", d.Key, s, vals)
			}
			for _, v := range vals {
				if mustCompare(t, d, s, v) < 0 {
					t.Fatalf("%s: strictest %v is weaker than %v", d.Key, s, v)
				}
			}
			shuffled := slices.Clone(vals)
			r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			if s2, _ := d.Strictest(shuffled...); s2 != s {
				t.Fatalf("%s: strictest of %v is %v, of %v is %v", d.Key, vals, s, shuffled, s2)
			}
			more, _ := d.Strictest(append(slices.Clone(vals), randomValue(r, d))...)
			if mustCompare(t, d, more, s) < 0 {
				t.Fatalf("%s: adding a value made strictest weaker (%v -> %v)", d.Key, s, more)
			}
		}
	}
	if _, err := (Def{Key: "x", Kind: KindInt, Direction: LowerIsStricter}).Strictest(); err == nil {
		t.Error("strictest of nothing")
	}
}

func TestComparatorRejects(t *testing.T) {
	cases := map[string]struct {
		d    Def
		a, b any
	}{
		"wrong type":              {Def{Key: "x", Kind: KindInt, Direction: LowerIsStricter}, "3", 3},
		"negative int":            {Def{Key: "x", Kind: KindInt, Direction: LowerIsStricter}, -1, 3},
		"negative duration":       {Def{Key: "x", Kind: KindDuration, Direction: LowerIsStricter}, -time.Second, time.Second},
		"enum outside order":      {Def{Key: "x", Kind: KindEnum, Direction: OrderedEnum, Order: []string{"a", "b"}}, "c", "a"},
		"bool with int direction": {Def{Key: "x", Kind: KindBool, Direction: LowerIsStricter}, true, false},
		"int with bool direction": {Def{Key: "x", Kind: KindInt, Direction: TrueIsStricter}, 1, 2},
		"enum unordered":          {Def{Key: "x", Kind: KindEnum, Direction: LowerIsStricter, Order: []string{"a", "b"}}, "a", "b"},
		"unknown kind":            {Def{Key: "x", Kind: Kind(42), Direction: LowerIsStricter}, 1, 2},
	}
	for name, c := range cases {
		if _, err := c.d.Compare(c.a, c.b); err == nil {
			t.Errorf("%s: compared", name)
		}
		if _, err := c.d.Strictest(c.a, c.b); err == nil {
			t.Errorf("%s: strictest", name)
		}
	}
}

// "Floor never violated" runs against the real registry:
// db/tests TestFloorNeverViolatedRealRegistry (moved with F-015 T-18).

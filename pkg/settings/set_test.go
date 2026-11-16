package settings

import (
	"slices"
	"strings"
	"testing"
)

// F-009 T-01b: the set kind. Values are canonical sets; inclusion orders
// them: a proper subset is stricter, anything that adds an element is
// weaker, and {"*"} includes every set.

var setDef = Def{Key: "p.set", Kind: KindSet, Direction: SubsetIsStricter}

func TestValidSet(t *testing.T) {
	for _, c := range []struct {
		s  []string
		ok bool
	}{
		{[]string{}, true},
		{[]string{"a.example"}, true},
		{[]string{"*.example.com", "a.example"}, true},
		{[]string{"*"}, true},
		{nil, false},
		{[]string{"b", "a"}, false},
		{[]string{"a", "a"}, false},
		{[]string{""}, false},
		{[]string{"*", "a"}, false},
		{[]string{"a\nb"}, false},
		{[]string{strings.Repeat("x", MaxStringLen+1)}, false},
		{slices.Repeat([]string{"x"}, 1), true},
	} {
		if got := ValidSet(c.s); got != c.ok {
			t.Errorf("ValidSet(%q) = %v", c.s, got)
		}
	}
	many := make([]string, MaxSetLen+1)
	for i := range many {
		many[i] = string(rune('A'+i/26)) + string(rune('a'+i%26))
	}
	if ValidSet(many[:MaxSetLen]) != true || ValidSet(many) != false {
		t.Error("the element limit")
	}
	if got := CanonicalSet([]string{"b", "a", "b"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("CanonicalSet: %q", got)
	}
	if got := CanonicalSet(nil); got == nil || len(got) != 0 {
		t.Errorf("CanonicalSet(nil): %#v", got)
	}
}

func TestSetComparator(t *testing.T) {
	r := propertyRand(t)
	all := []string{SetAll}
	for range 500 {
		a, b, c := randomSet(r), randomSet(r), randomSet(r)
		ab, ba := mustCompare(t, setDef, a, b), mustCompare(t, setDef, b, a)
		sub := func(x, y []string) bool { // x ⊆ y
			if slices.Equal(y, all) {
				return true
			}
			for _, e := range x {
				if !slices.Contains(y, e) {
					return false
				}
			}
			return true
		}
		switch {
		case slices.Equal(a, b):
			if ab != 0 || ba != 0 {
				t.Fatalf("%q = %q: %d, %d", a, b, ab, ba)
			}
		case sub(a, b):
			if ab != 1 || ba != -1 {
				t.Fatalf("%q ⊂ %q: %d, %d", a, b, ab, ba)
			}
		case sub(b, a):
			if ab != -1 || ba != 1 {
				t.Fatalf("%q ⊃ %q: %d, %d", a, b, ab, ba)
			}
		default: // each adds an element: each is weaker than the other
			if ab != -1 || ba != -1 {
				t.Fatalf("%q, %q incomparable: %d, %d", a, b, ab, ba)
			}
		}
		// Stricter is transitive.
		if ab == 1 && mustCompare(t, setDef, b, c) == 1 && mustCompare(t, setDef, a, c) != 1 {
			t.Fatalf("%q ⊂ %q ⊂ %q but not %q ⊂ %q", a, b, c, a, c)
		}
		// The empty set is the strictest, the universal set the weakest.
		if !slices.Equal(a, []string{}) && mustCompare(t, setDef, []string{}, a) != 1 {
			t.Fatalf("{} is not stricter than %q", a)
		}
		if !slices.Equal(a, all) && mustCompare(t, setDef, a, all) != 1 {
			t.Fatalf("%q is not stricter than {*}", a)
		}
	}
	if _, err := setDef.Compare([]string{"b", "a"}, []string{}); err == nil {
		t.Error("a non-canonical set compared")
	}
}

// randomSet draws a canonical set of a few hosts, sometimes the universal set.
func randomSet(r interface{ IntN(int) int }) []string {
	if r.IntN(8) == 0 {
		return []string{SetAll}
	}
	pool := []string{"*.example.com", "a.example", "b.example", "hooks.example.org"}
	var s []string
	for _, h := range pool {
		if r.IntN(2) == 0 {
			s = append(s, h)
		}
	}
	return CanonicalSet(s)
}

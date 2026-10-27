package settings

import (
	"math/rand/v2"
	"testing"
	"time"
)

// The T-00b in-process Registry and its tests were retired with F-015 T-18:
// every behavior they covered runs against the real registry in db/tests
// (TestRegistry*, TestPosture*, TestException*, TestRevert*).

func TestBuiltinProfilesValid(t *testing.T) {
	for _, p := range BuiltinProfiles() {
		if err := ValidateProfile(p, F001Defs()); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
	}
}

func TestProfileMissingBindingRejected(t *testing.T) {
	p := BuiltinProfiles()[0]
	delete(p.Settings, KeySessionIdleTimeout)
	if err := ValidateProfile(p, F001Defs()); err == nil {
		t.Fatal("a registered key with no profile binding must fail validation (F-015 AC-01)")
	}
}

func TestProfileBoundBelowFloorRejected(t *testing.T) {
	p := BuiltinProfiles()[0]
	p.Settings[KeyTLSMinVersion] = Bound{Default: "1.2", Weakest: "1.1"}
	if err := ValidateProfile(p, F001Defs()); err == nil {
		t.Fatal("a profile bound weaker than the hard floor must fail validation (AC-31)")
	}
}

// Property test: Compare is a total order consistent with Strictest.
func TestCompareIsTotalOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	defs := map[string]Def{}
	for _, d := range F001Defs() {
		defs[d.Key] = d
	}
	gen := func(d Def) any {
		switch d.Kind {
		case KindDuration:
			return time.Duration(rng.IntN(1000)) * time.Minute
		case KindInt:
			return rng.IntN(20)
		case KindBool:
			return rng.IntN(2) == 1
		default:
			return d.Order[rng.IntN(len(d.Order))]
		}
	}
	for _, d := range defs {
		for i := 0; i < 200; i++ {
			a, b, c := gen(d), gen(d), gen(d)
			ab, _ := d.Compare(a, b)
			ba, _ := d.Compare(b, a)
			if ab != -ba {
				t.Fatalf("%s: antisymmetry broken for %v,%v", d.Key, a, b)
			}
			bc, _ := d.Compare(b, c)
			ac, _ := d.Compare(a, c)
			if ab >= 0 && bc >= 0 && ac < 0 {
				t.Fatalf("%s: transitivity broken for %v,%v,%v", d.Key, a, b, c)
			}
			s, _ := d.Strictest(a, b, c)
			for _, x := range []any{a, b, c} {
				if cmp, _ := d.Compare(s, x); cmp < 0 {
					t.Fatalf("%s: Strictest(%v,%v,%v)=%v is weaker than %v", d.Key, a, b, c, s, x)
				}
			}
		}
	}
}

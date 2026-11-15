package acceptance

import (
	"errors"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

var defaults = Limits{Tier1Max: 100_000, Tier2Max: 1_000_000, Tier1LevelsUp: 0, Tier2LevelsUp: 1,
	Tier1Approvals: 1, Tier2Approvals: 1, Tier3Approvals: 2, MaxDurationDays: 365}

// F-008 T-01 (design §4): the service's limits on the acceptance settings.
func TestLimitsCheck(t *testing.T) {
	with := func(edit func(*Limits)) Limits {
		l := defaults
		edit(&l)
		return l
	}
	for name, c := range map[string]struct {
		l  Limits
		ok bool
	}{
		"the defaults":               {defaults, true},
		"two approvals everywhere":   {with(func(l *Limits) { l.Tier1Approvals, l.Tier2Approvals = 2, 2 }), true},
		"tier 2 equal to tier 1":     {with(func(l *Limits) { l.Tier2Max = l.Tier1Max }), false},
		"tier 2 below tier 1":        {with(func(l *Limits) { l.Tier2Max = 50_000 }), false},
		"a negative maximum":         {with(func(l *Limits) { l.Tier1Max = -1 }), false},
		"a tier without an approval": {with(func(l *Limits) { l.Tier3Approvals = 0 }), false},
		"three approvals":            {with(func(l *Limits) { l.Tier2Approvals = 3 }), false},
		"eleven levels":              {with(func(l *Limits) { l.Tier2LevelsUp = 11 }), false},
		"negative levels":            {with(func(l *Limits) { l.Tier1LevelsUp = -1 }), false},
		"too short a duration":       {with(func(l *Limits) { l.MaxDurationDays = 29 }), false},
	} {
		err := c.l.Check()
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrLimits)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// AC-04: the tier of a mean annualized loss.
func TestPlace(t *testing.T) {
	for mean, want := range map[float64]int{0: 1, 100_000: 1, 100_000.01: 2, 1_000_000: 2, 1_000_001: 3, 1e12: 3} {
		got := defaults.Place(mean)
		if got.N != want {
			t.Errorf("%v: tier %d, want %d", mean, got.N, want)
		}
	}
	t3 := defaults.Place(5e6)
	if t3.LevelsUp != nil || t3.Max != nil || t3.Approvals != 2 {
		t.Errorf("tier 3: %+v", t3)
	}
	if t2 := defaults.Place(5e5); *t2.LevelsUp != 1 || t2.Approvals != 1 {
		t.Errorf("tier 2: %+v", t2)
	}
}

func TestLimitsFrom(t *testing.T) {
	values := map[string]int{settings.KeyAcceptanceTier1Max: 100_000, settings.KeyAcceptanceTier2Max: 1_000_000,
		settings.KeyAcceptanceTier1LevelsUp: 0, settings.KeyAcceptanceTier2LevelsUp: 1, settings.KeyAcceptanceTier1Approvals: 1,
		settings.KeyAcceptanceTier2Approvals: 1, settings.KeyAcceptanceTier3Approvals: 2, settings.KeyAcceptanceMaxDuration: 365}
	l, err := LimitsFrom(func(k string) (int, error) {
		v, ok := values[k]
		if !ok {
			return 0, errors.New("unbound " + k)
		}
		return v, nil
	})
	if err != nil || l != defaults {
		t.Errorf("%+v %v", l, err)
	}
	delete(values, settings.KeyAcceptanceMaxDuration)
	if _, err := LimitsFrom(func(k string) (int, error) {
		v, ok := values[k]
		if !ok {
			return 0, errors.New("unbound " + k)
		}
		return v, nil
	}); err == nil {
		t.Error("an unbound setting read")
	}
	// The shipped profiles' defaults pass the service's check.
	for _, p := range settings.BuiltinProfiles() {
		l, err := LimitsFrom(func(k string) (int, error) {
			b, ok := p.Settings[k]
			if !ok {
				return 0, errors.New("unbound " + k)
			}
			return b.Default.(int), nil
		})
		if err != nil || l.Check() != nil {
			t.Errorf("%s: %+v %v %v", p.ID, l, err, l.Check())
		}
	}
}

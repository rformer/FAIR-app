// Package acceptance is F-008's risk acceptance lifecycle in the risk
// service: requests to accept register risks, their approval by exposure
// tier, expiry and renewal (design §1).
package acceptance

import (
	"errors"
	"fmt"

	"github.com/rformer/fair-app/pkg/settings"
)

// Service limits beyond the profiles' bounds (design §4).
const (
	MaxLevelsUp     = 10
	MaxApprovals    = 2
	MinDurationDays = 30
)

// Tier is one exposure tier: acceptances whose mean annualized loss is at
// most Max (tier 3: no maximum) are approved LevelsUp business unit levels
// above the risk's (tier 3: at the root) by Approvals approvers.
type Tier struct {
	N         int
	Max       *int64
	LevelsUp  *int // nil: the root
	Approvals int
}

// Limits are the acceptance settings in force (design §4).
type Limits struct {
	Tier1Max, Tier2Max                             int64
	Tier1LevelsUp, Tier2LevelsUp                   int
	Tier1Approvals, Tier2Approvals, Tier3Approvals int
	MaxDurationDays                                int
}

// ErrLimits is an acceptance setting the service cannot work with.
var ErrLimits = errors.New("acceptance: settings")

// Check refuses settings outside the service's limits: tier 2's maximum
// above tier 1's, levels from 0 to 10, one or two approvals per tier, a
// maximum duration of at least 30 days.
func (l Limits) Check() error {
	switch {
	case l.Tier1Max < 0 || l.Tier2Max <= l.Tier1Max:
		return fmt.Errorf("%w: %s (%d) must be above %s (%d), both 0 or more", ErrLimits, settings.KeyAcceptanceTier2Max, l.Tier2Max,
			settings.KeyAcceptanceTier1Max, l.Tier1Max)
	case l.Tier1LevelsUp < 0 || l.Tier1LevelsUp > MaxLevelsUp || l.Tier2LevelsUp < 0 || l.Tier2LevelsUp > MaxLevelsUp:
		return fmt.Errorf("%w: tiers' levels are 0 to %d", ErrLimits, MaxLevelsUp)
	}
	for _, n := range []int{l.Tier1Approvals, l.Tier2Approvals, l.Tier3Approvals} {
		if n < 1 || n > MaxApprovals {
			return fmt.Errorf("%w: a tier needs 1 to %d approvals, not %d", ErrLimits, MaxApprovals, n)
		}
	}
	if l.MaxDurationDays < MinDurationDays {
		return fmt.Errorf("%w: %s %d is below %d", ErrLimits, settings.KeyAcceptanceMaxDuration, l.MaxDurationDays, MinDurationDays)
	}
	return nil
}

// Tiers are the three tiers the limits define.
func (l Limits) Tiers() []Tier {
	t1, t2 := l.Tier1Max, l.Tier2Max
	l1, l2 := l.Tier1LevelsUp, l.Tier2LevelsUp
	return []Tier{
		{N: 1, Max: &t1, LevelsUp: &l1, Approvals: l.Tier1Approvals},
		{N: 2, Max: &t2, LevelsUp: &l2, Approvals: l.Tier2Approvals},
		{N: 3, Approvals: l.Tier3Approvals},
	}
}

// Place is the tier of a mean annualized loss (AC-04).
func (l Limits) Place(mean float64) Tier {
	for _, t := range l.Tiers() {
		if t.Max == nil || mean <= float64(*t.Max) {
			return t
		}
	}
	panic("unreachable: tier 3 has no maximum")
}

// LimitsFrom reads the limits from the settings in force.
func LimitsFrom(get func(key string) (int, error)) (Limits, error) {
	var l Limits
	var errs []error
	read := func(key string, into *int) {
		v, err := get(key)
		if err != nil {
			errs = append(errs, err)
		}
		*into = v
	}
	var t1, t2 int
	read(settings.KeyAcceptanceTier1Max, &t1)
	read(settings.KeyAcceptanceTier2Max, &t2)
	read(settings.KeyAcceptanceTier1LevelsUp, &l.Tier1LevelsUp)
	read(settings.KeyAcceptanceTier2LevelsUp, &l.Tier2LevelsUp)
	read(settings.KeyAcceptanceTier1Approvals, &l.Tier1Approvals)
	read(settings.KeyAcceptanceTier2Approvals, &l.Tier2Approvals)
	read(settings.KeyAcceptanceTier3Approvals, &l.Tier3Approvals)
	read(settings.KeyAcceptanceMaxDuration, &l.MaxDurationDays)
	l.Tier1Max, l.Tier2Max = int64(t1), int64(t2)
	return l, errors.Join(errs...)
}

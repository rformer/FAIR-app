package register

import (
	"errors"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-007 T-01 (design §4): the service's limits on the register settings.
func TestLimitsCheck(t *testing.T) {
	sim := analysis.Limits{IterationsDefault: 100_000, IterationsMin: 10_000, IterationsMax: 1_000_000, MaxActive: 5}
	for name, c := range map[string]struct {
		l  Limits
		ok bool
	}{
		"the defaults":             {Limits{Iterations: 100_000, MaxAgeDays: 365}, true},
		"at the simulation bounds": {Limits{Iterations: 10_000, MaxAgeDays: 30}, true},
		"the simulation maximum":   {Limits{Iterations: 1_000_000, MaxAgeDays: 730}, true},
		"below the minimum":        {Limits{Iterations: 9_999, MaxAgeDays: 365}, false},
		"above the maximum":        {Limits{Iterations: 1_000_001, MaxAgeDays: 365}, false},
		"too short an age":         {Limits{Iterations: 100_000, MaxAgeDays: 29}, false},
	} {
		err := c.l.Check(sim)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrLimits)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

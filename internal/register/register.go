// Package register is F-007's risk register in the risk service: risks
// covering scenarios, the analyses pinned as their exposure, treatment,
// and business unit roll-ups (design §1).
package register

import (
	"errors"
	"fmt"

	"github.com/rformer/fair-app/internal/analysis"
)

// MinAnalysisMaxAgeDays is the service's floor of register.analysis_max_age_days
// (design §4: bounds 30 to 730; the profiles bound the loosening side).
const MinAnalysisMaxAgeDays = 30

// Limits are the register's settings in force (design §4).
type Limits struct {
	// Iterations is the count a pinned run must have (register.iterations).
	Iterations int
	// MaxAgeDays is the age after which a pinned analysis is stale
	// (register.analysis_max_age_days).
	MaxAgeDays int
}

// ErrLimits is a register setting the service cannot work with.
var ErrLimits = errors.New("register: settings")

// Check refuses settings outside the service's limits: the register's
// iteration count within the simulation bounds in force (a run at that
// count must be possible), the maximum age at least 30 days.
func (l Limits) Check(sim analysis.Limits) error {
	if l.Iterations < sim.IterationsMin || l.Iterations > sim.IterationsMax {
		return fmt.Errorf("%w: register.iterations %d is outside the simulation bounds %d to %d", ErrLimits, l.Iterations, sim.IterationsMin, sim.IterationsMax)
	}
	if l.MaxAgeDays < MinAnalysisMaxAgeDays {
		return fmt.Errorf("%w: register.analysis_max_age_days %d is below %d", ErrLimits, l.MaxAgeDays, MinAnalysisMaxAgeDays)
	}
	return nil
}

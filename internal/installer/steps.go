// Package installer is fairctl's installer (F-014 T-12; design §3.4, §6.2;
// ADR-019): the steps of an install and their states, the local install
// log (fair-install.log), the fair-install step ConfigMap, the decisions
// file (fair.install-decisions.v1) and the output every command shares.
// Later tasks fill the steps' bodies (preflight T-13 to T-16, credentials
// T-17, install T-18); this package holds what they record and print.
package installer

import (
	"fmt"
	"slices"
)

// Step is one step of `fairctl install` (design §3.4), each idempotent.
type Step string

// The steps, in order.
const (
	StepVerify      Step = "verify"      // 1. verify the package (§3.5)
	StepDecisions   Step = "decisions"   // 2. read the decisions
	StepPreflight   Step = "preflight"   // 3. preflight and overrides (§3.7)
	StepCredentials Step = "credentials" // 4. generate credentials, load the key store (§3.6)
	StepDatabase    Step = "database"    // 5. bootstrap the database roles
	StepProvision   Step = "provision"   // 6. buckets, JetStream streams
	StepChart       Step = "chart"       // 7. helm install (hooks: in-cluster preflight, iam migrate)
	StepRecord      Step = "record"      // 8. record the installation, decisions, seed, consent
	StepEvents      Step = "events"      // 9. replay the install log's events into the trail
	StepReport      Step = "report"      // 10. the install report
)

// Steps returns the install steps in order.
func Steps() []Step {
	return []Step{StepVerify, StepDecisions, StepPreflight, StepCredentials, StepDatabase, StepProvision, StepChart, StepRecord, StepEvents, StepReport}
}

// State is a step's state.
type State string

// States. A step interrupted while running stays running until it is run
// again; resume starts at the first step not done.
const (
	StatePending State = "pending"
	StateRunning State = "running"
	StateDone    State = "done"
	StateFailed  State = "failed"
)

// States returns every state.
func States() []State { return []State{StatePending, StateRunning, StateDone, StateFailed} }

func validStep(s Step) bool    { return slices.Contains(Steps(), s) }
func validState(s State) bool  { return slices.Contains(States(), s) }
func (s Step) String() string  { return string(s) }
func (s State) String() string { return string(s) }

// Progress is the state of every step.
type Progress map[Step]State

// NewProgress returns every step pending.
func NewProgress() Progress {
	p := Progress{}
	for _, s := range Steps() {
		p[s] = StatePending
	}
	return p
}

// Set moves step to state: a step runs only after every earlier step is
// done, and a done step is never run again (resume skips it).
func (p Progress) Set(step Step, state State) error {
	if !validStep(step) {
		return fmt.Errorf("installer: unknown step %q", step)
	}
	if !validState(state) {
		return fmt.Errorf("installer: unknown state %q", state)
	}
	cur := p.state(step)
	switch state {
	case StateRunning:
		if cur == StateDone {
			return fmt.Errorf("installer: step %s is done", step)
		}
		for _, s := range Steps() {
			if s == step {
				break
			}
			if p.state(s) != StateDone {
				return fmt.Errorf("installer: step %s before %s is not done", s, step)
			}
		}
	case StateDone, StateFailed:
		if cur != StateRunning {
			return fmt.Errorf("installer: step %s is %s, not running", step, cur)
		}
	case StatePending:
		if cur != StatePending {
			return fmt.Errorf("installer: step %s is %s", step, cur)
		}
	}
	p[step] = state
	return nil
}

func (p Progress) state(s Step) State {
	if st, ok := p[s]; ok {
		return st
	}
	return StatePending
}

// Next returns the first step not done, or false when every step is.
func (p Progress) Next() (Step, bool) {
	for _, s := range Steps() {
		if p.state(s) != StateDone {
			return s, true
		}
	}
	return "", false
}

// Done reports whether every step is done.
func (p Progress) Done() bool { _, more := p.Next(); return !more }

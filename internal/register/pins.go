package register

import (
	"errors"
	"fmt"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// F-007 T-05 (F-007-AC-06, AC-10; design §3.3): pins between versions, and
// adopting newer runs.

// PinChange is a linked scenario whose pin was set, changed or cleared
// between two documents (Pin nil: cleared).
type PinChange struct {
	ScenarioID string
	Pin        *Pin
}

// PinChanges lists, in the order of to's scenarios, every pin of to that
// differs from from's pin of the same scenario, and every pin cleared on a
// scenario still linked (from nil: every pin of to). Unlinked scenarios are
// not pin changes.
func PinChanges(from, to []byte) ([]PinChange, error) {
	before := map[string]*Pin{}
	if from != nil {
		r, err := Decode(from)
		if err != nil {
			return nil, err
		}
		for _, l := range r.Scenarios {
			before[l.ScenarioID] = l.Pin
		}
	}
	r, err := Decode(to)
	if err != nil {
		return nil, err
	}
	var out []PinChange
	for _, l := range r.Scenarios {
		old, linked := before[l.ScenarioID]
		switch {
		case l.Pin == nil && (!linked || old == nil):
		case l.Pin == nil:
			out = append(out, PinChange{ScenarioID: l.ScenarioID})
		case old == nil || *old != *l.Pin:
			out = append(out, PinChange{ScenarioID: l.ScenarioID, Pin: l.Pin})
		}
	}
	return out, nil
}

// NewerRun is a succeeded run of a scenario newer than its pinned run, at
// the register's iteration count (register.newer_runs).
type NewerRun struct {
	ScenarioID  string
	RunID       string
	ControlSets []string // the run's sets, its current one first
}

// Adoptions are the pins that adopt the newest of newer (listed newest
// first per scenario) for every pinned scenario of r that has one (AC-10).
// A pin of the run's current set moves to the newer run's current set; a
// pin of another set, made with a reason, keeps that set and reason when
// the newer run has it, and otherwise moves to its current set.
func Adoptions(r Risk, newer []NewerRun) map[string]Pin {
	newest := map[string]NewerRun{}
	for _, n := range newer {
		if _, ok := newest[n.ScenarioID]; !ok && len(n.ControlSets) > 0 {
			newest[n.ScenarioID] = n
		}
	}
	out := map[string]Pin{}
	for _, l := range r.Scenarios {
		n, ok := newest[l.ScenarioID]
		if l.Pin == nil || !ok || n.RunID == l.Pin.RunID {
			continue
		}
		p := Pin{RunID: n.RunID, ControlSet: n.ControlSets[0]}
		if l.Pin.Reason != "" && l.Pin.ControlSet != n.ControlSets[0] {
			for _, s := range n.ControlSets[1:] {
				if s == l.Pin.ControlSet {
					p.ControlSet, p.Reason = s, l.Pin.Reason
				}
			}
		}
		out[l.ScenarioID] = p
	}
	return out
}

// ErrNotLinked is a pin for a scenario the risk does not link.
var ErrNotLinked = errors.New("register: the scenario is not linked to the risk")

// WithPins is a stored risk document with the pins of the given scenarios
// replaced and nothing else changed (adoption).
func WithPins(stored []byte, pins map[string]Pin) ([]byte, string, error) {
	v, err := canon.Parse(stored)
	if err != nil {
		return nil, "", err
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("register: the stored document is not an object")
	}
	links, _ := d["scenarios"].([]any)
	done := map[string]bool{}
	for _, x := range links {
		l, ok := x.(map[string]any)
		if !ok {
			continue
		}
		id, _ := l["scenario_id"].(string)
		p, ok := pins[id]
		if !ok {
			continue
		}
		pin := map[string]any{"run_id": p.RunID, "control_set": p.ControlSet}
		if p.Reason != "" {
			pin["reason"] = p.Reason
		}
		l["pin"] = pin
		done[id] = true
	}
	for id := range pins {
		if !done[id] {
			return nil, "", fmt.Errorf("%w: %s", ErrNotLinked, id)
		}
	}
	b, err := canon.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	return b, canon.Digest(b), nil
}

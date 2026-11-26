package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// StopError is a failed gate: the rollout stops here and nothing is
// written. Gate is flux, soak, readyz, slo, pin or window.
type StopError struct {
	Instance, Gate, Detail string
}

func (e *StopError) Error() string {
	return fmt.Sprintf("rollout stopped at %s: %s gate: %s", e.Instance, e.Gate, e.Detail)
}

// Change is one reviewed change: a branch with one commit over the base.
type Change struct {
	Instance string
	Branch   string
	Message  string
	Files    map[string][]byte // path in the fleet repository -> new content
}

// Plan is what a promotion or rollback writes.
type Plan struct {
	Ring    string   // the ring written (promote)
	Gated   []string // the instances whose gates passed
	Skipped []string // instances already on the release
	Changes []Change
}

// Gate checks that an instance runs the release p, is healthy, and has
// been for soak: Flux Ready on p (source, every step, the migration), the
// readiness URLs answering, and no SLO alert firing since the source
// stored p's artifact. A zero soak checks health now (status, the first
// ring's merge check). The first failure is returned as a *StopError.
func Gate(ctx context.Context, src Sources, now time.Time, in Instance, p Pin, soak time.Duration) error {
	stop := func(gate, f string, a ...any) error {
		return &StopError{Instance: in.ID, Gate: gate, Detail: fmt.Sprintf(f, a...)}
	}
	if in.Pin != p {
		return stop("pin", "pinned to %s, not %s", in.Pin, p)
	}
	fx, err := src.Flux(ctx, in)
	if err != nil {
		return stop("flux", "%v", err)
	}
	if prob := fx.Problem(p); prob != "" {
		return stop("flux", "%s", prob)
	}
	over := time.Duration(0)
	if soak > 0 {
		if fx.Since.IsZero() {
			return stop("soak", "the source reports no artifact time")
		}
		ran := now.Sub(fx.Since)
		if ran < soak {
			return stop("soak", "on %s for %s of %s (since %s)", p.Tag, ran.Truncate(time.Minute), soak, fx.Since.UTC().Format(time.RFC3339))
		}
		over = ran
	}
	if err := src.Ready(ctx, in); err != nil {
		return stop("readyz", "%v", err)
	}
	alerts, err := src.Alerts(ctx, in, over)
	if err != nil {
		return stop("slo", "%v", err)
	}
	if len(alerts) > 0 {
		return stop("slo", "SLO alerts fired: %s", strings.Join(alerts, ", "))
	}
	return nil
}

// Promote plans the release's next ring (or ring, when named): every
// instance of the closest earlier ring with instances must pass Gate with
// that ring's soak; then each instance of the ring not yet on the release
// gets a branch pinning it, its merge time inside its maintenance window.
// The first failing instance stops the plan; nothing is planned for it or
// any later ring.
func (f *Fleet) Promote(ctx context.Context, src Sources, now time.Time, rel Pin, ring string) (Plan, error) {
	if err := rel.Check(true); err != nil {
		return Plan{}, err
	}
	var target Ring
	if ring != "" {
		r, ok := f.Ring(ring)
		if !ok {
			return Plan{}, fmt.Errorf("no ring %q", ring)
		}
		target = r
	} else {
		found := false
		for _, r := range f.Rings {
			for _, in := range f.InRing(r.Name) {
				if in.Pin != rel {
					found = true
				}
			}
			if found {
				target = r
				break
			}
		}
		if !found {
			return Plan{}, nil // every instance runs rel
		}
	}
	plan := Plan{Ring: target.Name}
	if prev, ok := f.before(target.Name); ok {
		for _, in := range f.InRing(prev.Name) {
			if err := Gate(ctx, src, now, in, rel, prev.Soak); err != nil {
				return Plan{}, err
			}
			plan.Gated = append(plan.Gated, in.ID)
		}
	}
	for _, in := range f.InRing(target.Name) {
		if in.Pin == rel {
			plan.Skipped = append(plan.Skipped, in.ID)
			continue
		}
		c, err := promoteChange(in, rel, target, now)
		if err != nil {
			return Plan{}, err
		}
		plan.Changes = append(plan.Changes, c)
	}
	return plan, nil
}

func promoteChange(in Instance, rel Pin, ring Ring, now time.Time) (Change, error) {
	if in.Pin.Tag == rel.Tag {
		return Change{}, &StopError{Instance: in.ID, Gate: "pin", Detail: fmt.Sprintf("pinned to %s: the same tag with another digest", in.Pin)}
	}
	if c, err := Version(rel.Tag, in.Pin.Tag); err != nil {
		return Change{}, err
	} else if c < 0 {
		return Change{}, &StopError{Instance: in.ID, Gate: "pin", Detail: fmt.Sprintf("runs %s, newer than %s (rollback pins an older release)", in.Pin.Tag, rel.Tag)}
	}
	if in.RolledBackFrom.Tag == rel.Tag {
		return Change{}, &StopError{Instance: in.ID, Gate: "pin", Detail: fmt.Sprintf("was rolled back from %s; promote a fixed release", rel.Tag)}
	}
	kz, err := WritePin([]byte(in.kustomization), rel)
	if err != nil {
		return Change{}, fmt.Errorf("instances/%s: %w", in.ID, err)
	}
	ro, err := setRollout(in.rollout, in.Pin, Pin{})
	if err != nil {
		return Change{}, fmt.Errorf("instances/%s: %w", in.ID, err)
	}
	start, end, _ := in.Window.Next(now)
	msg := fmt.Sprintf("Promote %s to %s (ring %s)\n\n"+
		"Pins instances/%s to %s. The previous release, %s, is recorded for\n"+
		"rollback. The earlier ring passed its gates (Flux ready on the release,\n"+
		"the migration done, the soak time, /readyz, no SLO alert); fleetctl\n"+
		"merge-check repeats them and checks the maintenance window before merge.\n\n"+
		"Fleet-Instance: %s\nFleet-Release: %s\nFleet-Merge-After: %s\nFleet-Merge-Before: %s\n",
		in.ID, rel.Tag, ring.Name, in.ID, rel, in.Pin, in.ID, rel,
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	return Change{
		Instance: in.ID,
		Branch:   "fleet/promote/" + rel.Tag + "/" + in.ID,
		Message:  msg,
		Files: map[string][]byte{
			path.Join("instances", in.ID, "kustomization.yaml"): kz,
			path.Join("instances", in.ID, "rollout.yaml"):       []byte(ro),
		},
	}, nil
}

// Rollback plans pinning each instance (by ID, or every instance of ring)
// to its recorded previous release, with no gates and no window: the
// instance is failing. The previous release's code runs on the upgraded
// schema (migrations are expand-contract, T-08's upgrade test; no down
// migrations). Every instance must have a previous release, or nothing
// is planned.
func (f *Fleet) Rollback(ids []string, ring string) (Plan, error) {
	var ins []Instance
	if ring != "" {
		if _, ok := f.Ring(ring); !ok {
			return Plan{}, fmt.Errorf("no ring %q", ring)
		}
		ins = f.InRing(ring)
	}
	for _, id := range ids {
		in, ok := f.Instance(id)
		if !ok {
			return Plan{}, fmt.Errorf("no instance %q", id)
		}
		ins = append(ins, in)
	}
	if len(ins) == 0 {
		return Plan{}, errors.New("no instance to roll back")
	}
	plan := Plan{Ring: ring}
	for _, in := range ins {
		if in.Previous.IsZero() {
			return Plan{}, fmt.Errorf("instances/%s: no previous release recorded (rollout.yaml previous)", in.ID)
		}
		kz, err := WritePin([]byte(in.kustomization), in.Previous)
		if err != nil {
			return Plan{}, fmt.Errorf("instances/%s: %w", in.ID, err)
		}
		ro, err := setRollout(in.rollout, Pin{}, in.Pin)
		if err != nil {
			return Plan{}, fmt.Errorf("instances/%s: %w", in.ID, err)
		}
		msg := fmt.Sprintf("Roll back %s from %s to %s\n\n"+
			"Pins instances/%s to the previous release, %s. Its services run on the\n"+
			"schema %s migrated (expand-contract; no down migrations). promote\n"+
			"refuses %s for this instance from now on.\n\n"+
			"Fleet-Instance: %s\nFleet-Release: %s\nFleet-Rolled-Back-From: %s\n",
			in.ID, in.Pin.Tag, in.Previous.Tag, in.ID, in.Previous, in.Pin.Tag, in.Pin.Tag,
			in.ID, in.Previous, in.Pin)
		plan.Changes = append(plan.Changes, Change{
			Instance: in.ID,
			Branch:   "fleet/rollback/" + in.Pin.Tag + "/" + in.ID,
			Message:  msg,
			Files: map[string][]byte{
				path.Join("instances", in.ID, "kustomization.yaml"): kz,
				path.Join("instances", in.ID, "rollout.yaml"):       []byte(ro),
			},
		})
	}
	return plan, nil
}

// MergeCheck decides whether a branch may be merged now (the bot runs it
// after a human approved the pull request): exactly one instance's pin
// differs between base and head. A rollback (head records rolled_back_from
// as base's pin and pins base's previous) merges at once. A promotion
// needs now inside the instance's maintenance window and the earlier
// ring's gates passing again on the release, as at promote.
func MergeCheck(ctx context.Context, src Sources, now time.Time, base, head *Fleet) (string, error) {
	var changed []Instance
	for _, h := range head.Instances {
		b, ok := base.Instance(h.ID)
		if !ok {
			return "", fmt.Errorf("instances/%s is new; onboarding is not a promotion", h.ID)
		}
		if b.Pin != h.Pin {
			changed = append(changed, h)
		}
	}
	if len(changed) != 1 {
		return "", fmt.Errorf("%d instances change their release pin, want 1", len(changed))
	}
	h := changed[0]
	b, _ := base.Instance(h.ID)
	if h.RolledBackFrom == b.Pin && h.Pin == b.Previous && !b.Previous.IsZero() {
		return fmt.Sprintf("%s: rollback from %s to %s may merge now", h.ID, b.Pin, h.Pin), nil
	}
	if h.Previous != b.Pin {
		return "", fmt.Errorf("instances/%s: previous is %s, want the base's pin %s", h.ID, h.Previous, b.Pin)
	}
	if err := h.Pin.Check(true); err != nil {
		return "", fmt.Errorf("instances/%s: %w", h.ID, err)
	}
	if c, err := Version(h.Pin.Tag, b.Pin.Tag); err != nil || c <= 0 {
		return "", fmt.Errorf("instances/%s: %s is not newer than %s", h.ID, h.Pin.Tag, b.Pin.Tag)
	}
	start, end, open := b.Window.Next(now)
	if !open {
		return "", &StopError{Instance: h.ID, Gate: "window", Detail: fmt.Sprintf("outside the maintenance window; it opens %s and closes %s",
			start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))}
	}
	if prev, ok := base.before(b.Ring); ok {
		for _, in := range base.InRing(prev.Name) {
			if err := Gate(ctx, src, now, in, h.Pin, prev.Soak); err != nil {
				return "", err
			}
		}
	}
	return fmt.Sprintf("%s: promotion to %s may merge now (window closes %s)", h.ID, h.Pin, end.UTC().Format(time.RFC3339)), nil
}

// InstanceStatus is one row of status.
type InstanceStatus struct {
	Instance   string `json:"instance"`
	Ring       string `json:"ring"`
	Pinned     string `json:"pinned"`
	Previous   string `json:"previous,omitempty"`
	Reconciled string `json:"reconciled,omitempty"`
	Healthy    bool   `json:"healthy"`
	Problem    string `json:"problem,omitempty"`
	Window     string `json:"window"`
}

// Status reports every instance: its pin, what Flux reconciled, and its
// health now (Gate with no soak). One instance's failure does not hide
// the others'.
func (f *Fleet) Status(ctx context.Context, src Sources, now time.Time) []InstanceStatus {
	var out []InstanceStatus
	for _, in := range f.Instances {
		s := InstanceStatus{Instance: in.ID, Ring: in.Ring, Pinned: in.Pin.String()}
		if !in.Previous.IsZero() {
			s.Previous = in.Previous.String()
		}
		if fx, err := src.Flux(ctx, in); err == nil {
			s.Reconciled = fx.Reconciled()
		}
		if err := Gate(ctx, src, now, in, in.Pin, 0); err != nil {
			var se *StopError
			if errors.As(err, &se) {
				s.Problem = se.Gate + ": " + se.Detail
			} else {
				s.Problem = err.Error()
			}
		} else {
			s.Healthy = true
		}
		start, end, open := in.Window.Next(now)
		if open {
			s.Window = "open until " + end.UTC().Format(time.RFC3339)
		} else {
			s.Window = "opens " + start.UTC().Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

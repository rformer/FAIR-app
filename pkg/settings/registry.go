package settings

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// Errors returned by the registry.
var (
	ErrUnknownKey          = errors.New("settings: unknown key")
	ErrUnknownProfile      = errors.New("settings: unknown profile")
	ErrHardFloor           = errors.New("settings: change would weaken a hard-floor setting")
	ErrExplanationRequired = errors.New("settings: a written explanation is required to loosen beyond the profile bound")
	ErrSelfApproval        = errors.New("settings: the approver must be a different person than the requester")
	ErrNotPending          = errors.New("settings: request is not pending")
	ErrExceptionExpired    = errors.New("settings: exception has already expired")
	ErrExpiryTooLong       = errors.New("settings: requested exception expiry exceeds the maximum duration")
)

// Source records where a setting's current value came from.
type Source string

const (
	SourceProfile   Source = "profile"
	SourceChange    Source = "change"
	SourceException Source = "exception"
	SourceRevert    Source = "revert"
)

// Value is a setting's current instance-level value.
type Value struct {
	Value       any
	Source      Source
	ExceptionID string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// Outcome of a change request.
type Outcome string

const (
	Applied         Outcome = "applied"
	PendingApproval Outcome = "pending_approval"
	Refused         Outcome = "refused"
)

// Warning is shown before an out-of-bounds change is submitted (F-015 AC-21).
type Warning struct {
	Key      string
	Bound    any
	Controls []string
	Message  string
}

// Request asks to change a setting.
type Request struct {
	Key         string
	Value       any
	Actor       string // the stand-in Registry's actor; Setter takes the actor from the principal's signed context
	Explanation string
	BUID        string // BU override (Setter only; "" = instance-wide)
}

// Result describes what happened to a request.
type Result struct {
	Outcome    Outcome
	ApprovalID string
	ChangeID   string // Setter: the recorded change, applied with ApplyApproved once approved
	Warning    *Warning
}

// ExceptionState is the lifecycle state of an exception.
type ExceptionState string

const (
	ExceptionActive     ExceptionState = "active"
	ExceptionRenewed    ExceptionState = "renewed"
	ExceptionReverted   ExceptionState = "reverted"
	ExceptionSuperseded ExceptionState = "superseded"
)

// Exception is an approved, time-limited deviation (F-015 R-07).
type Exception struct {
	ID            string
	Key           string
	Value         any
	BoundAtCreate any
	Justification string
	Owner         string
	ApprovedBy    string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RenewedFrom   string
	State         ExceptionState
}

type pendingKind int

const (
	pendingChange pendingKind = iota
	pendingRenewal
)

type pending struct {
	id          string
	kind        pendingKind
	req         Request
	exceptionID string // renewals
	createdAt   time.Time
}

// SecOpsNotifier is called for any weakening change in SaaS mode (F-015 AC-23).
type SecOpsNotifier func(ctx context.Context, e audit.Event)

// Options configures a Registry.
type Options struct {
	Defs          []Def
	Profiles      []Profile
	ActiveProfile string
	Emitter       audit.Emitter
	Clock         func() time.Time
	SaaS          bool
	SecOps        SecOpsNotifier
}

// Registry holds definitions, the active profile, current values, pending
// approvals and exceptions. It is safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	defs       map[string]Def
	profiles   map[string]Profile
	active     Profile
	values     map[string]Value
	pending    map[string]*pending
	exceptions map[string]*Exception
	emit       audit.Emitter
	now        func() time.Time
	saas       bool
	secops     SecOpsNotifier
}

// New validates every profile against the definitions, seeds values from the
// active profile, and records the seeding in the audit trail (F-015 AC-10).
func New(ctx context.Context, o Options) (*Registry, error) {
	if o.Emitter == nil {
		return nil, errors.New("settings: an audit emitter is required")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	r := &Registry{
		defs:       map[string]Def{},
		profiles:   map[string]Profile{},
		values:     map[string]Value{},
		pending:    map[string]*pending{},
		exceptions: map[string]*Exception{},
		emit:       o.Emitter,
		now:        o.Clock,
		saas:       o.SaaS,
		secops:     o.SecOps,
	}
	for _, d := range o.Defs {
		if d.Key == "" {
			return nil, errors.New("settings: definition with empty key")
		}
		if _, dup := r.defs[d.Key]; dup {
			return nil, fmt.Errorf("settings: duplicate definition %s", d.Key)
		}
		if d.Floor != nil {
			if err := d.Validate(d.Floor); err != nil {
				return nil, fmt.Errorf("settings: floor for %s: %w", d.Key, err)
			}
		}
		r.defs[d.Key] = d
	}
	var errs []error
	for _, p := range o.Profiles {
		if err := ValidateProfile(p, o.Defs); err != nil {
			errs = append(errs, err)
		}
		r.profiles[p.ID] = p
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	p, ok := r.profiles[o.ActiveProfile]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProfile, o.ActiveProfile)
	}
	r.active = p
	now := r.now()
	for k, b := range p.Settings {
		if _, registered := r.defs[k]; registered {
			r.values[k] = Value{Value: b.Default, Source: SourceProfile, UpdatedAt: now, UpdatedBy: "system:settings"}
		}
	}
	if err := r.emit.Emit(ctx, audit.Event{
		Type: "setting.seeded", Severity: audit.SeverityInfo, Actor: "system:settings",
		Target: p.ID, Attributes: map[string]string{"profile_version": p.Version, "settings": fmt.Sprint(len(r.values))},
	}); err != nil {
		return nil, fmt.Errorf("settings: audit seed: %w", err)
	}
	return r, nil
}

// ActiveProfile returns the active profile's ID.
func (r *Registry) ActiveProfile() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active.ID
}

// Get returns the current value of key.
func (r *Registry) Get(key string) (Value, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.values[key]
	if !ok {
		return Value{}, fmt.Errorf("%w: %s", ErrUnknownKey, key)
	}
	return v, nil
}

// Duration is a typed convenience accessor.
func (r *Registry) Duration(key string) (time.Duration, error) {
	v, err := r.Get(key)
	if err != nil {
		return 0, err
	}
	d, ok := v.Value.(time.Duration)
	if !ok {
		return 0, fmt.Errorf("%w: %s is not a duration", ErrType, key)
	}
	return d, nil
}

// Set evaluates and applies a change according to F-015 R-06 and R-08:
//   - weaker than the hard floor → refused and audited
//   - tighter or equal → applied immediately
//   - looser but within the profile bound → applied and audited
//   - looser than the profile bound → explanation required, warning returned,
//     and the change waits for dual approval (see Approve)
func (r *Registry) Set(ctx context.Context, req Request) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	d, ok := r.defs[req.Key]
	if !ok {
		return Result{Outcome: Refused}, fmt.Errorf("%w: %s", ErrUnknownKey, req.Key)
	}
	if err := d.Validate(req.Value); err != nil {
		return Result{Outcome: Refused}, err
	}
	if req.Actor == "" {
		return Result{Outcome: Refused}, errors.New("settings: actor is required")
	}

	if below, err := d.belowFloor(r.active, req.Value); err != nil {
		return Result{Outcome: Refused}, err
	} else if below {
		_ = r.emit.Emit(ctx, audit.Event{
			Type: "setting.hard_floor_refused", Severity: audit.SeverityHigh, Actor: req.Actor,
			Target: req.Key, After: req.Value, Reason: req.Explanation,
		})
		return Result{Outcome: Refused}, fmt.Errorf("%w: %s", ErrHardFloor, req.Key)
	}

	cur := r.values[req.Key]
	bound := r.active.Settings[req.Key]
	vsCurrent, _ := d.Compare(req.Value, cur.Value)
	vsBound, _ := d.Compare(req.Value, bound.Weakest)

	switch {
	case vsCurrent >= 0: // tighten or no-op: immediate (AC-22)
		if vsBound < 0 && cur.ExceptionID != "" {
			// Tighter than the exception but still outside the bound: stays
			// covered by the same exception (same expiry), never uncovered.
			ex := r.exceptions[cur.ExceptionID]
			v := Value{Value: req.Value, Source: SourceException, ExceptionID: cur.ExceptionID}
			if err := r.applyLocked(ctx, d, req, v, audit.SeverityInfo, "setting.changed"); err != nil {
				return Result{}, err
			}
			if ex != nil {
				ex.Value = req.Value
			}
			return Result{Outcome: Applied}, nil
		}
		if err := r.applyLocked(ctx, d, req, Value{Value: req.Value, Source: SourceChange}, audit.SeverityInfo, "setting.changed"); err != nil {
			return Result{}, err
		}
		return Result{Outcome: Applied}, nil

	case vsBound >= 0: // looser, still within bounds (AC-20)
		if err := r.applyLocked(ctx, d, req, Value{Value: req.Value, Source: SourceChange}, audit.SeverityLow, "setting.changed"); err != nil {
			return Result{}, err
		}
		return Result{Outcome: Applied}, nil

	default: // out of bounds: explanation + warning + dual approval (AC-21)
		w := &Warning{
			Key: req.Key, Bound: bound.Weakest, Controls: d.Controls,
			Message: fmt.Sprintf("%s=%v is weaker than the %s bound (%v) and affects %s. It requires a second approver and becomes a time-limited exception.",
				req.Key, req.Value, r.active.Title, bound.Weakest, strings.Join(d.Controls, ", ")),
		}
		if strings.TrimSpace(req.Explanation) == "" {
			return Result{Outcome: Refused, Warning: w}, ErrExplanationRequired
		}
		id := newID()
		r.pending[id] = &pending{id: id, kind: pendingChange, req: req, createdAt: r.now()}
		ev := audit.Event{
			Type: "setting.loosening_requested", Severity: audit.SeverityHigh, Actor: req.Actor,
			Target: req.Key, Before: cur.Value, After: req.Value, Reason: req.Explanation,
			Attributes: map[string]string{"approval_id": id, "controls": strings.Join(d.Controls, ",")},
		}
		if err := r.emit.Emit(ctx, ev); err != nil {
			delete(r.pending, id)
			return Result{}, fmt.Errorf("settings: audit: %w", err)
		}
		return Result{Outcome: PendingApproval, ApprovalID: id, Warning: w}, nil
	}
}

// Approve applies a pending out-of-bounds change (or renewal) as an exception.
// The approver must differ from the requester. expiresIn of zero uses the
// maximum exception duration; longer values are rejected (F-015 AC-24).
func (r *Registry) Approve(ctx context.Context, approvalID, approver string, expiresIn time.Duration) (*Exception, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.pending[approvalID]
	if !ok {
		return nil, ErrNotPending
	}
	if approver == "" || approver == p.req.Actor {
		return nil, ErrSelfApproval
	}
	maxDur, ok := r.values[KeyExceptionMaxDuration].Value.(time.Duration)
	if !ok || maxDur <= 0 {
		maxDur = 90 * day
	}
	if expiresIn == 0 {
		expiresIn = maxDur
	}
	if expiresIn < 0 || expiresIn > maxDur {
		return nil, ErrExpiryTooLong
	}
	d := r.defs[p.req.Key]
	// Re-check the floor at approval time: the active profile may have changed.
	if below, _ := d.belowFloor(r.active, p.req.Value); below {
		delete(r.pending, approvalID)
		return nil, ErrHardFloor
	}

	now := r.now()
	ex := &Exception{
		ID: newID(), Key: p.req.Key, Value: p.req.Value, BoundAtCreate: r.active.Settings[p.req.Key].Weakest,
		Justification: p.req.Explanation, Owner: p.req.Actor, ApprovedBy: approver,
		CreatedAt: now, ExpiresAt: now.Add(expiresIn), State: ExceptionActive,
	}

	if p.kind == pendingRenewal {
		old := r.exceptions[p.exceptionID]
		if old == nil || old.State != ExceptionActive || !now.Before(old.ExpiresAt) {
			delete(r.pending, approvalID)
			return nil, ErrExceptionExpired
		}
		old.State = ExceptionRenewed
		ex.RenewedFrom = old.ID
		ex.Value = old.Value
	}

	prev := r.values[p.req.Key]
	r.values[p.req.Key] = Value{Value: ex.Value, Source: SourceException, ExceptionID: ex.ID, UpdatedAt: now, UpdatedBy: approver}
	r.exceptions[ex.ID] = ex
	delete(r.pending, approvalID)
	var superseded *Exception
	if prev.ExceptionID != "" && prev.ExceptionID != ex.RenewedFrom {
		if old := r.exceptions[prev.ExceptionID]; old != nil && old.State == ExceptionActive {
			old.State = ExceptionSuperseded
			superseded = old
		}
	}

	evType := "setting.exception_created"
	if ex.RenewedFrom != "" {
		evType = "setting.exception_renewed"
	}
	ev := audit.Event{
		Type: evType, Severity: audit.SeverityHigh, Actor: approver, Target: ex.Key,
		Before: prev.Value, After: ex.Value, Reason: ex.Justification,
		Attributes: map[string]string{
			"exception_id": ex.ID, "requested_by": ex.Owner, "expires_at": ex.ExpiresAt.Format(time.RFC3339),
			"renewed_from": ex.RenewedFrom,
		},
	}
	if err := r.emit.Emit(ctx, ev); err != nil {
		// Fail closed: roll back if the audit record cannot be written.
		r.values[p.req.Key] = prev
		delete(r.exceptions, ex.ID)
		if superseded != nil {
			superseded.State = ExceptionActive
		}
		if ex.RenewedFrom != "" {
			r.exceptions[ex.RenewedFrom].State = ExceptionActive
		}
		r.pending[approvalID] = p
		return nil, fmt.Errorf("settings: audit: %w", err)
	}
	r.notifySecOpsLocked(ctx, ev)
	return ex, nil
}

// Reject discards a pending request.
func (r *Registry) Reject(ctx context.Context, approvalID, approver, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[approvalID]
	if !ok {
		return ErrNotPending
	}
	delete(r.pending, approvalID)
	return r.emit.Emit(ctx, audit.Event{
		Type: "setting.loosening_rejected", Severity: audit.SeverityLow, Actor: approver,
		Target: p.req.Key, Reason: reason, Attributes: map[string]string{"approval_id": approvalID, "requested_by": p.req.Actor},
	})
}

// RequestRenewal asks to renew an active exception before it expires (F-015 AC-26).
func (r *Registry) RequestRenewal(ctx context.Context, exceptionID, actor, justification string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ex, ok := r.exceptions[exceptionID]
	if !ok || ex.State != ExceptionActive {
		return "", ErrNotPending
	}
	if !r.now().Before(ex.ExpiresAt) {
		return "", ErrExceptionExpired
	}
	if strings.TrimSpace(justification) == "" {
		return "", ErrExplanationRequired
	}
	id := newID()
	r.pending[id] = &pending{
		id: id, kind: pendingRenewal, exceptionID: exceptionID, createdAt: r.now(),
		req: Request{Key: ex.Key, Value: ex.Value, Actor: actor, Explanation: justification},
	}
	if err := r.emit.Emit(ctx, audit.Event{
		Type: "setting.exception_renewal_requested", Severity: audit.SeverityHigh, Actor: actor,
		Target: ex.Key, Reason: justification, Attributes: map[string]string{"exception_id": exceptionID, "approval_id": id},
	}); err != nil {
		delete(r.pending, id)
		return "", err
	}
	return id, nil
}

// ExpireExceptions reverts every active exception whose expiry has passed to
// the active profile's default (F-015 AC-27). It returns the reverted exceptions.
// The posture service runs this on a schedule; failures surface as errors so the
// caller can raise a critical drift finding (AC-29).
func (r *Registry) ExpireExceptions(ctx context.Context) ([]Exception, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []Exception
	var errs []error
	for _, ex := range r.sortedExceptionsLocked() {
		if ex.State != ExceptionActive || now.Before(ex.ExpiresAt) {
			continue
		}
		prev := r.values[ex.Key]
		def := r.active.Settings[ex.Key].Default
		r.values[ex.Key] = Value{Value: def, Source: SourceRevert, UpdatedAt: now, UpdatedBy: "system:settings"}
		ex.State = ExceptionReverted
		err := r.emit.Emit(ctx, audit.Event{
			Type: "setting.exception_reverted", Severity: audit.SeverityHigh, Actor: "system:settings",
			Target: ex.Key, Before: prev.Value, After: def,
			Attributes: map[string]string{"exception_id": ex.ID, "owner": ex.Owner},
		})
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, *ex)
	}
	return out, errors.Join(errs...)
}

// ExpiringWithin lists active exceptions expiring within d (for 14/7/1-day notices).
func (r *Registry) ExpiringWithin(d time.Duration) []Exception {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []Exception
	for _, ex := range r.sortedExceptionsLocked() {
		if ex.State == ExceptionActive && now.Before(ex.ExpiresAt) && ex.ExpiresAt.Sub(now) <= d {
			out = append(out, *ex)
		}
	}
	return out
}

// Exception returns an exception by ID.
func (r *Registry) Exception(id string) (Exception, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ex, ok := r.exceptions[id]
	if !ok {
		return Exception{}, false
	}
	return *ex, true
}

func (r *Registry) applyLocked(ctx context.Context, d Def, req Request, v Value, sev audit.Severity, evType string) error {
	prev := r.values[req.Key]
	v.UpdatedAt, v.UpdatedBy = r.now(), req.Actor
	r.values[req.Key] = v

	// A change that moves the value back inside the bound supersedes the exception.
	if prev.ExceptionID != "" && v.ExceptionID != prev.ExceptionID {
		if ex := r.exceptions[prev.ExceptionID]; ex != nil && ex.State == ExceptionActive {
			ex.State = ExceptionSuperseded
		}
	}
	ev := audit.Event{
		Type: evType, Severity: sev, Actor: req.Actor, Target: req.Key,
		Before: prev.Value, After: req.Value, Reason: req.Explanation,
		Attributes: map[string]string{"controls": strings.Join(d.Controls, ",")},
	}
	if err := r.emit.Emit(ctx, ev); err != nil {
		r.values[req.Key] = prev // fail closed
		return fmt.Errorf("settings: audit: %w", err)
	}
	if sev != audit.SeverityInfo { // weakening
		r.notifySecOpsLocked(ctx, ev)
	}
	return nil
}

func (r *Registry) notifySecOpsLocked(ctx context.Context, e audit.Event) {
	if r.saas && r.secops != nil {
		r.secops(ctx, e)
	}
}

func (r *Registry) sortedExceptionsLocked() []*Exception {
	out := make([]*Exception, 0, len(r.exceptions))
	for _, ex := range r.exceptions {
		out = append(out, ex)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

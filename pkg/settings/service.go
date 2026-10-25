package settings

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// Source records where a setting's current value came from.
type Source string

const (
	SourceProfile   Source = "profile"
	SourceChange    Source = "change"
	SourceException Source = "exception"
	SourceRevert    Source = "revert"
)

// Outcome of a Set call.
type Outcome string

const (
	// Applied: tightening or no-op; applied and audited.
	Applied Outcome = "applied"
	// AppliedWithWarning: loosening within the profile bounds; applied,
	// high-severity audit event, posture flag.
	AppliedWithWarning Outcome = "applied_with_warning"
	// PendingApproval: loosening outside bounds (or a key that always needs
	// dual approval); nothing changes until a second admin approves.
	PendingApproval Outcome = "pending_approval"
	// Refused: would weaken a hard-floor setting.
	Refused Outcome = "refused"
	// Unchanged: the value equals the current value.
	Unchanged Outcome = "unchanged"
)

// Errors returned by Set and Approve.
var (
	ErrUnknownKey     = errors.New("settings: unknown setting")
	ErrHardFloor      = errors.New("settings: value weakens a hard-floor setting")
	ErrReasonRequired = errors.New("settings: a reason is required to loosen a setting")
	ErrStaleApproval  = errors.New("settings: setting changed since the approval was requested")
	ErrNotAUser       = errors.New("settings: changes must be made by an identified user")
)

// Warning is shown to the admin when a change loosens security.
type Warning struct {
	Message  string
	Controls []string
	Bound    string
}

// SetRequest asks to change a setting.
type SetRequest struct {
	Key       string
	Value     string
	Reason    string
	Actor     audit.Actor
	RequestID string
}

// Result describes what Set or Approve did.
type Result struct {
	Outcome    Outcome
	Key        string
	Old, New   string
	Warning    *Warning
	ApprovalID string
	// ExceptionExpires is set when the change was applied as an exception.
	ExceptionExpires time.Time
}

// State is the current view of one setting (feeds the Posture page later).
type State struct {
	Key              string
	Value            string
	Default          string
	Bound            string
	Floor            string
	Source           Source
	OutOfProfile     bool // value weaker than the profile default (posture flag)
	Exception        bool // value weaker than the bound, held by an approved exception
	ExceptionExpires time.Time
	Controls         []string
}

type entry struct {
	value            string
	source           Source
	exceptionExpires time.Time
}

// Config builds a Service.
type Config struct {
	Profile   Profile
	Defs      []Def
	Audit     audit.Emitter
	Approvals Approvals
	// Clock defaults to time.Now.
	Clock func() time.Time
	// ExceptionTTL defaults to 90 days (ADR-006 Amendment 1).
	ExceptionTTL time.Duration
	// ApprovalTTL defaults to 72 hours (F-001 design §5.5).
	ApprovalTTL time.Duration
}

// Service is the Phase 0 settings module.
type Service struct {
	profile      Profile
	defs         map[string]Def
	audit        audit.Emitter
	approvals    Approvals
	clock        func() time.Time
	exceptionTTL time.Duration
	approvalTTL  time.Duration

	mu        sync.RWMutex
	values    map[string]entry
	listeners []func(key, value string)
}

var systemActor = audit.Actor{Kind: audit.ActorSystem, ID: "system:settings"}

// New validates the definitions against the profile and seeds every setting
// from it. A registered key with no profile value is a startup error
// (F-015 design §6.1).
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Audit == nil {
		return nil, errors.New("settings: an audit emitter is required")
	}
	if cfg.Approvals == nil {
		cfg.Approvals = NewMemoryApprovals()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.ExceptionTTL == 0 {
		cfg.ExceptionTTL = 90 * 24 * time.Hour
	}
	if cfg.ApprovalTTL == 0 {
		cfg.ApprovalTTL = 72 * time.Hour
	}
	s := &Service{
		profile: cfg.Profile, defs: map[string]Def{}, audit: cfg.Audit, approvals: cfg.Approvals,
		clock: cfg.Clock, exceptionTTL: cfg.ExceptionTTL, approvalTTL: cfg.ApprovalTTL,
		values: map[string]entry{},
	}
	var errs []error
	for _, d := range cfg.Defs {
		if err := d.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := s.defs[d.Key]; dup {
			errs = append(errs, fmt.Errorf("settings: %s registered twice", d.Key))
			continue
		}
		pv, ok := cfg.Profile.Values[d.Key]
		if !ok {
			errs = append(errs, fmt.Errorf("settings: %s has no value in profile %s", d.Key, cfg.Profile.ID))
			continue
		}
		def, err1 := d.Normalize(pv.Default)
		bound, err2 := d.Normalize(pv.Bound)
		if err := errors.Join(err1, err2); err != nil {
			errs = append(errs, fmt.Errorf("settings: profile %s: %w", cfg.Profile.ID, err))
			continue
		}
		if d.Weaker(def, bound) {
			errs = append(errs, fmt.Errorf("settings: profile %s: %s default %s is weaker than its bound %s", cfg.Profile.ID, d.Key, def, bound))
		}
		if f := s.floorFor(d, pv); f != "" && d.Weaker(bound, f) {
			errs = append(errs, fmt.Errorf("settings: profile %s: %s bound %s is below the hard floor %s", cfg.Profile.ID, d.Key, bound, f))
		}
		s.defs[d.Key] = d
		s.values[d.Key] = entry{value: def, source: SourceProfile}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	e := audit.New("setting.seeded", audit.SeverityInfo, audit.OutcomeSuccess, systemActor,
		audit.Target{Kind: "profile", ID: cfg.Profile.ID})
	e.After = audit.JSON(s.snapshot())
	if err := s.audit.Emit(ctx, e); err != nil {
		return nil, fmt.Errorf("settings: audit seed: %w", err)
	}
	return s, nil
}

func (s *Service) floorFor(d Def, pv Value) string {
	switch {
	case d.Floor == "" && pv.Floor == "":
		return ""
	case d.Floor == "":
		f, _ := d.Normalize(pv.Floor)
		return f
	case pv.Floor == "":
		return d.Floor
	}
	f, _ := d.Normalize(pv.Floor)
	return d.Strictest(d.Floor, f)
}

func (s *Service) snapshot() map[string]string {
	out := make(map[string]string, len(s.values))
	for k, v := range s.values {
		out[k] = v.value
	}
	return out
}

// Profile returns the active profile ID.
func (s *Service) Profile() string { return s.profile.ID }

// OnChange registers a callback invoked (synchronously, after the lock is
// released) whenever a value changes. Services use it to invalidate caches.
func (s *Service) OnChange(fn func(key, value string)) {
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

// Get returns a setting's current value.
func (s *Service) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.values[key]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownKey, key)
	}
	return e.value, nil
}

// Duration is Get for duration settings.
func (s *Service) Duration(key string) (time.Duration, error) {
	v, err := s.Get(key)
	if err != nil {
		return 0, err
	}
	return time.ParseDuration(v)
}

// Bool is Get for bool settings.
func (s *Service) Bool(key string) (bool, error) {
	v, err := s.Get(key)
	if err != nil {
		return false, err
	}
	return v == "true", nil
}

// States returns every setting's state, sorted by key.
func (s *Service) States() []State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]State, 0, len(s.values))
	for k, e := range s.values {
		d := s.defs[k]
		pv := s.profile.Values[k]
		def, _ := d.Normalize(pv.Default)
		bound, _ := d.Normalize(pv.Bound)
		out = append(out, State{
			Key: k, Value: e.value, Default: def, Bound: bound, Floor: s.floorFor(d, pv),
			Source: e.source, OutOfProfile: d.Weaker(e.value, def), Exception: d.Weaker(e.value, bound),
			ExceptionExpires: e.exceptionExpires, Controls: d.Controls,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// PostureFlags returns the settings that are weaker than their profile
// default: what the Security Posture page (F-015) will list.
func (s *Service) PostureFlags() []State {
	var out []State
	for _, st := range s.States() {
		if st.OutOfProfile {
			out = append(out, st)
		}
	}
	return out
}

func (s *Service) emit(ctx context.Context, typ string, sev audit.Severity, outcome audit.Outcome, actor audit.Actor, key, reason, requestID string, before, after any, attrs map[string]string) error {
	e := audit.New(typ, sev, outcome, actor, audit.Target{Kind: "setting", ID: key})
	e.Reason = reason
	e.RequestID = requestID
	if before != nil {
		e.Before = audit.JSON(before)
	}
	if after != nil {
		e.After = audit.JSON(after)
	}
	e.Attributes = attrs
	return s.audit.Emit(ctx, e)
}

func (s *Service) notify(key, value string) {
	s.mu.RLock()
	ls := append([]func(string, string){}, s.listeners...)
	s.mu.RUnlock()
	for _, fn := range ls {
		fn(key, value)
	}
}

// Set changes a setting, routing it down one of the ADR-006 paths:
//
//	weaker than the hard floor          -> Refused (high-severity audit)
//	tighter than current                -> Applied immediately
//	looser, within profile bounds       -> AppliedWithWarning (reason, high audit, posture flag)
//	looser, outside bounds (or a key
//	that always needs dual approval)    -> PendingApproval (reason, warning, dual approval)
//
// Audit delivery failure fails the change: nothing is applied unaudited.
func (s *Service) Set(ctx context.Context, req SetRequest) (Result, error) {
	d, ok := s.defs[req.Key]
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownKey, req.Key)
	}
	if req.Actor.Kind != audit.ActorUser || req.Actor.ID == "" {
		return Result{}, ErrNotAUser
	}
	newVal, err := d.Normalize(req.Value)
	if err != nil {
		return Result{}, err
	}
	pv := s.profile.Values[req.Key]
	bound, _ := d.Normalize(pv.Bound)
	floor := s.floorFor(d, pv)

	s.mu.Lock()
	cur := s.values[req.Key]
	res := Result{Key: req.Key, Old: cur.value, New: newVal}
	attrs := map[string]string{"profile": s.profile.ID, "bound": bound}

	// 1. Hard floor.
	if floor != "" && d.Weaker(newVal, floor) {
		s.mu.Unlock()
		res.Outcome = Refused
		attrs["floor"] = floor
		if err := s.emit(ctx, "setting.hard_floor_refused", audit.SeverityHigh, audit.OutcomeDenied, req.Actor,
			req.Key, req.Reason, req.RequestID, map[string]string{"value": cur.value}, map[string]string{"value": newVal}, attrs); err != nil {
			return res, errors.Join(ErrHardFloor, err)
		}
		return res, fmt.Errorf("%w: %s cannot be weaker than %s", ErrHardFloor, req.Key, floor)
	}

	cmp := d.Compare(newVal, cur.value)
	switch {
	case cmp == 0:
		s.mu.Unlock()
		res.Outcome = Unchanged
		return res, nil

	case cmp > 0: // 2. Tighten: immediate.
		if err := s.emit(ctx, "setting.changed", audit.SeverityInfo, audit.OutcomeSuccess, req.Actor,
			req.Key, req.Reason, req.RequestID, map[string]string{"value": cur.value}, map[string]string{"value": newVal},
			with(attrs, "direction", "tighten")); err != nil {
			s.mu.Unlock()
			return res, fmt.Errorf("settings: audit failed, change not applied: %w", err)
		}
		src := SourceChange
		var exp time.Time
		if d.Weaker(newVal, bound) && cur.source == SourceException {
			src, exp = SourceException, cur.exceptionExpires // still out of bounds: keep the exception clock
		}
		s.values[req.Key] = entry{value: newVal, source: src, exceptionExpires: exp}
		s.mu.Unlock()
		s.notify(req.Key, newVal)
		res.Outcome = Applied
		return res, nil
	}

	// Loosening from here on.
	if strings.TrimSpace(req.Reason) == "" {
		s.mu.Unlock()
		return res, ErrReasonRequired
	}
	outOfBounds := d.Weaker(newVal, bound)
	if outOfBounds || d.AlwaysDualApproveLoosen {
		// 4. Dual approval.
		s.mu.Unlock()
		msg := fmt.Sprintf("Loosening %s from %s to %s requires approval by a second administrator.", req.Key, cur.value, newVal)
		if outOfBounds {
			msg = fmt.Sprintf("%s to %s is outside the %s bound (%s). It weakens %s and needs approval by a second administrator; if approved it becomes an exception that expires after %s.",
				req.Key, newVal, s.profile.Title, bound, strings.Join(d.Controls, ", "), s.exceptionTTL)
		}
		res.Warning = &Warning{Message: msg, Controls: d.Controls, Bound: bound}
		now := s.clock()
		ar, err := s.approvals.Create(ctx, ApprovalRequest{
			Kind: "setting.loosen", Target: req.Key, Reason: req.Reason, RequestedBy: req.Actor,
			Payload:   map[string]string{"old": cur.value, "new": newVal, "out_of_bounds": fmt.Sprint(outOfBounds)},
			CreatedAt: now, ExpiresAt: now.Add(s.approvalTTL),
		})
		if err != nil {
			return res, fmt.Errorf("settings: create approval: %w", err)
		}
		res.ApprovalID = ar.ID
		if err := s.emit(ctx, "setting.loosen_requested", audit.SeverityHigh, audit.OutcomePending, req.Actor,
			req.Key, req.Reason, req.RequestID, map[string]string{"value": cur.value}, map[string]string{"value": newVal},
			with(with(attrs, "approval_id", ar.ID), "out_of_bounds", fmt.Sprint(outOfBounds))); err != nil {
			return res, fmt.Errorf("settings: audit failed: %w", err)
		}
		res.Outcome = PendingApproval
		return res, nil
	}

	// 3. Loosen within bounds: apply with warning.
	if err := s.emit(ctx, "setting.loosened", audit.SeverityHigh, audit.OutcomeSuccess, req.Actor,
		req.Key, req.Reason, req.RequestID, map[string]string{"value": cur.value}, map[string]string{"value": newVal},
		with(attrs, "direction", "loosen")); err != nil {
		s.mu.Unlock()
		return res, fmt.Errorf("settings: audit failed, change not applied: %w", err)
	}
	s.values[req.Key] = entry{value: newVal, source: SourceChange}
	s.mu.Unlock()
	s.notify(req.Key, newVal)
	res.Outcome = AppliedWithWarning
	res.Warning = &Warning{
		Message:  fmt.Sprintf("%s loosened from %s to %s. This is within the %s bound but weaker than its default and will be shown on the Security Posture page.", req.Key, cur.value, newVal, s.profile.Title),
		Controls: d.Controls, Bound: bound,
	}
	return res, nil
}

// Approve applies a pending loosening after a second administrator approves.
// Out-of-bounds values become exceptions that expire (default 90 days).
func (s *Service) Approve(ctx context.Context, approvalID string, approver audit.Actor, requestID string) (Result, error) {
	ar, err := s.approvals.Get(ctx, approvalID)
	if err != nil {
		return Result{}, err
	}
	d, ok := s.defs[ar.Target]
	if !ok || ar.Kind != "setting.loosen" {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownKey, ar.Target)
	}
	now := s.clock()
	s.mu.Lock()
	cur := s.values[ar.Target]
	res := Result{Key: ar.Target, Old: ar.Payload["old"], New: ar.Payload["new"], ApprovalID: approvalID}
	if cur.value != ar.Payload["old"] {
		s.mu.Unlock()
		return res, ErrStaleApproval
	}
	ar, err = s.approvals.Decide(ctx, approvalID, approver, true, now)
	if err != nil {
		s.mu.Unlock()
		_ = s.emit(ctx, "approval.denied", audit.SeverityHigh, audit.OutcomeDenied, approver, ar.Target, err.Error(), requestID,
			nil, nil, map[string]string{"approval_id": approvalID, "requested_by": ar.RequestedBy.ID})
		return res, err
	}
	pv := s.profile.Values[ar.Target]
	bound, _ := d.Normalize(pv.Bound)
	if f := s.floorFor(d, pv); f != "" && d.Weaker(res.New, f) { // defence in depth
		s.mu.Unlock()
		return res, ErrHardFloor
	}
	attrs := map[string]string{"approval_id": approvalID, "requested_by": ar.RequestedBy.ID, "approved_by": approver.ID, "profile": s.profile.ID, "bound": bound}
	next := entry{value: res.New, source: SourceChange}
	typ := "setting.loosened"
	if d.Weaker(res.New, bound) {
		next.source = SourceException
		next.exceptionExpires = now.Add(s.exceptionTTL)
		res.ExceptionExpires = next.exceptionExpires
		attrs["exception_expires"] = next.exceptionExpires.UTC().Format(time.RFC3339)
		typ = "setting.exception_created"
	}
	if err := s.emit(ctx, typ, audit.SeverityHigh, audit.OutcomeSuccess, approver, ar.Target, ar.Reason, requestID,
		map[string]string{"value": res.Old}, map[string]string{"value": res.New}, attrs); err != nil {
		s.mu.Unlock()
		return res, fmt.Errorf("settings: audit failed, change not applied: %w", err)
	}
	s.values[ar.Target] = next
	s.mu.Unlock()
	s.notify(ar.Target, res.New)
	res.Outcome = AppliedWithWarning
	return res, nil
}

// Reject records a rejection of a pending loosening.
func (s *Service) Reject(ctx context.Context, approvalID string, approver audit.Actor, reason, requestID string) error {
	ar, err := s.approvals.Decide(ctx, approvalID, approver, false, s.clock())
	if err != nil {
		return err
	}
	return s.emit(ctx, "setting.loosen_rejected", audit.SeverityMedium, audit.OutcomeDenied, approver, ar.Target, reason, requestID,
		nil, nil, map[string]string{"approval_id": approvalID, "requested_by": ar.RequestedBy.ID})
}

// RevertExpired reverts every exception whose expiry has passed to the
// profile default (ADR-006 Amendment 1). It returns the keys reverted.
// F-015 runs this from a scheduled job with retries; Phase 0 exposes it so
// iam can call it on a ticker.
func (s *Service) RevertExpired(ctx context.Context) ([]string, error) {
	now := s.clock()
	var reverted []string
	var errs []error
	s.mu.Lock()
	for k, e := range s.values {
		if e.source != SourceException || now.Before(e.exceptionExpires) {
			continue
		}
		d := s.defs[k]
		def, _ := d.Normalize(s.profile.Values[k].Default)
		if err := s.emit(ctx, "setting.exception_reverted", audit.SeverityHigh, audit.OutcomeSuccess, systemActor, k,
			"exception expired", "", map[string]string{"value": e.value}, map[string]string{"value": def},
			map[string]string{"expired_at": e.exceptionExpires.UTC().Format(time.RFC3339)}); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue // stays out of bounds; retried next run
		}
		s.values[k] = entry{value: def, source: SourceRevert}
		reverted = append(reverted, k)
	}
	s.mu.Unlock()
	sort.Strings(reverted)
	for _, k := range reverted {
		v, _ := s.Get(k)
		s.notify(k, v)
	}
	return reverted, errors.Join(errs...)
}

func with(m map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

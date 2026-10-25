package settings

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// Approval states.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
)

// ApprovalRequest mirrors F-001's iam.approval_request row.
type ApprovalRequest struct {
	ID          string
	Kind        string // e.g. "setting.loosen"
	Target      string // setting key
	Payload     map[string]string
	Reason      string
	RequestedBy audit.Actor
	Status      string
	DecidedBy   audit.Actor
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Errors from the approvals engine.
var (
	ErrSelfApproval     = errors.New("settings: approver must differ from requester")
	ErrApprovalNotFound = errors.New("settings: approval request not found")
	ErrApprovalDecided  = errors.New("settings: approval request already decided")
	ErrApprovalExpired  = errors.New("settings: approval request expired")
)

// Approvals is the dual-approval engine interface. F-001 T-26 implements it
// in iam (with a DB CHECK decided_by <> requested_by); this package ships an
// in-memory implementation for Phase 0.
type Approvals interface {
	Create(ctx context.Context, r ApprovalRequest) (ApprovalRequest, error)
	Get(ctx context.Context, id string) (ApprovalRequest, error)
	// Decide records a decision. It must refuse when approver == requester.
	Decide(ctx context.Context, id string, approver audit.Actor, approve bool, now time.Time) (ApprovalRequest, error)
}

// MemoryApprovals is an in-memory Approvals.
type MemoryApprovals struct {
	mu   sync.Mutex
	reqs map[string]ApprovalRequest
}

// NewMemoryApprovals returns an empty engine.
func NewMemoryApprovals() *MemoryApprovals {
	return &MemoryApprovals{reqs: map[string]ApprovalRequest{}}
}

// Create implements Approvals.
func (m *MemoryApprovals) Create(_ context.Context, r ApprovalRequest) (ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = audit.NewID()
	r.Status = ApprovalPending
	m.reqs[r.ID] = r
	return r, nil
}

// Get implements Approvals.
func (m *MemoryApprovals) Get(_ context.Context, id string) (ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return ApprovalRequest{}, ErrApprovalNotFound
	}
	return r, nil
}

// Decide implements Approvals.
func (m *MemoryApprovals) Decide(_ context.Context, id string, approver audit.Actor, approve bool, now time.Time) (ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return ApprovalRequest{}, ErrApprovalNotFound
	}
	if r.Status != ApprovalPending {
		return r, ErrApprovalDecided
	}
	if !now.Before(r.ExpiresAt) {
		r.Status = ApprovalExpired
		m.reqs[id] = r
		return r, ErrApprovalExpired
	}
	if approver.Kind != audit.ActorUser || approver.ID == "" || approver.ID == r.RequestedBy.ID {
		return r, ErrSelfApproval
	}
	r.DecidedBy = approver
	if approve {
		r.Status = ApprovalApproved
	} else {
		r.Status = ApprovalRejected
	}
	m.reqs[id] = r
	return r, nil
}

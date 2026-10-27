package tests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-26 (AC-30, AC-41, AC-53, AC-63): the dual-approval engine.

// approvalsFixture: the assignment fixture plus a second Platform Admin, a BU
// Admin and an analyst with scope, and context key k1.
func approvalsFixture(t *testing.T) (*env, approvals.Service) {
	e := assignmentFixture(t)
	e.mustOwner(grant("platform", "user:platform2", "Platform Admin", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:buadmin", "BU Admin", "A"))
	e.mustOwner(grant("platform", "user:analyst", "Risk Analyst", "A"))
	e.drain()
	e.addCtxKey(ctxKey1)
	return e, approvals.Service{DB: e.appPool()}
}

func auditTypes(e *env, target string) string {
	return e.adminQuery(`SELECT coalesce(string_agg(payload->>'type' || ':' || (payload->>'severity'), ',' ORDER BY id), '')
		FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'target' = 'approval:` + target + `'`)
}

func TestApprovalLifecycle(t *testing.T) {
	e, svc := approvalsFixture(t)
	ctx := context.Background()
	analyst, buadmin, platform := e.principal("analyst"), e.principal("buadmin"), e.principal("platform")

	id, err := svc.Request(ctx, analyst, approvals.NewRequest{Kind: approvals.KindSettingsOutOfBounds, TargetRef: "change:42",
		Reason: "pilot needs 10 lockout attempts", Payload: []byte(`{"key": "auth.lockout_threshold", "value": 10}`)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.Get(ctx, analyst, id)
	if err != nil || r.Status != approvals.Pending || r.RequestedBy != analyst.UserID || r.ExpiresAt.Sub(r.CreatedAt).Hours() != 72 {
		t.Fatalf("requester's view %+v, %v", r, err)
	}
	// Someone who is neither requester nor approver cannot see it (AC-25 style).
	if _, err := svc.Get(ctx, buadmin, id); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("bystander get: %v", err)
	}

	// Self-approval: refused by the API, and by the database when the API is bypassed.
	if _, err := svc.Decide(ctx, analyst, id, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self-approval through the API: %v", err)
	}
	if out, err := e.asCtx(analyst.DBToken, "SELECT iam.decide_approval('"+id+"', true)"); err == nil || !strings.Contains(out, "different person") {
		t.Fatalf("self-approval in the database: %q %v", out, err)
	}
	// Without the kind's permission.
	if _, err := svc.Decide(ctx, buadmin, id, true, ""); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("non-approver decide: %v", err) // cannot even see it
	}
	if out, err := e.asCtx(buadmin.DBToken, "SELECT iam.decide_approval('"+id+"', true)"); err == nil || !strings.Contains(out, "may not decide") {
		t.Fatalf("non-approver in the database: %q %v", out, err)
	}

	st, err := svc.Decide(ctx, platform, id, true, "")
	if err != nil || st != approvals.Approved {
		t.Fatalf("approve: %v %v", st, err)
	}
	if _, err := svc.Decide(ctx, platform, id, false, "changed my mind"); !errors.Is(err, approvals.ErrNotApplicable) {
		t.Fatalf("second decision: %v", err)
	}
	if got := auditTypes(e, id); got != "approval.requested:info,approval.approved:high" {
		t.Fatalf("audit trail %s", got)
	}
	if got := e.adminQuery(`SELECT (payload->'attributes'->>'decided_by') = '` + platform.UserID + `' FROM iam.event_outbox WHERE payload->>'type' = 'approval.approved'`); got != "t" {
		t.Fatalf("approval audit does not name the approver: %s", got)
	}

	// Consumed exactly once, by exactly the approved kind and target.
	for _, bad := range []string{
		"SELECT iam.consume_approval('" + id + "', 'settings.out_of_bounds', 'change:43')",
		"SELECT iam.consume_approval('" + id + "', 'bu.unrestrict', 'change:42')",
	} {
		if state := e.adminState("PERFORM " + strings.TrimPrefix(bad, "SELECT ")); state != "AP004" {
			t.Errorf("%s: %s", bad, state)
		}
	}
	// Since F-015 T-14, consume returns the payload with requester and approver.
	got := e.adminQuery("SELECT (r->'payload'->>'value') || ':' || (r->>'requested_by' = '" + analyst.UserID + "') || ':' || (r->>'decided_by' = '" + platform.UserID + "') FROM iam.consume_approval('" + id + "', 'settings.out_of_bounds', 'change:42') r")
	if got != "10:true:true" {
		t.Fatalf("consume returned %s", got)
	}
	if state := e.adminState("PERFORM iam.consume_approval('" + id + "', 'settings.out_of_bounds', 'change:42')"); state != "AP004" {
		t.Fatalf("second consume: %s", state)
	}
	if got := auditTypes(e, id); got != "approval.requested:info,approval.approved:high,approval.consumed:info" {
		t.Fatalf("audit trail %s", got)
	}
	// Application roles cannot consume an approval directly, nor touch the tables.
	e.wantState("app_rw", "PERFORM iam.consume_approval('"+id+"', 'settings.out_of_bounds', 'change:42')", "42501")
	e.wantState("app_rw", "PERFORM 1 FROM iam.approval_request", "42501")
	e.wantState("app_rw", "UPDATE iam.approval_request SET status = 'approved'", "42501")
	e.wantState("app_rw", "UPDATE iam.approval_kind SET approve_permission = 'bu.view'", "42501")
}

// A Platform Admin's own request needs the other Platform Admin; a
// rejection needs a reason.
func TestApprovalSecondAdmin(t *testing.T) {
	e, svc := approvalsFixture(t)
	ctx := context.Background()
	platform, platform2 := e.principal("platform"), e.principal("platform2")
	id, err := svc.Request(ctx, platform, approvals.NewRequest{Kind: approvals.KindBUUnrestrict, TargetRef: "bu:R", Reason: "merger"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, platform, id, true, ""); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("own request: %v", err)
	}
	if _, err := svc.Decide(ctx, platform2, id, false, " "); !errors.Is(err, approvals.ErrInvalid) {
		t.Fatalf("rejection without reason: %v", err)
	}
	if st, err := svc.Decide(ctx, platform2, id, false, "not before the audit"); err != nil || st != approvals.Rejected {
		t.Fatalf("reject: %v %v", st, err)
	}
	if state := e.adminState("PERFORM iam.consume_approval('" + id + "', 'bu.unrestrict', 'bu:R')"); state != "AP004" {
		t.Fatalf("consumed a rejected request: %s", state)
	}
	// The table's own check stops self-approval even past the functions.
	if err := e.psqlAs(nil, e.db, "UPDATE iam.approval_request SET status = 'approved', decided_by = requested_by, decided_at = now() WHERE id = '"+id+"'"); err == nil {
		t.Fatal("the table accepted decided_by = requested_by")
	}
}

// Requests expire (72 h by default, configurable per kind); expired ones
// cannot be decided or used.
func TestApprovalExpiry(t *testing.T) {
	e, svc := approvalsFixture(t)
	ctx := context.Background()
	analyst, platform := e.principal("analyst"), e.principal("platform")
	pending, err := svc.Request(ctx, analyst, approvals.NewRequest{Kind: approvals.KindSettingsOutOfBounds, TargetRef: "change:1", Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	approved, _ := svc.Request(ctx, analyst, approvals.NewRequest{Kind: approvals.KindSettingsOutOfBounds, TargetRef: "change:2", Reason: "r"})
	if _, err := svc.Decide(ctx, platform, approved, true, ""); err != nil {
		t.Fatal(err)
	}
	// Time passes: move both requests 73 hours into the past.
	e.admin(e.db, "UPDATE iam.approval_request SET created_at = created_at - interval '73 hours', expires_at = expires_at - interval '73 hours'")

	if _, err := svc.Decide(ctx, platform, pending, true, ""); !errors.Is(err, approvals.ErrNotApplicable) {
		t.Fatalf("deciding an expired request: %v", err)
	}
	if state := e.adminState("PERFORM iam.consume_approval('" + approved + "', 'settings.out_of_bounds', 'change:2')"); state != "AP004" {
		t.Fatalf("consumed an expired approval: %s", state)
	}
	if n, err := approvals.ExpireDue(ctx, e.appPool()); err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1 (the approved one keeps its decision)", n, err)
	}
	if got := e.adminQuery("SELECT string_agg(target_ref || '=' || status, ',' ORDER BY target_ref) FROM iam.approval_request"); got != "change:1=expired,change:2=approved" {
		t.Fatalf("statuses %s", got)
	}
	if got := auditTypes(e, pending); !strings.HasSuffix(got, "approval.expired:info") {
		t.Fatalf("expiry not audited: %s", got)
	}

	// The window is configurable per kind.
	e.mustOwner("UPDATE iam.approval_kind SET ttl = interval '4 hours' WHERE kind = 'breakglass.enable'")
	id, _ := svc.Request(ctx, platform, approvals.NewRequest{Kind: approvals.KindBreakGlassEnable, TargetRef: "breakglass", Reason: "IdP outage"})
	if got := e.adminQuery("SELECT expires_at - created_at FROM iam.approval_request WHERE id = '" + id + "'"); got != "04:00:00" {
		t.Fatalf("configured window %s", got)
	}
}

func TestApprovalNeedsSignedContext(t *testing.T) {
	e, svc := approvalsFixture(t)
	ctx := context.Background()
	req := approvals.NewRequest{Kind: approvals.KindSoDException, TargetRef: "role:x", Reason: "r"}
	if _, err := svc.Request(ctx, authz.Principal{}, req); !errors.Is(err, approvals.ErrNoContext) {
		t.Fatalf("no token: %v", err)
	}
	forged := e.principal("analyst")
	forged.DBToken = forged.DBToken[:len(forged.DBToken)-4] + "0000"
	if _, err := svc.Request(ctx, forged, req); !errors.Is(err, approvals.ErrNoContext) {
		t.Fatalf("forged token: %v", err)
	}
	// A disabled user's still-valid token is refused.
	p := e.principal("analyst")
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'analyst@example.test'")
	if _, err := svc.Request(ctx, p, req); !errors.Is(err, approvals.ErrNoContext) {
		t.Fatalf("disabled user: %v", err)
	}
	for _, bad := range []approvals.NewRequest{
		{Kind: "no.such_kind", TargetRef: "x", Reason: "r"},
		{Kind: approvals.KindSoDException, TargetRef: "x", Reason: "  "},
		{Kind: approvals.KindSoDException, TargetRef: "", Reason: "r"},
	} {
		if _, err := svc.Request(ctx, e.principal("platform"), bad); !errors.Is(err, approvals.ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

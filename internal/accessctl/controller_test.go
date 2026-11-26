package accessctl

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
)

const (
	acme    = "777777777777"
	globex  = "888888888888"
	alice   = "9067a1b2c3-11111111-1111-1111-1111-111111111111"
	bob     = "9067a1b2c3-22222222-2222-2222-2222-222222222222"
	carol   = "9067a1b2c3-33333333-3333-3333-3333-333333333333"
	viewARN = "arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
)

type harness struct {
	t     *testing.T
	d     *Dir
	w     *world
	clk   *clock
	recs  *bytes.Buffer
	c     *Controller
	psOp  string
	psRO  string
	entry func(account, role string) string
}

func newHarness(t *testing.T, now string) *harness {
	t.Helper()
	d := testDir(t)
	w := newWorld(d)
	h := &harness{t: t, d: d, w: w, clk: &clock{t: at(now)}, recs: &bytes.Buffer{},
		psOp: d.Controller.PermissionSets[RoleOperator].ARN, psRO: d.Controller.PermissionSets[RoleReadOnly].ARN}
	h.c = &Controller{Dir: d, SSO: w.sso(), Accounts: w.accountsFn(), Records: h.recs, Now: h.clk.Now, Sleep: h.clk.Sleep}
	h.entry = func(account, role string) string {
		prefix := "AWSReservedSSO_" + d.Controller.PermissionSets[role].Name + "_"
		for _, r := range w.account(account).roles {
			if strings.HasPrefix(r, prefix) {
				return w.account(account).arn(r)
			}
		}
		t.Fatalf("no %s role in %s", role, account)
		return ""
	}
	return h
}

func (h *harness) records() []Record {
	h.t.Helper()
	var out []Record
	for _, l := range strings.Split(strings.TrimSpace(h.recs.String()), "\n") {
		if l == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			h.t.Fatalf("record %q: %v", l, err)
		}
		out = append(out, r)
	}
	h.recs.Reset()
	return out
}

func (h *harness) assigned(account, ps, user string) bool {
	return h.w.assignments[akey(account, ps, "USER", user)]
}

// F-012 T-18 (F-012-AC-27; design §3.9): a request inside its window
// becomes the operator's assignment of the role's permission set in the
// instance's account, and an access entry for the role it provisions:
// the view policy at cluster scope and, for operators, the group
// fair:operator. Granting again changes nothing.
func TestGrantCreatesAssignmentAndAccessEntry(t *testing.T) {
	h := newHarness(t, "2026-11-26T11:30:00Z")
	h.w.pending = 2 // provisioning takes two polls
	ctx := context.Background()
	if err := h.c.Grant(ctx, "acme-incident-0042"); err != nil {
		t.Fatal(err)
	}
	if !h.assigned(acme, h.psOp, alice) {
		t.Fatal("alice has no FairOperator assignment in acme's account")
	}
	if len(h.w.assignments) != 1 {
		t.Errorf("assignments: %v", h.w.assignments)
	}
	p := h.entry(acme, RoleOperator)
	if strings.Contains(strings.TrimPrefix(p, "arn:aws-us-gov:iam::777777777777:role/"), "/") || !strings.HasPrefix(p, "arn:aws-us-gov:iam::777777777777:role/AWSReservedSSO_FairOperator_") {
		t.Errorf("the access entry's principal %s must be the provisioned role without its path", p)
	}
	e := h.w.account(acme).entries[p]
	if e == nil {
		t.Fatalf("no access entry for %s", p)
	}
	if !slices.Equal(e.groups, []string{"fair:operator"}) {
		t.Errorf("groups %v", e.groups)
	}
	if len(e.policies) != 1 || e.policies[viewARN] != ekstypes.AccessScopeTypeCluster {
		t.Errorf("policies %v: the view policy at cluster scope only", e.policies)
	}
	recs := h.records()
	if len(recs) != 2 || recs[0].Action != ActionAssigned || recs[1].Action != ActionEntryCreated {
		t.Fatalf("records %+v", recs)
	}
	r := recs[0]
	if r.Request != "acme-incident-0042" || r.Operator != "alice" || r.Approver != "bob" || r.Ticket != "OPS-42" || r.Account != acme ||
		r.Role != RoleOperator || r.Principal != "USER:"+alice || r.Expires != "2026-11-26T14:00:00Z" || r.Time == "" {
		t.Errorf("record %+v", r)
	}

	h.w.reset()
	if err := h.c.Grant(ctx, "acme-incident-0042"); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.w.calls {
		if strings.HasPrefix(c, "sso:Create") || strings.HasPrefix(c, "eks:Create") {
			t.Errorf("granting again created something: %s", c)
		}
	}
	if recs := h.records(); len(recs) != 1 || recs[0].Action != ActionAlreadyAssigned {
		t.Errorf("records %+v", recs)
	}

	// A read-only grant: the view policy, no groups.
	h.clk.t = at("2026-11-25T08:30:00Z")
	if err := h.c.Grant(ctx, "globex-check-0040"); err != nil {
		t.Fatal(err)
	}
	ro := h.w.account(globex).entries[h.entry(globex, RoleReadOnly)]
	if ro == nil || len(ro.groups) != 0 || len(ro.policies) != 1 || ro.policies[viewARN] != ekstypes.AccessScopeTypeCluster {
		t.Errorf("read-only entry %+v", ro)
	}
}

// Access exists only inside the window: a request before its start, after
// its end or after its revocation is refused, and so is an unknown one.
func TestGrantRefusesOutsideTheWindow(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ now, id, want string }{
		{"2026-11-26T09:59:59Z", "acme-incident-0042", "only from 2026-11-26T10:00:00Z until 2026-11-26T14:00:00Z"},
		{"2026-11-26T14:00:00Z", "acme-incident-0042", "only from"},
		{"2026-11-26T09:45:00Z", "globex-revoked-0041", "revoked at 2026-11-26T09:30:00Z"},
		{"2026-11-26T11:00:00Z", "nope", "no such request"},
	} {
		h := newHarness(t, c.now)
		err := h.c.Grant(ctx, c.id)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s at %s: %v, want %q", c.id, c.now, err, c.want)
		}
		if len(h.w.calls) != 0 {
			t.Errorf("%s at %s: AWS was called: %v", c.id, c.now, h.w.calls)
		}
	}
	h := newHarness(t, "2026-11-26T09:15:00Z")
	if err := h.c.Grant(ctx, "globex-revoked-0041"); err != nil {
		t.Errorf("before its revocation the request is active: %v", err)
	}
	if err := h.c.Grant(ctx); err == nil {
		t.Error("grant without requests")
	}
}

// Provisioning that fails or never finishes is an error, not a grant.
func TestGrantFailsOnProvisioning(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "2026-11-26T11:30:00Z")
	h.w.failAssign = "PermissionSet not provisioned"
	if err := h.c.Grant(ctx, "acme-incident-0042"); err == nil || !strings.Contains(err.Error(), "failed: PermissionSet not provisioned") {
		t.Errorf("%v", err)
	}
	if h.w.entriesOf(acme) != 0 {
		t.Error("an access entry without an assignment")
	}

	h = newHarness(t, "2026-11-26T11:30:00Z")
	h.w.pending = 1 << 20
	if err := h.c.Grant(ctx, "acme-incident-0042"); err == nil || !strings.Contains(err.Error(), "still IN_PROGRESS after 5m0s") {
		t.Errorf("%v", err)
	}
}

// An access entry for the role with other groups (changed by hand) is not
// silently reused.
func TestGrantRefusesAChangedEntry(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "2026-11-26T11:30:00Z")
	h.w.provision(acme, h.psOp)
	h.w.account(acme).entries[h.entry(acme, RoleOperator)] = &entry{groups: []string{"system:masters"}, policies: map[string]ekstypes.AccessScopeType{}}
	if err := h.c.Grant(ctx, "acme-incident-0042"); err == nil || !strings.Contains(err.Error(), "has groups [system:masters]") {
		t.Errorf("%v", err)
	}
}

// F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing
// access"): expire removes everything no active request backs (expired,
// revoked, unrequested, group, unknown account) and leaves access that is
// still requested and everything that is not FAIR's.
func TestExpireRemovesWhatNoActiveRequestBacks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "2026-11-26T11:30:00Z")
	w := h.w
	// Active: alice (until 14:00) and carol (11:00 to 13:00), operator in acme.
	w.assign(acme, h.psOp, ssotypes.PrincipalTypeUser, alice)
	w.assign(acme, h.psOp, ssotypes.PrincipalTypeUser, carol)
	// Unbacked: bob's expired read-only in globex, carol's revoked one, a
	// group assignment, an assignment nobody asked for, an unknown account.
	w.assign(globex, h.psRO, ssotypes.PrincipalTypeUser, bob)
	w.assign(globex, h.psRO, ssotypes.PrincipalTypeUser, carol)
	w.assign(acme, h.psRO, ssotypes.PrincipalTypeGroup, "9067a1b2c3-44444444-4444-4444-4444-444444444444")
	w.assign(acme, h.psRO, ssotypes.PrincipalTypeUser, bob)
	w.assign("999999999999", h.psOp, ssotypes.PrincipalTypeUser, alice)
	opEntry, roEntry := h.entry(acme, RoleOperator), h.entry(globex, RoleReadOnly)
	acmeRO := h.entry(acme, RoleReadOnly)
	admin := w.account(acme).arn("fair-instances-apply")
	other := w.account(acme).arn("AWSReservedSSO_SomethingElse_0123456789abcdef")
	for _, p := range []string{opEntry, acmeRO, admin, other} {
		w.account(acme).entries[p] = &entry{policies: map[string]ekstypes.AccessScopeType{}}
	}
	w.account(globex).entries[roEntry] = &entry{policies: map[string]ekstypes.AccessScopeType{}}

	if err := h.c.Expire(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.assigned(acme, h.psOp, alice) || !h.assigned(acme, h.psOp, carol) {
		t.Error("active requests' assignments were removed")
	}
	if len(w.assignments) != 2 {
		t.Errorf("left: %v", w.assignments)
	}
	if w.account(acme).entries[opEntry] == nil || w.account(acme).entries[admin] == nil || w.account(acme).entries[other] == nil {
		t.Error("removed an active role's entry or an entry that is not FAIR's")
	}
	if w.account(acme).entries[acmeRO] != nil || w.account(globex).entries[roEntry] != nil {
		t.Error("entries of roles without an active request remain")
	}
	reasons := map[string]string{}
	for _, r := range h.records() {
		reasons[r.Action+" "+r.Account+" "+r.Principal] = r.Reason
	}
	for k, want := range map[string]string{
		"assignment_deleted 888888888888 USER:" + bob:                                           "request globex-check-0040 expired at 2026-11-25T09:30:00Z",
		"assignment_deleted 888888888888 USER:" + carol:                                         "request globex-revoked-0041 revoked: The target group recovered",
		"assignment_deleted 777777777777 GROUP:9067a1b2c3-44444444-4444-4444-4444-444444444444": "a group assignment",
		"assignment_deleted 777777777777 USER:" + bob:                                           "no request for it",
		"assignment_deleted 999999999999 USER:" + alice:                                         "not an instance in instances.yaml",
		"access_entry_deleted 777777777777 " + acmeRO:                                           "no active request holds the role",
		"access_entry_deleted 888888888888 " + roEntry:                                          "no active request holds the role",
	} {
		if got, ok := reasons[k]; !ok || !strings.Contains(got, want) {
			t.Errorf("%s: reason %q, want %q (records %v)", k, got, want, reasons)
		}
	}
	if len(reasons) != 7 {
		t.Errorf("records: %v", reasons)
	}

	// 13:00: carol's request ends; alice's continues, so the entry stays.
	h.clk.t = at("2026-11-26T13:00:00Z")
	if err := h.c.Expire(ctx); err != nil {
		t.Fatal(err)
	}
	if h.assigned(acme, h.psOp, carol) || !h.assigned(acme, h.psOp, alice) || w.account(acme).entries[opEntry] == nil {
		t.Errorf("at 13:00: %v, entry %v", w.assignments, w.account(acme).entries[opEntry])
	}
	// 14:00: alice's ends too: nothing of FAIR's is left.
	h.clk.t = at("2026-11-26T14:00:00Z")
	if err := h.c.Expire(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.assignments) != 0 || w.account(acme).entries[opEntry] != nil {
		t.Errorf("at 14:00: %v, entries %v", w.assignments, w.account(acme).entries)
	}
	if w.account(acme).entries[admin] == nil || w.account(acme).entries[other] == nil {
		t.Error("expire removed entries that are not FAIR's")
	}
	// Nothing to do: no calls that change anything.
	w.reset()
	if err := h.c.Expire(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.calls {
		if !strings.HasPrefix(c, "sso:List") {
			t.Errorf("an idle expire changed something: %s", c)
		}
	}
}

// Revoke ends one operator's access now; the role's access entry stays
// while another operator's request still needs it.
func TestRevoke(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "2026-11-26T11:30:00Z")
	for _, id := range []string{"acme-incident-0042", "acme-review-0043"} {
		if err := h.c.Grant(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	p := h.entry(acme, RoleOperator)
	h.records()
	if err := h.c.Revoke(ctx, "acme-incident-0042", "short"); err == nil {
		t.Error("a revocation needs a reason")
	}
	if err := h.c.Revoke(ctx, "acme-incident-0042", "The incident is closed early"); err != nil {
		t.Fatal(err)
	}
	if h.assigned(acme, h.psOp, alice) || !h.assigned(acme, h.psOp, carol) || h.w.account(acme).entries[p] == nil {
		t.Errorf("after revoking alice's: %v", h.w.assignments)
	}
	if recs := h.records(); len(recs) != 1 || recs[0].Action != ActionUnassigned || !strings.Contains(recs[0].Reason, "revoked: The incident is closed early") {
		t.Errorf("records %+v", recs)
	}
	if err := h.c.Revoke(ctx, "acme-review-0043", "The rollout finished, nothing to watch"); err != nil {
		t.Fatal(err)
	}
	if len(h.w.assignments) != 0 || h.w.account(acme).entries[p] != nil {
		t.Errorf("after revoking both: %v, %v", h.w.assignments, h.w.account(acme).entries)
	}
}

// List shows each FAIR grant with the request that backs it, and flags the
// rest.
func TestList(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "2026-11-26T11:30:00Z")
	if err := h.c.Grant(ctx, "acme-incident-0042"); err != nil {
		t.Fatal(err)
	}
	h.w.assign(globex, h.psRO, ssotypes.PrincipalTypeUser, bob)
	gs, err := h.c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 3 {
		t.Fatalf("grants %+v", gs)
	}
	for _, g := range gs {
		switch {
		case g.Account == acme && g.Principal == "USER:"+alice:
			if !g.Backed || g.Request != "acme-incident-0042" || g.Operator != "alice" || g.Expires != "2026-11-26T14:00:00Z" {
				t.Errorf("%+v", g)
			}
		case g.Account == acme:
			if !g.Backed || g.Principal != h.entry(acme, RoleOperator) {
				t.Errorf("%+v", g)
			}
		default:
			if g.Backed || g.Operator != "bob" || g.Instance != "globex" {
				t.Errorf("an expired assignment shows as backed: %+v", g)
			}
		}
	}
}

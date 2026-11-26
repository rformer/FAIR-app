package accessctl

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
)

// world is a fake AWS: IAM Identity Center with its assignments, and each
// instance account's provisioned roles and cluster access entries. Calls
// are recorded; pages are one item long, so pagination is exercised.
type world struct {
	mu sync.Mutex
	// psNames maps permission set ARNs to names (for provisioned roles).
	psNames map[string]string
	// assignments: account|permission set|type|principal.
	assignments map[string]bool
	provisioned map[string]map[string]bool // permission set -> accounts
	accounts    map[string]*fakeAccount
	statuses    map[string]*ssotypes.AccountAssignmentOperationStatus
	pollers     map[string]func()
	// pending is how many polls an operation stays IN_PROGRESS; failAssign
	// makes creations fail.
	pending    int
	failAssign string
	calls      []string
	nextID     int
}

type fakeAccount struct {
	w       *world
	id      string
	roles   []string // role names under /aws-reserved/sso.amazonaws.com/
	other   []string // roles elsewhere
	entries map[string]*entry
}

type entry struct {
	groups   []string
	policies map[string]ekstypes.AccessScopeType
}

func newWorld(d *Dir) *world {
	w := &world{psNames: map[string]string{}, assignments: map[string]bool{}, provisioned: map[string]map[string]bool{},
		accounts: map[string]*fakeAccount{}, statuses: map[string]*ssotypes.AccountAssignmentOperationStatus{}, pollers: map[string]func(){}}
	for _, ps := range d.Controller.PermissionSets {
		w.psNames[ps.ARN] = ps.Name
		w.provisioned[ps.ARN] = map[string]bool{}
	}
	return w
}

func (w *world) account(id string) *fakeAccount {
	a, ok := w.accounts[id]
	if !ok {
		a = &fakeAccount{w: w, id: id, entries: map[string]*entry{}, other: []string{"OrganizationAccountAccessRole", "fair-instance-plan"}}
		w.accounts[id] = a
	}
	return a
}

func akey(account, ps, typ, id string) string { return account + "|" + ps + "|" + typ + "|" + id }

func (w *world) call(f string, a ...any) {
	w.calls = append(w.calls, fmt.Sprintf(f, a...))
}

// assign puts an assignment in place directly (state before a test).
func (w *world) assign(account, ps string, typ ssotypes.PrincipalType, id string) {
	w.assignments[akey(account, ps, string(typ), id)] = true
	w.provision(account, ps)
}

func (w *world) provision(account, ps string) {
	w.provisioned[ps][account] = true
	a := w.account(account)
	prefix := "AWSReservedSSO_" + w.psNames[ps] + "_"
	for _, r := range a.roles {
		if strings.HasPrefix(r, prefix) {
			return
		}
	}
	a.roles = append(a.roles, prefix+fmt.Sprintf("%016x", len(a.roles)+0xa1b2))
}

func (w *world) status(req string) *ssotypes.AccountAssignmentOperationStatus {
	st := w.statuses[req]
	return &ssotypes.AccountAssignmentOperationStatus{RequestId: aws.String(req), Status: st.Status, FailureReason: st.FailureReason}
}

func (w *world) operation(apply func(), fail string) *ssotypes.AccountAssignmentOperationStatus {
	w.nextID++
	id := fmt.Sprintf("req-%d", w.nextID)
	st := &ssotypes.AccountAssignmentOperationStatus{RequestId: aws.String(id), Status: ssotypes.StatusValuesInProgress}
	w.statuses[id] = st
	remaining := w.pending
	resolve := func() {
		if fail != "" {
			st.Status, st.FailureReason = ssotypes.StatusValuesFailed, aws.String(fail)
			return
		}
		apply()
		st.Status = ssotypes.StatusValuesSucceeded
	}
	if remaining == 0 {
		resolve()
	} else {
		w.pollers[id] = func() {
			remaining--
			if remaining == 0 {
				resolve()
			}
		}
	}
	return w.status(id)
}

type fakeSSO struct{ *world }

func (w *world) sso() fakeSSO { return fakeSSO{w} }

func (f fakeSSO) CreateAccountAssignment(_ context.Context, in *ssoadmin.CreateAccountAssignmentInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.CreateAccountAssignmentOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acct, ps, id := aws.ToString(in.TargetId), aws.ToString(in.PermissionSetArn), aws.ToString(in.PrincipalId)
	f.call("sso:CreateAccountAssignment %s %s %s:%s", acct, f.psNames[ps], in.PrincipalType, id)
	if in.TargetType != ssotypes.TargetTypeAwsAccount || aws.ToString(in.InstanceArn) == "" {
		return nil, fmt.Errorf("bad request")
	}
	st := f.operation(func() { f.assign(acct, ps, in.PrincipalType, id) }, f.failAssign)
	return &ssoadmin.CreateAccountAssignmentOutput{AccountAssignmentCreationStatus: st}, nil
}

func (f fakeSSO) DeleteAccountAssignment(_ context.Context, in *ssoadmin.DeleteAccountAssignmentInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DeleteAccountAssignmentOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acct, ps, id := aws.ToString(in.TargetId), aws.ToString(in.PermissionSetArn), aws.ToString(in.PrincipalId)
	f.call("sso:DeleteAccountAssignment %s %s %s:%s", acct, f.psNames[ps], in.PrincipalType, id)
	k := akey(acct, ps, string(in.PrincipalType), id)
	if !f.assignments[k] {
		return nil, fmt.Errorf("no such assignment %s", k)
	}
	st := f.operation(func() { delete(f.assignments, k) }, "")
	return &ssoadmin.DeleteAccountAssignmentOutput{AccountAssignmentDeletionStatus: st}, nil
}

func (f fakeSSO) poll(id string) *ssotypes.AccountAssignmentOperationStatus {
	if p := f.pollers[id]; p != nil && f.statuses[id].Status == ssotypes.StatusValuesInProgress {
		p()
	}
	return f.status(id)
}

func (f fakeSSO) DescribeAccountAssignmentCreationStatus(_ context.Context, in *ssoadmin.DescribeAccountAssignmentCreationStatusInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentCreationStatusOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &ssoadmin.DescribeAccountAssignmentCreationStatusOutput{AccountAssignmentCreationStatus: f.poll(aws.ToString(in.AccountAssignmentCreationRequestId))}, nil
}

func (f fakeSSO) DescribeAccountAssignmentDeletionStatus(_ context.Context, in *ssoadmin.DescribeAccountAssignmentDeletionStatusInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentDeletionStatusOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &ssoadmin.DescribeAccountAssignmentDeletionStatusOutput{AccountAssignmentDeletionStatus: f.poll(aws.ToString(in.AccountAssignmentDeletionRequestId))}, nil
}

// page returns one item at the token's offset, and the next token.
func page[T any](all []T, token *string) ([]T, *string) {
	i := 0
	if token != nil {
		_, _ = fmt.Sscan(*token, &i)
	}
	if i >= len(all) {
		return nil, nil
	}
	var next *string
	if i+1 < len(all) {
		next = aws.String(fmt.Sprint(i + 1))
	}
	return all[i : i+1], next
}

func (f fakeSSO) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acct, ps := aws.ToString(in.AccountId), aws.ToString(in.PermissionSetArn)
	var all []ssotypes.AccountAssignment
	var keys []string
	for k := range f.assignments {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := strings.Split(k, "|")
		if p[0] == acct && p[1] == ps {
			all = append(all, ssotypes.AccountAssignment{AccountId: aws.String(acct), PermissionSetArn: aws.String(ps), PrincipalType: ssotypes.PrincipalType(p[2]), PrincipalId: aws.String(p[3])})
		}
	}
	items, next := page(all, in.NextToken)
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: items, NextToken: next}, nil
}

func (f fakeSSO) ListAccountsForProvisionedPermissionSet(_ context.Context, in *ssoadmin.ListAccountsForProvisionedPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []string
	for a := range f.provisioned[aws.ToString(in.PermissionSetArn)] {
		all = append(all, a)
	}
	sort.Strings(all)
	items, next := page(all, in.NextToken)
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: items, NextToken: next}, nil
}

func (a *fakeAccount) arn(role string) string { return "arn:aws-us-gov:iam::" + a.id + ":role/" + role }

func (a *fakeAccount) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	var all []iamtypes.Role
	for _, r := range a.roles {
		all = append(all, iamtypes.Role{RoleName: aws.String(r), Path: aws.String(ssoRolePath)})
	}
	if aws.ToString(in.PathPrefix) != ssoRolePath {
		for _, r := range a.other {
			all = append(all, iamtypes.Role{RoleName: aws.String(r), Path: aws.String("/")})
		}
	}
	items, next := page(all, in.Marker)
	return &iam.ListRolesOutput{Roles: items, IsTruncated: next != nil, Marker: next}, nil
}

func (a *fakeAccount) cluster(name *string) error {
	if want := "fair-" + map[string]string{"777777777777": "acme", "888888888888": "globex"}[a.id]; aws.ToString(name) != want {
		return fmt.Errorf("no cluster %s in %s", aws.ToString(name), a.id)
	}
	return nil
}

func (a *fakeAccount) CreateAccessEntry(_ context.Context, in *eks.CreateAccessEntryInput, _ ...func(*eks.Options)) (*eks.CreateAccessEntryOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if err := a.cluster(in.ClusterName); err != nil {
		return nil, err
	}
	p := aws.ToString(in.PrincipalArn)
	a.w.call("eks:CreateAccessEntry %s %s %v %s", a.id, p, in.KubernetesGroups, aws.ToString(in.Type))
	if _, ok := a.entries[p]; ok {
		return nil, &ekstypes.ResourceInUseException{Message: aws.String("exists")}
	}
	a.entries[p] = &entry{groups: in.KubernetesGroups, policies: map[string]ekstypes.AccessScopeType{}}
	return &eks.CreateAccessEntryOutput{AccessEntry: &ekstypes.AccessEntry{PrincipalArn: in.PrincipalArn, KubernetesGroups: in.KubernetesGroups}}, nil
}

func (a *fakeAccount) DescribeAccessEntry(_ context.Context, in *eks.DescribeAccessEntryInput, _ ...func(*eks.Options)) (*eks.DescribeAccessEntryOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if err := a.cluster(in.ClusterName); err != nil {
		return nil, err
	}
	e, ok := a.entries[aws.ToString(in.PrincipalArn)]
	if !ok {
		return nil, &ekstypes.ResourceNotFoundException{Message: aws.String("no entry")}
	}
	return &eks.DescribeAccessEntryOutput{AccessEntry: &ekstypes.AccessEntry{PrincipalArn: in.PrincipalArn, KubernetesGroups: e.groups}}, nil
}

func (a *fakeAccount) DeleteAccessEntry(_ context.Context, in *eks.DeleteAccessEntryInput, _ ...func(*eks.Options)) (*eks.DeleteAccessEntryOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if err := a.cluster(in.ClusterName); err != nil {
		return nil, err
	}
	p := aws.ToString(in.PrincipalArn)
	a.w.call("eks:DeleteAccessEntry %s %s", a.id, p)
	if _, ok := a.entries[p]; !ok {
		return nil, &ekstypes.ResourceNotFoundException{Message: aws.String("no entry")}
	}
	delete(a.entries, p)
	return &eks.DeleteAccessEntryOutput{}, nil
}

func (a *fakeAccount) AssociateAccessPolicy(_ context.Context, in *eks.AssociateAccessPolicyInput, _ ...func(*eks.Options)) (*eks.AssociateAccessPolicyOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if err := a.cluster(in.ClusterName); err != nil {
		return nil, err
	}
	e, ok := a.entries[aws.ToString(in.PrincipalArn)]
	if !ok {
		return nil, &ekstypes.ResourceNotFoundException{Message: aws.String("no entry")}
	}
	a.w.call("eks:AssociateAccessPolicy %s %s %s %s", a.id, aws.ToString(in.PrincipalArn), aws.ToString(in.PolicyArn), in.AccessScope.Type)
	e.policies[aws.ToString(in.PolicyArn)] = in.AccessScope.Type
	return &eks.AssociateAccessPolicyOutput{}, nil
}

func (a *fakeAccount) ListAccessEntries(_ context.Context, in *eks.ListAccessEntriesInput, _ ...func(*eks.Options)) (*eks.ListAccessEntriesOutput, error) {
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if err := a.cluster(in.ClusterName); err != nil {
		return nil, err
	}
	var all []string
	for p := range a.entries {
		all = append(all, p)
	}
	sort.Strings(all)
	items, next := page(all, in.NextToken)
	return &eks.ListAccessEntriesOutput{AccessEntries: items, NextToken: next}, nil
}

// clock is a fake clock; Sleep advances it.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Sleep(d time.Duration)   { c.t = c.t.Add(d) }
func at(s string) time.Time              { t, _ := time.Parse(time.RFC3339, s); return t }
func (w *world) accountsFn() Accounts    { return w.accountsFunc }
func (w *world) reset()                  { w.calls = nil }
func (w *world) entriesOf(id string) int { return len(w.account(id).entries) }

func (w *world) accountsFunc(_ context.Context, id, region string) (*Account, error) {
	if region != "us-gov-west-1" {
		return nil, fmt.Errorf("region %s", region)
	}
	a := w.account(id)
	return &Account{EKS: a, IAM: a}, nil
}

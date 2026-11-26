package accessctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
)

// SSOAdmin is the part of the IAM Identity Center admin API accessctl uses.
type SSOAdmin interface {
	CreateAccountAssignment(context.Context, *ssoadmin.CreateAccountAssignmentInput, ...func(*ssoadmin.Options)) (*ssoadmin.CreateAccountAssignmentOutput, error)
	DeleteAccountAssignment(context.Context, *ssoadmin.DeleteAccountAssignmentInput, ...func(*ssoadmin.Options)) (*ssoadmin.DeleteAccountAssignmentOutput, error)
	DescribeAccountAssignmentCreationStatus(context.Context, *ssoadmin.DescribeAccountAssignmentCreationStatusInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentCreationStatusOutput, error)
	DescribeAccountAssignmentDeletionStatus(context.Context, *ssoadmin.DescribeAccountAssignmentDeletionStatusInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentDeletionStatusOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
}

// EKS is the part of the EKS API accessctl uses (access entries only).
type EKS interface {
	CreateAccessEntry(context.Context, *eks.CreateAccessEntryInput, ...func(*eks.Options)) (*eks.CreateAccessEntryOutput, error)
	DescribeAccessEntry(context.Context, *eks.DescribeAccessEntryInput, ...func(*eks.Options)) (*eks.DescribeAccessEntryOutput, error)
	DeleteAccessEntry(context.Context, *eks.DeleteAccessEntryInput, ...func(*eks.Options)) (*eks.DeleteAccessEntryOutput, error)
	AssociateAccessPolicy(context.Context, *eks.AssociateAccessPolicyInput, ...func(*eks.Options)) (*eks.AssociateAccessPolicyOutput, error)
	ListAccessEntries(context.Context, *eks.ListAccessEntriesInput, ...func(*eks.Options)) (*eks.ListAccessEntriesOutput, error)
}

// IAM is the part of the IAM API accessctl uses: finding the role IAM
// Identity Center provisions for a permission set.
type IAM interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

// Account is an instance account's clients (through its fair-access-eks role).
type Account struct {
	EKS EKS
	IAM IAM
}

// Accounts opens an instance account's clients.
type Accounts func(ctx context.Context, accountID, region string) (*Account, error)

// Record is one change accessctl made (or refused), as a JSON line.
type Record struct {
	Time      string `json:"time"`
	Action    string `json:"action"`
	Request   string `json:"request,omitempty"`
	Operator  string `json:"operator,omitempty"`
	Approver  string `json:"approver,omitempty"`
	Ticket    string `json:"ticket,omitempty"`
	Instance  string `json:"instance,omitempty"`
	Account   string `json:"account"`
	Role      string `json:"role"`
	Principal string `json:"principal"`
	Expires   string `json:"expires,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Actions in records.
const (
	ActionAssigned        = "assignment_created"
	ActionUnassigned      = "assignment_deleted"
	ActionEntryCreated    = "access_entry_created"
	ActionEntryDeleted    = "access_entry_deleted"
	ActionAlreadyAssigned = "assignment_present"
)

// Controller applies an access directory.
type Controller struct {
	Dir      *Dir
	SSO      SSOAdmin
	Accounts Accounts
	// Records receives each change as a JSON line.
	Records io.Writer
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Sleep waits between status polls (time.Sleep when nil).
	Sleep func(time.Duration)
	// Timeout bounds waiting for an assignment's provisioning (5 minutes
	// when zero).
	Timeout time.Duration
}

const ssoRolePath = "/aws-reserved/sso.amazonaws.com/"

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Controller) record(r Record) error {
	r.Time = c.now().Format(time.RFC3339)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if c.Records == nil {
		return nil
	}
	_, err = c.Records.Write(append(b, '\n'))
	return err
}

func (c *Controller) wait(ctx context.Context, what string, poll func() (*ssotypes.AccountAssignmentOperationStatus, error), first *ssotypes.AccountAssignmentOperationStatus) error {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	deadline := c.now().Add(timeout)
	st := first
	for {
		if st == nil {
			return fmt.Errorf("%s: no status", what)
		}
		switch st.Status {
		case ssotypes.StatusValuesSucceeded:
			return nil
		case ssotypes.StatusValuesFailed:
			return fmt.Errorf("%s failed: %s", what, aws.ToString(st.FailureReason))
		}
		if !c.now().Before(deadline) {
			return fmt.Errorf("%s: still %s after %s", what, st.Status, timeout)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		sleep(2 * time.Second)
		var err error
		if st, err = poll(); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
}

type assignment struct {
	account, role, principalType, principalID string
}

func (c *Controller) listAssignments(ctx context.Context, account, role string) ([]assignment, error) {
	cfg := c.Dir.Controller
	var out []assignment
	var token *string
	for {
		page, err := c.SSO.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			InstanceArn:      aws.String(cfg.InstanceARN),
			AccountId:        aws.String(account),
			PermissionSetArn: aws.String(cfg.PermissionSets[role].ARN),
			NextToken:        token,
		})
		if err != nil {
			return nil, fmt.Errorf("assignments of %s in %s: %w", cfg.PermissionSets[role].Name, account, err)
		}
		for _, a := range page.AccountAssignments {
			out = append(out, assignment{account: account, role: role, principalType: string(a.PrincipalType), principalID: aws.ToString(a.PrincipalId)})
		}
		if token = page.NextToken; token == nil {
			return out, nil
		}
	}
}

// provisionedAccounts lists the accounts a role's permission set is
// provisioned to: wherever it could be assigned, including accounts not in
// instances.yaml.
func (c *Controller) provisionedAccounts(ctx context.Context, role string) ([]string, error) {
	cfg := c.Dir.Controller
	var out []string
	var token *string
	for {
		page, err := c.SSO.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      aws.String(cfg.InstanceARN),
			PermissionSetArn: aws.String(cfg.PermissionSets[role].ARN),
			NextToken:        token,
		})
		if err != nil {
			return nil, fmt.Errorf("accounts of %s: %w", cfg.PermissionSets[role].Name, err)
		}
		out = append(out, page.AccountIds...)
		if token = page.NextToken; token == nil {
			return out, nil
		}
	}
}

func (c *Controller) assign(ctx context.Context, r *Request) error {
	cfg := c.Dir.Controller
	in := c.Dir.Instances[r.Instance]
	user := c.Dir.Operators[r.Operator].UserID
	rec := Record{Request: r.ID, Operator: r.Operator, Approver: r.Approver, Ticket: r.Ticket, Instance: r.Instance,
		Account: in.AccountID, Role: r.Role, Principal: "USER:" + user, Expires: r.Expires().Format(time.RFC3339), Reason: r.Reason}
	current, err := c.listAssignments(ctx, in.AccountID, r.Role)
	if err != nil {
		return err
	}
	if slices.Contains(current, assignment{account: in.AccountID, role: r.Role, principalType: string(ssotypes.PrincipalTypeUser), principalID: user}) {
		rec.Action = ActionAlreadyAssigned
		return c.record(rec)
	}
	out, err := c.SSO.CreateAccountAssignment(ctx, &ssoadmin.CreateAccountAssignmentInput{
		InstanceArn:      aws.String(cfg.InstanceARN),
		PermissionSetArn: aws.String(cfg.PermissionSets[r.Role].ARN),
		PrincipalType:    ssotypes.PrincipalTypeUser,
		PrincipalId:      aws.String(user),
		TargetType:       ssotypes.TargetTypeAwsAccount,
		TargetId:         aws.String(in.AccountID),
	})
	if err != nil {
		return fmt.Errorf("assign %s to %s in %s: %w", cfg.PermissionSets[r.Role].Name, r.Operator, r.Instance, err)
	}
	st := out.AccountAssignmentCreationStatus
	err = c.wait(ctx, "assignment for "+r.ID, func() (*ssotypes.AccountAssignmentOperationStatus, error) {
		o, err := c.SSO.DescribeAccountAssignmentCreationStatus(ctx, &ssoadmin.DescribeAccountAssignmentCreationStatusInput{
			InstanceArn:                        aws.String(cfg.InstanceARN),
			AccountAssignmentCreationRequestId: st.RequestId,
		})
		if err != nil {
			return nil, err
		}
		return o.AccountAssignmentCreationStatus, nil
	}, st)
	if err != nil {
		return err
	}
	rec.Action = ActionAssigned
	return c.record(rec)
}

func (c *Controller) unassign(ctx context.Context, a assignment, rec Record) error {
	cfg := c.Dir.Controller
	out, err := c.SSO.DeleteAccountAssignment(ctx, &ssoadmin.DeleteAccountAssignmentInput{
		InstanceArn:      aws.String(cfg.InstanceARN),
		PermissionSetArn: aws.String(cfg.PermissionSets[a.role].ARN),
		PrincipalType:    ssotypes.PrincipalType(a.principalType),
		PrincipalId:      aws.String(a.principalID),
		TargetType:       ssotypes.TargetTypeAwsAccount,
		TargetId:         aws.String(a.account),
	})
	if err != nil {
		return fmt.Errorf("remove %s from %s:%s in %s: %w", cfg.PermissionSets[a.role].Name, a.principalType, a.principalID, a.account, err)
	}
	st := out.AccountAssignmentDeletionStatus
	err = c.wait(ctx, "removing "+a.principalType+":"+a.principalID+" from "+a.account, func() (*ssotypes.AccountAssignmentOperationStatus, error) {
		o, err := c.SSO.DescribeAccountAssignmentDeletionStatus(ctx, &ssoadmin.DescribeAccountAssignmentDeletionStatusInput{
			InstanceArn:                        aws.String(cfg.InstanceARN),
			AccountAssignmentDeletionRequestId: st.RequestId,
		})
		if err != nil {
			return nil, err
		}
		return o.AccountAssignmentDeletionStatus, nil
	}, st)
	if err != nil {
		return err
	}
	rec.Action, rec.Account, rec.Role, rec.Principal = ActionUnassigned, a.account, a.role, a.principalType+":"+a.principalID
	return c.record(rec)
}

// roleARN finds the role IAM Identity Center provisioned for a role's
// permission set in an account (AWSReservedSSO_<name>_<suffix>), as EKS
// wants it: without its path.
func (c *Controller) roleARN(ctx context.Context, acct *Account, accountID, role string) (string, error) {
	prefix := "AWSReservedSSO_" + c.Dir.Controller.PermissionSets[role].Name + "_"
	var found []string
	var marker *string
	for {
		page, err := acct.IAM.ListRoles(ctx, &iam.ListRolesInput{PathPrefix: aws.String(ssoRolePath), Marker: marker})
		if err != nil {
			return "", fmt.Errorf("roles in %s: %w", accountID, err)
		}
		for _, r := range page.Roles {
			if name := aws.ToString(r.RoleName); strings.HasPrefix(name, prefix) {
				found = append(found, name)
			}
		}
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%s: %d roles %s* (the permission set is provisioned when assigned: one role expected)", accountID, len(found), prefix)
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", c.Dir.Controller.Partition, accountID, found[0]), nil
}

// roleOf says which FAIR role an access entry's principal is, or "".
func (c *Controller) roleOf(principal, accountID string) string {
	name, ok := strings.CutPrefix(principal, fmt.Sprintf("arn:%s:iam::%s:role/", c.Dir.Controller.Partition, accountID))
	if !ok {
		return ""
	}
	for _, role := range Roles {
		if strings.HasPrefix(name, "AWSReservedSSO_"+c.Dir.Controller.PermissionSets[role].Name+"_") && !strings.Contains(name, "/") {
			return role
		}
	}
	return ""
}

func groupsFor(role string) []string {
	if role == RoleOperator {
		return []string{OperatorGroup}
	}
	return nil
}

func (c *Controller) viewPolicy() string {
	return fmt.Sprintf("arn:%s:eks::aws:cluster-access-policy/AmazonEKSViewPolicy", c.Dir.Controller.Partition)
}

func (c *Controller) ensureEntry(ctx context.Context, acct *Account, r *Request, principal string) error {
	in := c.Dir.Instances[r.Instance]
	want := groupsFor(r.Role)
	d, err := acct.EKS.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{ClusterName: aws.String(in.Cluster), PrincipalArn: aws.String(principal)})
	var nf *ekstypes.ResourceNotFoundException
	switch {
	case errors.As(err, &nf):
		if _, err := acct.EKS.CreateAccessEntry(ctx, &eks.CreateAccessEntryInput{
			ClusterName:      aws.String(in.Cluster),
			PrincipalArn:     aws.String(principal),
			Type:             aws.String("STANDARD"),
			KubernetesGroups: want,
		}); err != nil {
			return fmt.Errorf("access entry for %s in %s: %w", principal, in.Cluster, err)
		}
		if err := c.record(Record{Action: ActionEntryCreated, Request: r.ID, Operator: r.Operator, Ticket: r.Ticket, Instance: r.Instance,
			Account: in.AccountID, Role: r.Role, Principal: principal, Expires: r.Expires().Format(time.RFC3339)}); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("access entry for %s in %s: %w", principal, in.Cluster, err)
	default:
		got := slices.Clone(d.AccessEntry.KubernetesGroups)
		sort.Strings(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("the access entry for %s in %s has groups %v, not %v: remove it (accessctl expire) and grant again", principal, in.Cluster, got, want)
		}
	}
	if _, err := acct.EKS.AssociateAccessPolicy(ctx, &eks.AssociateAccessPolicyInput{
		ClusterName:  aws.String(in.Cluster),
		PrincipalArn: aws.String(principal),
		PolicyArn:    aws.String(c.viewPolicy()),
		AccessScope:  &ekstypes.AccessScope{Type: ekstypes.AccessScopeTypeCluster},
	}); err != nil {
		return fmt.Errorf("view policy for %s in %s: %w", principal, in.Cluster, err)
	}
	return nil
}

// Grant applies requests: the operator's assignment and the role's access
// entry. A request outside its window (not started, expired or revoked) is
// refused.
func (c *Controller) Grant(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return errors.New("grant: name the requests")
	}
	now := c.now()
	var errs []error
	for _, id := range ids {
		r, ok := c.Dir.Requests[id]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("grant %s: no such request", id))
			continue
		case r.Revoked != nil && !now.Before(r.Expires()):
			errs = append(errs, fmt.Errorf("grant %s: revoked at %s", id, r.Revoked.At))
			continue
		case !r.ActiveAt(now):
			s, e := r.Window()
			errs = append(errs, fmt.Errorf("grant %s: only from %s until %s (now %s)", id, s.Format(time.RFC3339), e.Format(time.RFC3339), now.Format(time.RFC3339)))
			continue
		}
		if err := c.grant(ctx, r); err != nil {
			errs = append(errs, fmt.Errorf("grant %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) grant(ctx context.Context, r *Request) error {
	if err := c.assign(ctx, r); err != nil {
		return err
	}
	in := c.Dir.Instances[r.Instance]
	acct, err := c.Accounts(ctx, in.AccountID, in.Region)
	if err != nil {
		return err
	}
	principal, err := c.roleARN(ctx, acct, in.AccountID, r.Role)
	if err != nil {
		return err
	}
	return c.ensureEntry(ctx, acct, r, principal)
}

// Revoke ends a request now: the operator's assignment, and the role's
// access entry once nobody else holds the role in the account. A revocation that should
// last is also recorded in the request (revoked), by pull request.
func (c *Controller) Revoke(ctx context.Context, id, reason string) error {
	r, ok := c.Dir.Requests[id]
	if !ok {
		return fmt.Errorf("revoke %s: no such request", id)
	}
	if len(strings.TrimSpace(reason)) < 10 {
		return errors.New("revoke: a reason (at least 10 characters) is required")
	}
	in := c.Dir.Instances[r.Instance]
	user := c.Dir.Operators[r.Operator].UserID
	rec := Record{Request: r.ID, Operator: r.Operator, Ticket: r.Ticket, Instance: r.Instance, Reason: "revoked: " + reason}
	current, err := c.listAssignments(ctx, in.AccountID, r.Role)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range current {
		if a.principalType == string(ssotypes.PrincipalTypeUser) && a.principalID == user {
			if err := c.unassign(ctx, a, rec); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// The role's access entry goes once nobody holds the role's assignment
	// in the account (the role cannot be assumed without one).
	left, err := c.listAssignments(ctx, in.AccountID, r.Role)
	if err != nil {
		errs = append(errs, err)
	} else if len(left) == 0 {
		if err := c.removeEntries(ctx, r.Instance, func(role string) bool { return role == r.Role }, rec); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) removeEntries(ctx context.Context, instance string, remove func(role string) bool, rec Record) error {
	in := c.Dir.Instances[instance]
	acct, err := c.Accounts(ctx, in.AccountID, in.Region)
	if err != nil {
		return err
	}
	entries, err := c.entries(ctx, acct, in)
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range entries {
		role := c.roleOf(p, in.AccountID)
		if role == "" || !remove(role) {
			continue
		}
		if _, err := acct.EKS.DeleteAccessEntry(ctx, &eks.DeleteAccessEntryInput{ClusterName: aws.String(in.Cluster), PrincipalArn: aws.String(p)}); err != nil {
			errs = append(errs, fmt.Errorf("remove the access entry for %s in %s: %w", p, in.Cluster, err))
			continue
		}
		r := rec
		r.Action, r.Instance, r.Account, r.Role, r.Principal = ActionEntryDeleted, instance, in.AccountID, role, p
		if err := c.record(r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) entries(ctx context.Context, acct *Account, in Instance) ([]string, error) {
	var out []string
	var token *string
	for {
		page, err := acct.EKS.ListAccessEntries(ctx, &eks.ListAccessEntriesInput{ClusterName: aws.String(in.Cluster), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("access entries of %s: %w", in.Cluster, err)
		}
		out = append(out, page.AccessEntries...)
		if token = page.NextToken; token == nil {
			return out, nil
		}
	}
}

func (c *Controller) instanceOf(account string) (string, bool) {
	for name, in := range c.Dir.Instances {
		if in.AccountID == account {
			return name, true
		}
	}
	return "", false
}

// Expire removes every assignment to a FAIR permission set and every FAIR
// access entry that no request active now backs: expired and revoked
// requests, and access nobody requested (a group assignment, an assignment
// by hand, an account missing from instances.yaml). It never grants. Every
// instance is tried; the errors are returned together.
func (c *Controller) Expire(ctx context.Context) error {
	now := c.now()
	var errs []error
	// kept: instance/role pairs with an assignment an active request backs;
	// only their access entries stay.
	kept := map[string]bool{}
	failed := map[string]bool{}
	for _, role := range Roles {
		accounts, err := c.provisionedAccounts(ctx, role)
		if err != nil {
			errs = append(errs, err)
			for _, n := range c.instanceNames() {
				failed[n+"/"+role] = true
			}
			continue
		}
		for _, in := range c.Dir.Instances {
			if !slices.Contains(accounts, in.AccountID) {
				accounts = append(accounts, in.AccountID)
			}
		}
		sort.Strings(accounts)
		for _, account := range accounts {
			name, known := c.instanceOf(account)
			backed := map[string]*Request{}
			if known {
				for _, r := range c.Dir.Active(now, name, role) {
					backed[c.Dir.Operators[r.Operator].UserID] = r
				}
			}
			current, err := c.listAssignments(ctx, account, role)
			if err != nil {
				errs = append(errs, err)
				failed[name+"/"+role] = true
				continue
			}
			for _, a := range current {
				if r := backed[a.principalID]; r != nil && a.principalType == string(ssotypes.PrincipalTypeUser) {
					kept[name+"/"+role] = true
					continue
				}
				rec := Record{Instance: name, Reason: c.why(name, role, a, now)}
				if err := c.unassign(ctx, a, rec); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	for _, name := range c.instanceNames() {
		// An entry whose assignments could not be read is left for the
		// next run (the run fails).
		rec := Record{Reason: "no active request holds the role"}
		remove := func(role string) bool { return !kept[name+"/"+role] && !failed[name+"/"+role] }
		if err := c.removeEntries(ctx, name, remove, rec); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) instanceNames() []string {
	names := make([]string, 0, len(c.Dir.Instances))
	for n := range c.Dir.Instances {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// why explains an assignment's removal.
func (c *Controller) why(instance, role string, a assignment, now time.Time) string {
	if instance == "" {
		return "the account is not an instance in instances.yaml"
	}
	if a.principalType != string(ssotypes.PrincipalTypeUser) {
		return "a group assignment: access is given to one operator at a time"
	}
	var last *Request
	for _, r := range c.Dir.SortedRequests() {
		if r.Instance == instance && r.Role == role && c.Dir.Operators[r.Operator].UserID == a.principalID && !now.Before(r.Begins()) {
			if last == nil || r.Expires().After(last.Expires()) {
				last = r
			}
		}
	}
	switch {
	case last == nil:
		return "no request for it"
	case last.Revoked != nil:
		return "request " + last.ID + " revoked: " + last.Revoked.Reason
	default:
		return "request " + last.ID + " expired at " + last.Expires().Format(time.RFC3339)
	}
}

// Begins is when the request's access begins.
func (r *Request) Begins() time.Time { return r.start }

// Grant is one current grant, as List shows it.
type Grant struct {
	Instance  string `json:"instance"`
	Account   string `json:"account"`
	Role      string `json:"role"`
	Principal string `json:"principal"`
	Operator  string `json:"operator,omitempty"`
	Request   string `json:"request,omitempty"`
	Expires   string `json:"expires,omitempty"`
	// Backed is false for access no active request backs (expire removes it).
	Backed bool `json:"backed"`
}

// List shows every assignment to a FAIR permission set and every FAIR
// access entry, with the request backing each.
func (c *Controller) List(ctx context.Context) ([]Grant, error) {
	now := c.now()
	var out []Grant
	var errs []error
	users := map[string]string{}
	for n, o := range c.Dir.Operators {
		users[o.UserID] = n
	}
	for _, role := range Roles {
		accounts, err := c.provisionedAccounts(ctx, role)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sort.Strings(accounts)
		for _, account := range accounts {
			name, _ := c.instanceOf(account)
			current, err := c.listAssignments(ctx, account, role)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, a := range current {
				g := Grant{Instance: name, Account: account, Role: role, Principal: a.principalType + ":" + a.principalID, Operator: users[a.principalID]}
				if a.principalType == string(ssotypes.PrincipalTypeUser) && name != "" {
					for _, r := range c.Dir.Active(now, name, role) {
						if c.Dir.Operators[r.Operator].UserID == a.principalID {
							g.Request, g.Expires, g.Backed = r.ID, r.Expires().Format(time.RFC3339), true
						}
					}
				}
				out = append(out, g)
			}
		}
	}
	for _, name := range c.instanceNames() {
		in := c.Dir.Instances[name]
		acct, err := c.Accounts(ctx, in.AccountID, in.Region)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entries, err := c.entries(ctx, acct, in)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range entries {
			role := c.roleOf(p, in.AccountID)
			if role == "" {
				continue
			}
			g := Grant{Instance: name, Account: in.AccountID, Role: role, Principal: p}
			for _, r := range c.Dir.Active(now, name, role) {
				if e := r.Expires().Format(time.RFC3339); e > g.Expires {
					g.Request, g.Expires, g.Backed = r.ID, e, true
				}
			}
			out = append(out, g)
		}
	}
	return out, errors.Join(errs...)
}

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"

	"github.com/rformer/fair-app/internal/accessctl"
)

var template = filepath.Join("..", "..", "deploy", "fleet", "access")

// empty is an AWS with no FAIR access anywhere.
type empty struct{ calls []string }

func (e *empty) CreateAccountAssignment(context.Context, *ssoadmin.CreateAccountAssignmentInput, ...func(*ssoadmin.Options)) (*ssoadmin.CreateAccountAssignmentOutput, error) {
	e.calls = append(e.calls, "CreateAccountAssignment")
	return nil, errors.New("not in this test")
}

func (e *empty) DeleteAccountAssignment(context.Context, *ssoadmin.DeleteAccountAssignmentInput, ...func(*ssoadmin.Options)) (*ssoadmin.DeleteAccountAssignmentOutput, error) {
	e.calls = append(e.calls, "DeleteAccountAssignment")
	return nil, errors.New("not in this test")
}

func (e *empty) DescribeAccountAssignmentCreationStatus(context.Context, *ssoadmin.DescribeAccountAssignmentCreationStatusInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentCreationStatusOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) DescribeAccountAssignmentDeletionStatus(context.Context, *ssoadmin.DescribeAccountAssignmentDeletionStatusInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribeAccountAssignmentDeletionStatusOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	e.calls = append(e.calls, "ListAccountAssignments")
	return &ssoadmin.ListAccountAssignmentsOutput{}, nil
}

func (e *empty) ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	e.calls = append(e.calls, "ListAccountsForProvisionedPermissionSet")
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{}, nil
}

func (e *empty) CreateAccessEntry(context.Context, *eks.CreateAccessEntryInput, ...func(*eks.Options)) (*eks.CreateAccessEntryOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) DescribeAccessEntry(context.Context, *eks.DescribeAccessEntryInput, ...func(*eks.Options)) (*eks.DescribeAccessEntryOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) DeleteAccessEntry(context.Context, *eks.DeleteAccessEntryInput, ...func(*eks.Options)) (*eks.DeleteAccessEntryOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) AssociateAccessPolicy(context.Context, *eks.AssociateAccessPolicyInput, ...func(*eks.Options)) (*eks.AssociateAccessPolicyOutput, error) {
	return nil, errors.New("not in this test")
}

func (e *empty) ListAccessEntries(context.Context, *eks.ListAccessEntriesInput, ...func(*eks.Options)) (*eks.ListAccessEntriesOutput, error) {
	e.calls = append(e.calls, "ListAccessEntries")
	return &eks.ListAccessEntriesOutput{}, nil
}

func (e *empty) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{}, nil
}

func (e *empty) clients(accessctl.ControllerConfig) (accessctl.SSOAdmin, accessctl.Accounts, error) {
	return e, func(context.Context, string, string) (*accessctl.Account, error) {
		return &accessctl.Account{EKS: e, IAM: e}, nil
	}, nil
}

func noAWS(accessctl.ControllerConfig) (accessctl.SSOAdmin, accessctl.Accounts, error) {
	return nil, nil, errors.New("AWS was not expected")
}

func runIt(t *testing.T, mk clients, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, mk, func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) })
	return code, out.String(), errb.String()
}

// F-012 T-18: check runs without AWS on the fleet template (CI's fleet job)
// and, given the base, refuses a changed merged request.
func TestCheck(t *testing.T) {
	if code, out, errs := runIt(t, noAWS, "check", "-dir", template); code != 0 || !strings.Contains(out, "1 requests, 2 operators, 1 instances: ok") {
		t.Fatalf("check: %d %q %q", code, out, errs)
	}
	if code, _, errs := runIt(t, noAWS, "check", "-dir", template, "-base", template); code != 0 {
		t.Fatalf("check against itself: %s", errs)
	}

	head := t.TempDir()
	for _, f := range []string{"controller.yaml", "operators.yaml", "instances.yaml", "requests/example-2026-11-26-read-only.yaml"} {
		b, err := os.ReadFile(filepath.Join(template, f)) // #nosec G304 -- test files
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(f, "requests/") {
			b = bytes.Replace(b, []byte("duration: 1h"), []byte("duration: 8h"), 1)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(head, f)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(head, f), b, 0o600); err != nil { // #nosec G703 -- test files
			t.Fatal(err)
		}
	}
	if code, _, errs := runIt(t, noAWS, "check", "-dir", head, "-base", template); code != 1 || !strings.Contains(errs, "may not change") {
		t.Errorf("a lengthened merged request: %d %s", code, errs)
	}
	if code, _, errs := runIt(t, noAWS, "check", "-dir", filepath.Join(head, "requests")); code != 1 || !strings.Contains(errs, "controller.yaml") {
		t.Errorf("not an access directory: %d %s", code, errs)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"apply"}, {"grant", "-dir", template}, {"revoke", "-dir", template, "x"}, {"expire", "-dir", template, "x"}} {
		if code, _, _ := runIt(t, noAWS, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// Without the web identity token file, nothing reaches AWS: access keys in
// the environment are not used.
func TestCredentialsOnlyFromTheTokenFile(t *testing.T) {
	t.Setenv("AWS_ROLE_ARN", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEEXAMPLE00")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ignored")
	code, _, errs := runIt(t, realClients, "expire", "-dir", template)
	if code != 1 || !strings.Contains(errs, "AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Errorf("%d %s", code, errs)
	}
}

// expire and list over an AWS with nothing to remove; records go to -record.
func TestExpireAndList(t *testing.T) {
	e := &empty{}
	rec := filepath.Join(t.TempDir(), "access.jsonl")
	if code, _, errs := runIt(t, e.clients, "expire", "-dir", template, "-record", rec); code != 0 {
		t.Fatalf("expire: %s", errs)
	}
	for _, c := range e.calls {
		if !strings.HasPrefix(c, "List") {
			t.Errorf("expire with nothing to do called %s", c)
		}
	}
	if _, err := os.Stat(rec); err != nil {
		t.Errorf("the record file: %v", err)
	}
	code, out, errs := runIt(t, e.clients, "list", "-dir", template)
	if code != 0 || !strings.HasPrefix(out, "INSTANCE") {
		t.Errorf("list: %d %q %s", code, out, errs)
	}
	// The example request is over: granting it is refused before AWS.
	if code, _, errs := runIt(t, e.clients, "grant", "-dir", template, "example-2026-11-26-read-only"); code != 1 || !strings.Contains(errs, "only from") {
		t.Errorf("grant of an expired request: %d %s", code, errs)
	}
}

// ADR-018: the AWS SDK's Identity Center, EKS and IAM clients are linked
// into accessctl only, and the SDK into no service: the services' images,
// SBOMs and scans stay without it. ADR-019 (F-014 T-06): the Helm SDK, and
// the Kubernetes and kustomize modules it brings, likewise reach only the
// release tools and the installer (releasegen, profilegen, fairctl).
func TestSDKLinkedOnlyIntoTools(t *testing.T) {
	g, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, g, "list", "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./cmd/...")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	const mod = "github.com/rformer/fair-app/cmd/"
	const sdk = "github.com/aws/aws-sdk-go-v2"
	awsTools := map[string]bool{mod + "accessctl": true, mod + "releasegen": true}
	helmTools := map[string]bool{mod + "releasegen": true, mod + "profilegen": true, mod + "fairctl": true}
	helmLinked := false
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg, deps, _ := strings.Cut(l, " ")
		for _, d := range strings.Fields(deps) {
			switch {
			case strings.HasPrefix(d, "helm.sh/helm/"), strings.HasPrefix(d, "k8s.io/"), strings.HasPrefix(d, "sigs.k8s.io/"):
				if !helmTools[pkg] {
					t.Errorf("%s links %s (ADR-019: tools only)", pkg, d)
				}
				helmLinked = helmLinked || pkg == mod+"releasegen" && strings.HasPrefix(d, "helm.sh/helm/v4/pkg/chart")
			case !strings.HasPrefix(d, sdk):
			case !awsTools[pkg]:
				t.Errorf("%s links %s", pkg, d)
			case pkg != mod+"accessctl" && (strings.HasPrefix(d, sdk+"/service/ssoadmin") || strings.HasPrefix(d, sdk+"/service/eks") || strings.HasPrefix(d, sdk+"/service/iam")):
				t.Errorf("%s links %s (accessctl's clients)", pkg, d)
			}
		}
	}
	if !helmLinked {
		t.Error("releasegen does not link the Helm SDK's chart packages (the check would prove nothing)")
	}
}

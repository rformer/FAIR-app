package accessctl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// F-012 T-18 (design §3.9; ADR-016, ADR-018): every client accessctl builds
// uses a FIPS endpoint in GovCloud, and credentials come only from the web
// identity token file.
func TestClientsUseFIPSEndpointsAndWebIdentity(t *testing.T) {
	t.Setenv("AWS_ROLE_ARN", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEEXAMPLE00")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-a-secret-but-must-be-ignored")
	cfg := testDir(t).Controller
	if _, err := NewClients(cfg); err == nil || !strings.Contains(err.Error(), "AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Fatalf("access keys in the environment are not credentials: %v", err)
	}

	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ROLE_ARN", "arn:aws-us-gov:iam::555555555555:role/fair-access-controller")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	c, err := NewClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.SSO.Options(); o.EndpointOptions.UseFIPSEndpoint != aws.FIPSEndpointStateEnabled || o.Region != "us-gov-west-1" {
		t.Errorf("sso-admin: FIPS %v, region %s", o.EndpointOptions.UseFIPSEndpoint, o.Region)
	}
	a, err := c.Accounts(context.Background(), "777777777777", "us-gov-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if o := a.EKS.(*eks.Client).Options(); o.EndpointOptions.UseFIPSEndpoint != aws.FIPSEndpointStateEnabled {
		t.Error("eks: not on its FIPS endpoint")
	}
	if o := a.IAM.(*iam.Client).Options(); o.EndpointOptions.UseFIPSEndpoint != aws.FIPSEndpointStateEnabled {
		t.Error("iam: not on its FIPS endpoint")
	}

	cfg.Partition = "aws"
	if _, err := NewClients(cfg); err == nil {
		t.Error("a commercial partition is refused")
	}
}

// The endpoints those options resolve to in GovCloud, by the SDK's rules
// (no network): in the aws-us-gov partition the FIPS endpoints are the
// services' GovCloud endpoints, which are FIPS 140-validated.
func TestFIPSEndpointsResolve(t *testing.T) {
	ctx := context.Background()
	region, fips := aws.String("us-gov-west-1"), aws.Bool(true)
	check := func(name, url, want string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if url != want {
			t.Errorf("%s resolves to %s, want %s", name, url, want)
		}
	}
	e1, err := ssoadmin.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, ssoadmin.EndpointParameters{Region: region, UseFIPS: fips})
	check("sso-admin", e1.URI.String(), "https://sso.us-gov-west-1.amazonaws.com", err)
	e2, err := eks.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, eks.EndpointParameters{Region: region, UseFIPS: fips})
	check("eks", e2.URI.String(), "https://eks.us-gov-west-1.amazonaws.com", err)
	e3, err := iam.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, iam.EndpointParameters{Region: region, UseFIPS: fips})
	check("iam", e3.URI.String(), "https://iam.us-gov.amazonaws.com", err)
	e4, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, sts.EndpointParameters{Region: region, UseFIPS: fips})
	check("sts", e4.URI.String(), "https://sts.us-gov-west-1.amazonaws.com", err)
}

package accessctl

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Clients are the real AWS clients: IAM Identity Center in the controller's
// region and each instance account's EKS and IAM through its EKS role. All
// use FIPS endpoints. The base credentials come only from the web identity
// token file AWS_WEB_IDENTITY_TOKEN_FILE for the role AWS_ROLE_ARN (the
// access workflow's OIDC token for fair-access-controller in the operations
// account); no access key is read from the environment or a file.
type Clients struct {
	SSO      *ssoadmin.Client
	Accounts Accounts

	base aws.CredentialsProvider
}

// NewClients builds the clients for a controller configuration.
func NewClients(cfg ControllerConfig) (*Clients, error) {
	role, tokenFile := os.Getenv("AWS_ROLE_ARN"), os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if role == "" || tokenFile == "" {
		return nil, errors.New("accessctl: AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE are required (the access workflow's OIDC token file)")
	}
	if cfg.Partition != "aws-us-gov" {
		return nil, fmt.Errorf("accessctl: partition %q: GovCloud only", cfg.Partition)
	}
	webSTS := sts.New(sts.Options{Region: cfg.Region, EndpointOptions: sts.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled}})
	base := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(webSTS, role, stscreds.IdentityTokenFile(tokenFile),
		func(o *stscreds.WebIdentityRoleOptions) { o.RoleSessionName = "fair-accessctl" }))
	c := &Clients{SSO: newSSOAdmin(cfg.Region, base), base: base}
	c.Accounts = func(_ context.Context, accountID, region string) (*Account, error) {
		return c.account(cfg, accountID, region), nil
	}
	return c, nil
}

func newSSOAdmin(region string, creds aws.CredentialsProvider) *ssoadmin.Client {
	return ssoadmin.New(ssoadmin.Options{
		Region:          region,
		Credentials:     creds,
		EndpointOptions: ssoadmin.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled},
	})
}

// account assumes cfg.EKSRole in the instance account (from the base
// credentials, through STS on its FIPS endpoint).
func (c *Clients) account(cfg ControllerConfig, accountID, region string) *Account {
	roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", cfg.Partition, accountID, cfg.EKSRole)
	s := sts.New(sts.Options{Region: region, Credentials: c.base, EndpointOptions: sts.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled}})
	creds := aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(s, roleARN, func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = "fair-accessctl" }))
	return &Account{
		EKS: eks.New(eks.Options{Region: region, Credentials: creds, EndpointOptions: eks.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled}}),
		IAM: iam.New(iam.Options{Region: region, Credentials: creds, EndpointOptions: iam.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled}}),
	}
}

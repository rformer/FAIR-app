// Package kmssign signs release artifacts with the release key held in AWS
// KMS (F-012 T-06, design §3.3, ADR-018): ECDSA P-256 over SHA-256, the key
// never leaving the KMS HSM (FIPS 140-validated). Signatures have the format
// file keys produce (profilepkg.Sign: base64 ASN.1 DER plus a newline), so
// profilepkg.VerifySignature, releasegen verify and the offline verifier
// check them with the release public key alone.
//
// Credentials come from a web identity token file (the release workflow's
// GitHub OIDC token, AWS_WEB_IDENTITY_TOKEN_FILE) exchanged through STS for
// the role AWS_ROLE_ARN, which may only kms:Sign with the release key. No
// credential is read from the environment or written anywhere; every call
// goes to a FIPS endpoint.
package kmssign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// API is the part of the KMS client the signer uses (a fake in tests).
type API interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs with one KMS key.
type Signer struct {
	api   API
	keyID string
	pub   *ecdsa.PublicKey
}

// New reads the key's public half and checks it is an ECDSA P-256 signing
// key; anything else is refused before anything is signed.
func New(ctx context.Context, api API, keyID string) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("kmssign: a key id, ARN or alias is required")
	}
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kmssign: public key of %s: %w", keyID, err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kmssign: %s is %s for %s; the release key is ECC_NIST_P256 for SIGN_VERIFY", keyID, out.KeySpec, out.KeyUsage)
	}
	k, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kmssign: public key of %s: %w", keyID, err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("kmssign: public key of %s is not ECDSA P-256", keyID)
	}
	return &Signer{api: api, keyID: keyID, pub: pub}, nil
}

// Public is the release public key.
func (s *Signer) Public() *ecdsa.PublicKey { return s.pub }

// PublicPEM is the release public key as PEM (PKIX), as cosign.pub and
// profilepkg.LoadPublicKey use it.
func (s *Signer) PublicPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Sign returns a detached signature over SHA-256 of b. KMS signs the digest;
// the signature is checked against the public key before it is returned, so
// a wrong key or a corrupted answer never becomes a release signature.
func (s *Signer) Sign(ctx context.Context, b []byte) ([]byte, error) {
	d := sha256.Sum256(b)
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          d[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kmssign: sign with %s: %w", s.keyID, err)
	}
	if !ecdsa.VerifyASN1(s.pub, d[:], out.Signature) {
		return nil, fmt.Errorf("kmssign: the signature from %s does not verify with its public key", s.keyID)
	}
	return []byte(base64.StdEncoding.EncodeToString(out.Signature) + "\n"), nil
}

// Client is a KMS client for region on its FIPS endpoint, with credentials
// from the web identity token file AWS_WEB_IDENTITY_TOKEN_FILE for the role
// AWS_ROLE_ARN (STS, also on its FIPS endpoint).
func Client(region string) (*kms.Client, error) {
	if region == "" {
		return nil, errors.New("kmssign: a region is required")
	}
	role, tokenFile := os.Getenv("AWS_ROLE_ARN"), os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if role == "" || tokenFile == "" {
		return nil, errors.New("kmssign: AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE are required (the release workflow's OIDC token file)")
	}
	stsc := sts.New(sts.Options{
		Region:          region,
		EndpointOptions: sts.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled},
	})
	creds := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(stsc, role, stscreds.IdentityTokenFile(tokenFile),
		func(o *stscreds.WebIdentityRoleOptions) { o.RoleSessionName = "fair-release-sign" }))
	return kms.New(kms.Options{
		Region:          region,
		Credentials:     creds,
		EndpointOptions: kms.EndpointResolverOptions{UseFIPSEndpoint: aws.FIPSEndpointStateEnabled},
	}), nil
}

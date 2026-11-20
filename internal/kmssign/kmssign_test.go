package kmssign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/rformer/fair-app/internal/profilepkg"
)

// fakeKMS holds a key as KMS would: it answers GetPublicKey and signs
// digests, and records what it was asked.
type fakeKMS struct {
	key     *ecdsa.PrivateKey
	spec    types.KeySpec
	usage   types.KeyUsageType
	corrupt bool
	fail    error
	signed  []*kms.SignInput
}

func newFake(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{key: k, spec: types.KeySpecEccNistP256, usage: types.KeyUsageTypeSignVerify}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.spec, KeyUsage: f.usage}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signed = append(f.signed, in)
	if f.fail != nil {
		return nil, f.fail
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, in.Message)
	if err != nil {
		return nil, err
	}
	if f.corrupt {
		sig[len(sig)-1] ^= 0xff
	}
	return &kms.SignOutput{Signature: sig}, nil
}

// F-012 T-06 (F-012-AC-08; design §3.3): a KMS signature has the file-key
// format and verifies with the release public key alone.
func TestSignMatchesFileKeyFormat(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	s, err := New(ctx, f, "alias/fair-release")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"format":"fair.release.v1"}`)
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := profilepkg.VerifySignature(&f.key.PublicKey, msg, sig); err != nil {
		t.Fatalf("not verifiable as a file-key signature: %v", err)
	}
	if err := profilepkg.VerifySignature(&f.key.PublicKey, []byte("other"), sig); err == nil {
		t.Fatal("verified over other bytes")
	}
	if !strings.HasSuffix(string(sig), "\n") || strings.Count(string(sig), "\n") != 1 {
		t.Fatalf("format %q", sig)
	}
	in := f.signed[0]
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != 32 || *in.KeyId != "alias/fair-release" {
		t.Fatalf("request %+v", in)
	}
	// The public key in PEM loads as the release public key.
	p, err := s.PublicPEM()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(file, p, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := profilepkg.LoadPublicKey(file)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(&f.key.PublicKey) {
		t.Fatal("PEM is another key")
	}
}

func TestRefusesOtherKeys(t *testing.T) {
	ctx := context.Background()
	for name, mut := range map[string]func(*fakeKMS){
		"P-384":   func(f *fakeKMS) { f.spec = types.KeySpecEccNistP384 },
		"RSA":     func(f *fakeKMS) { f.spec = types.KeySpecRsa2048 },
		"encrypt": func(f *fakeKMS) { f.usage = types.KeyUsageTypeEncryptDecrypt },
	} {
		f := newFake(t)
		mut(f)
		if _, err := New(ctx, f, "k"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(ctx, newFake(t), ""); err == nil {
		t.Error("empty key id accepted")
	}
}

// A signature KMS returns that does not verify, or a failed call, never
// becomes a release signature.
func TestFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	s, err := New(ctx, f, "k")
	if err != nil {
		t.Fatal(err)
	}
	f.corrupt = true
	if sig, err := s.Sign(ctx, []byte("m")); err == nil {
		t.Fatalf("corrupted signature returned: %q", sig)
	}
	f.corrupt, f.fail = false, errors.New("AccessDeniedException")
	if _, err := s.Sign(ctx, []byte("m")); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("err %v", err)
	}
}

func TestClientNeedsTokenFile(t *testing.T) {
	t.Setenv("AWS_ROLE_ARN", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	if _, err := Client("us-gov-west-1"); err == nil {
		t.Fatal("client without a token file")
	}
	t.Setenv("AWS_ROLE_ARN", "arn:aws-us-gov:iam::111111111111:role/fair-release-sign")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", t.TempDir()+"/token")
	if _, err := Client(""); err == nil {
		t.Fatal("client without a region")
	}
	c, err := Client("us-gov-west-1")
	if err != nil || c == nil {
		t.Fatal(err)
	}
}

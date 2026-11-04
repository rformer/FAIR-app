package objstore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// F-002 T-08 (design §6.3, §6.7; ADR-012).

func credFiles(t *testing.T, access, secret string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	a, s := filepath.Join(dir, "access"), filepath.Join(dir, "secret")
	if err := os.WriteFile(a, []byte(access+"\n"), 0o600); err != nil { // #nosec G703 -- a test temp file
		t.Fatal(err)
	}
	if err := os.WriteFile(s, []byte(secret+"\n"), 0o600); err != nil { // #nosec G703 -- a test temp file
		t.Fatal(err)
	}
	return a, s
}

func TestConfigRefusals(t *testing.T) {
	a, s := credFiles(t, "ak", "sk")
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	good := Config{Endpoint: "s3.example:443", Bucket: "b", AccessKeyFile: a, SecretKeyFile: s, Env: "production"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"no endpoint":              func(c *Config) { c.Endpoint = "" },
		"a scheme":                 func(c *Config) { c.Endpoint = "https://s3.example:443" },
		"no port":                  func(c *Config) { c.Endpoint = "s3.example" },
		"no bucket":                func(c *Config) { c.Bucket = "" },
		"no access key file":       func(c *Config) { c.AccessKeyFile = "" },
		"missing secret key file":  func(c *Config) { c.SecretKeyFile = filepath.Join(t.TempDir(), "nope") },
		"empty access key":         func(c *Config) { c.AccessKeyFile = empty },
		"plaintext in production":  func(c *Config) { c.Plaintext = true },
		"a CA file without a cert": func(c *Config) { c.CAFile = empty },
	} {
		c := good
		mut(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dev := good
	dev.Plaintext, dev.Env = true, "development"
	if _, err := New(dev); err != nil {
		t.Fatalf("plaintext in development: %v", err)
	}
	env := map[string]string{"X_ENDPOINT": "h:1", "X_BUCKET": "b", "X_REGION": "r", "X_ACCESS_KEY_FILE": a, "X_SECRET_KEY_FILE": s,
		"X_CA_FILE": "/ca", "X_PLAINTEXT": "true"}
	if c := FromEnv("X", "development", func(k string) string { return env[k] }); c.Endpoint != "h:1" || c.Bucket != "b" || c.Region != "r" ||
		c.AccessKeyFile != a || c.SecretKeyFile != s || c.CAFile != "/ca" || !c.Plaintext || c.Env != "development" {
		t.Fatalf("FromEnv: %+v", c)
	}
}

// TLS 1.2 is the floor: a store that offers only TLS 1.1 is refused before
// any request; one with TLS 1.2 is reached.
func TestTLSFloor(t *testing.T) {
	a, s := credFiles(t, "ak", "sk")
	for _, tc := range []struct {
		max   uint16
		reach bool
	}{{tls.VersionTLS11, false}, {tls.VersionTLS12, true}} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tc.max} // #nosec G402 -- the old version under test
		srv.StartTLS()
		ca := filepath.Join(t.TempDir(), "ca.pem")
		_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
		st, err := New(Config{Endpoint: strings.TrimPrefix(srv.URL, "https://"), Bucket: "bucket", AccessKeyFile: a, SecretKeyFile: s, CAFile: ca, Env: "production"})
		if err != nil {
			t.Fatal(err)
		}
		err = st.CheckBucket(context.Background())
		reached := err != nil && strings.Contains(err.Error(), "does not exist")
		if reached != tc.reach {
			t.Errorf("max TLS %x: reached %v (%v)", tc.max, reached, err)
		}
		srv.Close()
	}
}

// liveStore is the contract-test store: FAIR_TEST_S3=1 with
// FAIR_TEST_S3_ENDPOINT, _ACCESS_KEY, _SECRET_KEY and _CA_FILE
// (scripts/s3-test-server.sh starts one).
func liveStore(t *testing.T, lock bool) (*Store, *minio.Client, string) {
	t.Helper()
	if os.Getenv("FAIR_TEST_S3") != "1" {
		t.Skip("set FAIR_TEST_S3=1 (scripts/s3-test-server.sh) to run the object storage contract tests")
	}
	ep, ak, sk, ca := os.Getenv("FAIR_TEST_S3_ENDPOINT"), os.Getenv("FAIR_TEST_S3_ACCESS_KEY"), os.Getenv("FAIR_TEST_S3_SECRET_KEY"), os.Getenv("FAIR_TEST_S3_CA_FILE")
	a, s := credFiles(t, ak, sk)
	bucket := fmt.Sprintf("t%d", time.Now().UnixNano())
	st, err := New(Config{Endpoint: ep, Bucket: bucket, AccessKeyFile: a, SecretKeyFile: s, CAFile: ca, Env: "production"})
	if err != nil {
		t.Fatal(err)
	}
	// Bucket creation is the installer's (F-014); the test does it directly.
	pemCA, err := os.ReadFile(ca) // #nosec G304 G703 -- the test server CA
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCA)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	admin, err := minio.New(ep, &minio.Options{Creds: credentials.NewStaticV4(ak, sk, ""), Secure: true, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{ObjectLocking: lock, Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	return st, admin, bucket
}

func TestContractWORM(t *testing.T) {
	st, admin, bucket := liveStore(t, true)
	ctx := context.Background()
	if err := st.CheckBucket(ctx); err != nil {
		t.Fatal(err)
	}

	// A locked object: readable and digestible, not deletable until its
	// retention has passed.
	data := []byte("segment 1: bodies, leaves, checkpoint")
	until := time.Now().Add(4 * time.Second).Truncate(time.Second)
	v, err := st.Put(ctx, "segments/i/1.jsonl.zst", data, until)
	if err != nil || v.VersionID == "" {
		t.Fatalf("put: %+v %v", v, err)
	}
	if got, err := st.Get(ctx, v); err != nil || string(got) != string(data) {
		t.Fatalf("get: %q %v", got, err)
	}
	if d, err := st.Digest(ctx, v); err != nil || d != sha256.Sum256(data) {
		t.Fatalf("digest: %x %v", d, err)
	}
	if r, err := st.RetainedUntil(ctx, v); err != nil || !r.Equal(until.UTC()) {
		t.Fatalf("retained until %v (%v), want %v", r, err, until.UTC())
	}
	if err := st.Delete(ctx, v); err == nil {
		t.Fatal("a version under compliance retention was deleted")
	}
	if err := st.Delete(ctx, Version{Key: v.Key}); err == nil {
		t.Fatal("a delete without a version was accepted")
	}

	// A second write of the key is a new version; the first is untouched.
	v2, err := st.Put(ctx, v.Key, []byte("other"), time.Time{})
	if err != nil || v2.VersionID == v.VersionID {
		t.Fatalf("second version: %+v %v", v2, err)
	}
	if got, _ := st.Get(ctx, v); string(got) != string(data) {
		t.Fatal("the first version changed")
	}
	if r, err := st.RetainedUntil(ctx, v2); err != nil || !r.IsZero() {
		t.Fatalf("an unlocked version is retained until %v (%v)", r, err)
	}

	// A legal hold blocks deletion, whatever the retention (AC-29).
	h, err := st.Put(ctx, "checkpoints/i/7.json", []byte("{}"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetLegalHold(ctx, h, true); err != nil {
		t.Fatal(err)
	}
	if on, err := st.LegalHold(ctx, h); err != nil || !on {
		t.Fatalf("hold: %v %v", on, err)
	}
	if err := st.Delete(ctx, h); err == nil {
		t.Fatal("a held version was deleted")
	}
	if err := st.SetLegalHold(ctx, h, false); err != nil {
		t.Fatal(err)
	}
	if on, _ := st.LegalHold(ctx, h); on {
		t.Fatal("hold not released")
	}
	if err := st.Delete(ctx, h); err != nil {
		t.Fatalf("delete after release: %v", err)
	}

	// Listings show every version of every object under a prefix.
	objs, err := st.List(ctx, "segments/")
	if err != nil || len(objs) != 2 {
		t.Fatalf("list: %+v %v", objs, err)
	}
	if objs, _ := st.List(ctx, "checkpoints/"); len(objs) != 0 {
		t.Fatalf("a deleted version is still listed: %+v", objs)
	}
	if _, err := st.Get(ctx, h); err == nil {
		t.Fatal("a deleted version was read")
	}

	// Get is bounded (Open streams larger objects).
	if _, err := st.get(ctx, v2, 3); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a bounded get: %v", err)
	}
	if b, err := st.get(ctx, v2, 5); err != nil || string(b) != "other" {
		t.Fatalf("a get at the bound: %q %v", b, err)
	}

	// Only compliance retention counts: a governance-mode lock, which an
	// administrator can bypass, is reported as an error, not as retention.
	gov, err := admin.PutObject(ctx, bucket, "governed", strings.NewReader("g"), 1, minio.PutObjectOptions{Mode: minio.Governance,
		RetainUntilDate: time.Now().Add(time.Hour), SendContentMd5: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RetainedUntil(ctx, Version{Key: "governed", VersionID: gov.VersionID}); err == nil || !strings.Contains(err.Error(), "not compliance") {
		t.Fatalf("governance retention: %v", err)
	}
	// Delete markers (a delete without a version, which hides an object)
	// are not listed as objects; the hidden version still is.
	if _, err := st.Put(ctx, "checkpoints/marked", []byte("m"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := admin.RemoveObject(ctx, bucket, "checkpoints/marked", minio.RemoveObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if objs, err := st.List(ctx, "checkpoints/"); err != nil || len(objs) != 1 || objs[0].Latest {
		t.Fatalf("listing with a delete marker: %+v %v", objs, err)
	}

	// Once the retention has passed, the version can be removed.
	time.Sleep(time.Until(until) + 1500*time.Millisecond)
	if err := st.Delete(ctx, v); err != nil {
		t.Fatalf("delete after retention: %v", err)
	}
}

// A bucket without Object Lock is refused: records could be changed there.
func TestContractRefusesAPlainBucket(t *testing.T) {
	st, _, _ := liveStore(t, false)
	if err := st.CheckBucket(context.Background()); !errors.Is(err, ErrNotWORM) {
		t.Fatalf("a bucket without Object Lock: %v", err)
	}
	missing := *st
	missing.bucket = "no-such-bucket-" + fmt.Sprint(time.Now().UnixNano())
	if err := missing.CheckBucket(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing bucket: %v", err)
	}
}

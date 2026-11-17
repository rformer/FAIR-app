package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/reports"
)

// versionedMem is a memStore that lists every version of a key, as a
// versioned bucket does.
type versionedMem struct{ *memStore }

func (v versionedMem) List(_ context.Context, prefix string) ([]objstore.Object, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []objstore.Object
	for ver, b := range v.objects {
		if strings.HasPrefix(ver.Key, prefix) {
			out = append(out, objstore.Object{Version: ver, Size: int64(len(b))})
		}
	}
	return out, nil
}

// reportTestStore is the report store for retention tests: a versioned
// bucket on the S3 test server with FAIR_TEST_S3=1, else versionedMem.
type reportTestStore interface {
	reports.Store
	reports.PurgeStore
}

func reportStoreForTest(t *testing.T) reportTestStore {
	t.Helper()
	if os.Getenv("FAIR_TEST_S3") != "1" {
		return versionedMem{newMemStore()}
	}
	ep, ak, sk, ca := os.Getenv("FAIR_TEST_S3_ENDPOINT"), os.Getenv("FAIR_TEST_S3_ACCESS_KEY"), os.Getenv("FAIR_TEST_S3_SECRET_KEY"), os.Getenv("FAIR_TEST_S3_CA_FILE")
	dir := t.TempDir()
	akf, skf := filepath.Join(dir, "ak"), filepath.Join(dir, "sk")
	for f, v := range map[string]string{akf: ak, skf: sk} {
		if err := os.WriteFile(f, []byte(v), 0o600); err != nil { // #nosec G703 -- a test temp dir
			t.Fatal(err)
		}
	}
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
	bucket := fmt.Sprintf("rep%d", time.Now().UnixNano())
	ctx := context.Background()
	if err := admin.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	if err := admin.EnableVersioning(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	st, err := objstore.New(objstore.Config{Endpoint: ep, Bucket: bucket, AccessKeyFile: akf, SecretKeyFile: skf, CAFile: ca, Env: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CheckVersioned(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

// F-010 T-13 (F-010-AC-15; OQ8; design §3.6): files past
// report.retention_days are deleted, every version, and marked purged with
// report.files_purged; the run and its digests stay; younger files stay.
func TestReportRetention(t *testing.T) {
	ra := strideF003Fixture(t)
	seedPosture(t, ra.env)
	reportUsers(ra)
	re := reportAPI(t, ra)
	store := reportStoreForTest(t)
	re.worker.Store = store
	ctx := context.Background()
	generate := func() string {
		t.Helper()
		got := re.request(t, "pub", ra.bu["A1"], map[string]any{"formats": []string{"csv", "json"}})
		if got.code != 202 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		id := got.body["id"].(string)
		if err := re.attempt(t, id, 1); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old, young := generate(), generate()
	keys := strings.Split(ra.adminQuery("SELECT string_agg(object_key, ',' ORDER BY format) FROM report.file WHERE run_id = '"+old+"'"), ",")
	// A second version of one object: purging removes every version.
	if _, err := store.PutStream(ctx, keys[0], bytes.NewReader([]byte("again")), 5, time.Time{}); err != nil {
		t.Fatal(err)
	}
	versions := func(key string) int {
		objs, err := store.List(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, o := range objs {
			if o.Key == key {
				n++
			}
		}
		return n
	}
	if versions(keys[0]) != 2 || versions(keys[1]) != 1 {
		t.Fatalf("versions before: %d %d", versions(keys[0]), versions(keys[1]))
	}
	// Time travel: the old run's files were made 31 days ago.
	ra.admin(ra.db, "SET session_replication_role = replica; UPDATE report.file SET created_at = now() - interval '31 days' WHERE run_id = '"+old+"'")
	p := &reports.Purger{DB: ra.appPool(), Store: store, Retention: func() (int, error) { return 30, nil }}
	if n, err := p.Step(ctx); err != nil || n != 2 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if versions(keys[0]) != 0 || versions(keys[1]) != 0 {
		t.Errorf("versions after: %d %d", versions(keys[0]), versions(keys[1]))
	}
	if got := ra.adminQuery("SELECT string_agg(format || ':' || (purged_at IS NOT NULL) || ':' || length(sha256), ',' ORDER BY format) FROM report.file WHERE run_id = '" + old + "'"); got != "csv:true:64,json:true:64" {
		t.Errorf("the old run's files: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM report.file WHERE run_id = '" + young + "' AND purged_at IS NULL"); got != "2" {
		t.Errorf("the young run's files: %s", got)
	}
	if got := ra.adminQuery("SELECT body ->> 'severity' || ' ' || (body ->> 'actor') || ' ' || (body -> 'attributes' ->> 'formats') || ' ' || (body ->> 'bu_id') FROM audit.intake WHERE body ->> 'type' = 'report.files_purged' AND body ->> 'target' = 'report_run:" + old + "'"); got != "info system:risk csv json "+ra.bu["A1"] {
		t.Errorf("report.files_purged: %q", got)
	}
	// The run and its digests stay; its files answer 410.
	got := re.call(t, "GET", "pub", "/api/v1/reports/"+old, nil)
	if got.code != 200 || got.body["state"] != "succeeded" || !strings.Contains(got.raw, `"purged":true`) || !strings.Contains(got.raw, `"sha256":"`) {
		t.Errorf("the purged run: %d %s", got.code, got.raw)
	}
	if code, _, _ := re.download(t, "pub", old, "json"); code != 410 {
		t.Errorf("a purged file: %d", code)
	}
	// Nothing more to do; marked once.
	if n, err := p.Step(ctx); err != nil || n != 0 {
		t.Errorf("again: %d %v", n, err)
	}
	if out, err := ra.as("app_rw", "SELECT report.mark_purged('"+old+"', '{csv}')"); err != nil || !strings.Contains(out, "0") {
		t.Errorf("marked twice: %s %v", out, err)
	}
	// The setting's bounds hold.
	bad := &reports.Purger{DB: ra.appPool(), Store: store, Retention: func() (int, error) { return 0, nil }}
	if _, err := bad.Step(ctx); err == nil {
		t.Error("a retention of 0 days")
	}
	if _, err := ra.as("app_rw", "SELECT * FROM report.files_due(0, 10)"); err == nil {
		t.Error("files_due with 0 days")
	}
}

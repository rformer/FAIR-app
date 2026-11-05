package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/auditapi"
	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-002 T-15 (F-002-AC-32, AC-33, AC-34; design §5, §6.6): evidence exports.

// memStore is an in-memory ExportStore (the S3 path has its own test).
type memStore struct {
	mu      sync.Mutex
	objects map[objstore.Version][]byte
	locks   map[objstore.Version]time.Time
	n       int
	fail    error
	// corrupt makes reads return other bytes than were written.
	corrupt bool
}

func newMemStore() *memStore {
	return &memStore{objects: map[objstore.Version][]byte{}, locks: map[objstore.Version]time.Time{}}
}

func (s *memStore) PutStream(_ context.Context, key string, r io.Reader, size int64, until time.Time) (objstore.Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return objstore.Version{}, s.fail
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return objstore.Version{}, err
	}
	if int64(len(b)) != size {
		return objstore.Version{}, fmt.Errorf("put %s: %d bytes, size %d", key, len(b), size)
	}
	s.n++
	v := objstore.Version{Key: key, VersionID: fmt.Sprint(s.n)}
	s.objects[v], s.locks[v] = b, until
	return v, nil
}

func (s *memStore) read(v objstore.Version) ([]byte, error) {
	b, ok := s.objects[v]
	if !ok {
		return nil, errors.New("no such object")
	}
	if s.corrupt {
		b = append(bytes.Clone(b), 0)
	}
	return b, nil
}

func (s *memStore) Digest(_ context.Context, v objstore.Version) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.read(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func (s *memStore) Open(_ context.Context, v objstore.Version) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.read(v)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// exportEnv is the audit API fixture with exports: queued ids are
// collected (or handed to River), bundles kept in a memStore.
type exportEnv struct {
	auditAPIEnv
	store    *memStore
	exporter *auditsvc.Exporter
	mu       sync.Mutex
	queued   []string
}

func newExportEnv(t *testing.T, ae auditAPIEnv) *exportEnv {
	t.Helper()
	cp := checkpointer(t, ae.pool, newCheckpointKey(t))
	xe := &exportEnv{auditAPIEnv: ae, store: newMemStore()}
	xe.exporter = &auditsvc.Exporter{DB: ae.pool, Checkpointer: &cp, Store: xe.store, Archives: xe.store,
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ae.pool}), TempDir: t.TempDir()}
	xe.api(t, func(_ context.Context, _ pgx.Tx, id string) error {
		xe.mu.Lock()
		defer xe.mu.Unlock()
		xe.queued = append(xe.queued, id)
		return nil
	})
	return xe
}

// api serves the Audit API with exports, queuing jobs with enqueue.
func (xe *exportEnv) api(t *testing.T, enqueue func(context.Context, pgx.Tx, string) error) {
	t.Helper()
	pool := xe.pool
	api := &auditapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), Enqueue: enqueue, Bundles: xe.store}
	srv := httptest.NewServer(api.Handler(xe.keys, nil))
	t.Cleanup(srv.Close)
	xe.url = srv.URL
}

// do calls the API as user with an optional Idempotency-Key and JSON body.
func (ae auditAPIEnv) do(t *testing.T, user, method, path, key string, body any) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ae.url+auditapi.Prefix+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set(server.IdempotencyHeader, key)
	}
	if user != "" {
		p := ae.e.principal(user)
		tok, err := authz.MintJWT(ae.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "audit", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return apiResp{code: resp.StatusCode, body: m, raw: string(raw), hdr: resp.Header}
}

var idemSeq int

func idem() string {
	idemSeq++
	return fmt.Sprintf("export-key-%06d", idemSeq)
}

// request asks for an export as user and returns its id.
func (xe *exportEnv) request(t *testing.T, user string, filter map[string]string, format string) string {
	t.Helper()
	r := xe.do(t, user, "POST", "/exports", idem(), map[string]any{"filter": filter, "format": format, "reason": "quarterly access review"})
	if r.code != http.StatusAccepted || r.body["status"] != "pending" {
		t.Fatalf("export as %s: %d %s", user, r.code, r.raw)
	}
	if loc := r.hdr.Get("Location"); loc != auditapi.Prefix+"/exports/"+fmt.Sprint(r.body["export_id"]) {
		t.Fatalf("Location %q", loc)
	}
	return fmt.Sprint(r.body["export_id"])
}

// run makes export id and downloads and verifies its bundle against the
// trail's own keys.
func (xe *exportEnv) run(t *testing.T, user, id string) (evidence.ExportResult, map[string][]byte, string) {
	t.Helper()
	res, err := xe.exporter.Run(context.Background(), id)
	if err != nil || !res.Created {
		t.Fatalf("export %s: %+v %v", id, res, err)
	}
	b := xe.do(t, user, "GET", "/exports/"+id+"/bundle", "", nil)
	if b.code != http.StatusOK || b.hdr.Get("Content-Type") != "application/zip" {
		t.Fatalf("bundle: %d %s", b.code, b.raw)
	}
	sum := sha256.Sum256([]byte(b.raw))
	if want := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"; b.hdr.Get("Content-Digest") != want || sum != [32]byte(res.Digest) {
		t.Fatalf("digest: header %q, result %s, body %x", b.hdr.Get("Content-Digest"), res.Digest, sum)
	}
	v, err := evidence.VerifyExport(strings.NewReader(b.raw), int64(len(b.raw)), evidence.Keys(xe.e.signingKeys()))
	if err != nil || !v.Pinned || uint64(v.Records) != res.Records { // #nosec G115 -- a count
		t.Fatalf("fair-audit-verify verify-export: %+v %v", v, err)
	}
	return v, zipEntries(t, []byte(b.raw)), hex.EncodeToString(sum[:])
}

func zipEntries(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		out[f.Name], _ = io.ReadAll(rc)
		_ = rc.Close()
	}
	return out
}

// bodyIDs lists the ids of a bundle's record bodies, in order.
func bodyIDs(t *testing.T, lines []byte) string {
	t.Helper()
	var ids []string
	for _, l := range bytes.Split(bytes.TrimSpace(lines), []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		var b struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(l, &b); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, b.ID)
	}
	return strings.Join(ids, ",")
}

// trailEvents returns the recorded events of a type, oldest first.
func trailEvents(t *testing.T, ae auditAPIEnv, typ string) []map[string]any {
	t.Helper()
	drainTrail(t, ae.seq)
	raw := ae.e.adminQuery(fmt.Sprintf(`SELECT coalesce(jsonb_agg(convert_from(body, 'UTF8')::jsonb ORDER BY seq), '[]')
		FROM audit.record WHERE type = '%s'`, typ))
	var out []map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func attrs(ev map[string]any) map[string]any {
	a, _ := ev["attributes"].(map[string]any)
	return a
}

// AC-32, AC-34: a bundle that verifies with fair-audit-verify, stating its
// filter, and an export recorded at high severity with its filter, count
// and digest; downloads are recorded too.
func TestAuditExportBundle(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	filter := map[string]string{"type": "setting.change_requested"}
	id := xe.request(t, "rootaud", filter, "jsonl")
	if len(xe.queued) != 1 || xe.queued[0] != id {
		t.Fatalf("queued %v", xe.queued)
	}
	// Pending until the job has run.
	if r := xe.do(t, "rootaud", "GET", "/exports/"+id+"/bundle", "", nil); r.code != http.StatusConflict {
		t.Fatalf("a pending bundle: %d %s", r.code, r.raw)
	}
	res, files, digest := xe.run(t, "rootaud", id)
	m := res.Manifest

	// The records: the root auditor's visible ones (not restricted R's), in
	// order, with proofs into the checkpoint closed for the export.
	if got := bodyIDs(t, files[evidence.FileRecords]); got != "a1,root1,a2" {
		t.Fatalf("records %s", got)
	}
	var stored map[string]string
	_ = json.Unmarshal(m.Filter.Data, &stored)
	if stored["type"] != "setting.change_requested" || len(stored) != 1 || !strings.Contains(m.Filter.Description, "of type setting.change_requested") {
		t.Fatalf("manifest filter %+v", m.Filter)
	}
	rootaud := xe.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rootaud@example.test'")
	if m.RequestedBy != rootaud || m.Reason != "quarterly access review" || m.ExportID != id || m.RecordFormat != "jsonl" {
		t.Fatalf("manifest %+v", m)
	}
	scope := xe.e.adminQuery("SELECT string_agg(id::text, ',' ORDER BY id) FROM iam.bu WHERE NOT restricted")
	if strings.Join(m.BUScope, ",") != scope {
		t.Fatalf("bu_scope %v, want %s", m.BUScope, scope)
	}
	last := xe.e.adminQuery("SELECT max(segment) FROM audit.checkpoint")
	if res.Segments == 0 || lastCheckpointSegment(t, files) != last {
		t.Fatalf("%d checkpoints, the last %s; want the closing one %s", res.Segments, lastCheckpointSegment(t, files), last)
	}

	// The export as the API shows it.
	g := xe.do(t, "rootaud", "GET", "/exports/"+id, "", nil)
	if g.code != http.StatusOK || g.body["status"] != "ready" || fmt.Sprint(g.body["record_count"]) != "3" ||
		fmt.Sprint(g.body["checkpoint_segment"]) != last || g.body["digest"] != digest {
		t.Fatalf("export: %d %s", g.code, g.raw)
	}

	// AC-34: recorded at high severity with filter, count and digest.
	evs := trailEvents(t, xe.auditAPIEnv, "audit.exported")
	if len(evs) != 1 {
		t.Fatalf("%d audit.exported", len(evs))
	}
	a := attrs(evs[0])
	var recorded map[string]string
	_ = json.Unmarshal([]byte(fmt.Sprint(a["filter"])), &recorded)
	if evs[0]["severity"] != "high" || evs[0]["actor"] != rootaud || evs[0]["target"] != "audit:export:"+id || evs[0]["reason"] != "quarterly access review" ||
		a["status"] != "ready" || a["record_count"] != "3" || a["digest"] != g.body["digest"] || recorded["type"] != "setting.change_requested" ||
		a["checkpoint_segment"] != last || a["format"] != "jsonl" {
		t.Fatalf("audit.exported %v", evs[0])
	}
	fetched := trailEvents(t, xe.auditAPIEnv, "audit.export_fetched")
	if len(fetched) != 1 || attrs(fetched[0])["export_id"] != id || attrs(fetched[0])["digest"] != g.body["digest"] ||
		fetched[0]["severity"] != "low" || fetched[0]["actor"] != rootaud {
		t.Fatalf("audit.export_fetched %v", fetched)
	}
	// Reading the export's status is recorded as a read.
	if got := xe.e.adminQuery(`SELECT count(*) FROM audit.record WHERE type = 'audit.searched' AND convert_from(body, 'UTF8')::jsonb #>> '{attributes,view}' = 'export'`); got != "1" {
		t.Fatalf("%s export reads recorded", got)
	}

	// A finished export is not completed or made again.
	if _, err := xe.e.as("app_audit", fmt.Sprintf(`SELECT audit.export_complete('%s', 1, decode(repeat('00', 32), 'hex'), 1, 'k', 'v')`, id)); err == nil {
		t.Fatal("a ready export completed again")
	}
	if got := xe.e.adminQuery("SELECT record_count || ' ' || object_key FROM audit.export WHERE id = '" + id + "'"); got != "3 "+auditsvc.ExportKey(xe.e.adminQuery("SELECT instance FROM audit.head"), id) {
		t.Fatalf("the ready export changed: %s", got)
	}
	if again, err := xe.exporter.Run(context.Background(), id); err != nil || again.Created {
		t.Fatalf("second run: %+v %v", again, err)
	}
}

// lastCheckpointSegment is the segment of a bundle's last checkpoint.
func lastCheckpointSegment(t *testing.T, files map[string][]byte) string {
	t.Helper()
	cps, err := evidence.ReadCheckpoints(bytes.NewReader(files[evidence.FileCheckpoints]))
	if err != nil || len(cps) == 0 {
		t.Fatalf("checkpoints: %v", err)
	}
	var st struct {
		Segment uint64 `json:"segment"`
	}
	_ = json.Unmarshal(cps[len(cps)-1].Statement, &st)
	return fmt.Sprint(st.Segment)
}

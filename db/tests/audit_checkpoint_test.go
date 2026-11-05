package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-09 (F-002-AC-09, AC-10; design §6.3; ADR-011): checkpoints.

func newCheckpointKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// checkpointer is a Checkpointer recording its events to the trail.
func checkpointer(t *testing.T, pool *pgxpool.Pool, key *ecdsa.PrivateKey) auditsvc.Checkpointer {
	t.Helper()
	c := auditsvc.Checkpointer{DB: pool, Key: key, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	if err := c.RegisterKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func submitN(t *testing.T, e *env, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		submitAs(t, e, "app_rw", map[string]any{"id": fmt.Sprintf("%s-%d", prefix, i), "type": "db.migrated", "severity": "info", "actor": "x"})
	}
}

type storedCheckpoint struct {
	segment   int64
	statement []byte
	signature []byte
	wormKey   string
}

func (e *env) checkpoints() []storedCheckpoint {
	e.t.Helper()
	out := e.adminQuery(`SELECT coalesce(json_agg(json_build_object('segment', segment, 'statement', encode(statement, 'hex'),
		'signature', encode(signature, 'hex'), 'worm', coalesce(worm_key, '')) ORDER BY segment), '[]') FROM audit.checkpoint`)
	var rows []struct {
		Segment   int64  `json:"segment"`
		Statement string `json:"statement"`
		Signature string `json:"signature"`
		Worm      string `json:"worm"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		e.t.Fatal(err)
	}
	cps := make([]storedCheckpoint, len(rows))
	for i, r := range rows {
		st, _ := hex.DecodeString(r.Statement)
		sig, _ := hex.DecodeString(r.Signature)
		cps[i] = storedCheckpoint{segment: r.Segment, statement: st, signature: sig, wormKey: r.Worm}
	}
	return cps
}

// signingKeys reads the registered public keys, as a verifier would.
func (e *env) signingKeys() map[string]*ecdsa.PublicKey {
	e.t.Helper()
	out := e.adminQuery(`SELECT coalesce(json_object_agg(key_id, public_pem), '{}') FROM audit.signing_key`)
	var pems map[string]string
	if err := json.Unmarshal([]byte(out), &pems); err != nil {
		e.t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for id, p := range pems {
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			e.t.Fatalf("key %s: not PEM", id)
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			e.t.Fatal(err)
		}
		keys[id] = k.(*ecdsa.PublicKey)
	}
	return keys
}

// verifyCheckpoints checks every checkpoint with the offline verifier: the
// signatures, the links from the genesis, and each segment's records.
func (e *env) verifyCheckpoints(t *testing.T) []integrity.Statement {
	t.Helper()
	instance := e.adminQuery("SELECT instance FROM audit.head")
	stored := e.checkpoints()
	cps := make([]integrity.Checkpoint, len(stored))
	for i, c := range stored {
		cps[i] = integrity.Checkpoint{Statement: c.statement, Signature: c.signature}
	}
	sts, err := integrity.VerifyCheckpoints(instance, integrity.Genesis(instance), 1, cps, e.signingKeys())
	if err != nil {
		t.Fatalf("checkpoints do not verify: %v", err)
	}
	recs := e.trailRecords()
	prevChain := integrity.Genesis(instance)
	for _, s := range sts {
		var in []integrity.Record
		for _, r := range recs {
			if r.seq >= s.SeqFrom && r.seq <= s.SeqTo {
				var l, c integrity.Hash
				copy(l[:], r.leaf)
				copy(c[:], r.chain)
				in = append(in, integrity.Record{Seq: r.seq, Body: r.body, Leaf: l, Chain: c})
			}
		}
		if err := integrity.VerifySegment(s, prevChain, in); err != nil {
			t.Fatalf("segment %d: %v", s.Segment, err)
		}
		if s.Count() > 0 {
			prevChain = s.ChainHash
		}
		// The stored columns agree with the signed statement.
		if got := e.adminQuery(fmt.Sprintf("SELECT seq_from || ':' || seq_to || ':' || encode(merkle_root, 'hex') || ':' || encode(chain_hash, 'hex') || ':' || key_id FROM audit.checkpoint WHERE segment = %d", s.Segment)); got != fmt.Sprintf("%d:%d:%s:%s:%s", s.SeqFrom, s.SeqTo, s.MerkleRoot, s.ChainHash, s.KeyID) {
			t.Fatalf("segment %d columns %s", s.Segment, got)
		}
	}
	return sts
}

func TestAuditCheckpoints(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	seq := auditsvc.Sequencer{DB: pool}
	key1 := newCheckpointKey(t)
	c := checkpointer(t, pool, key1)

	// Segment 1: events, then a close.
	submitN(t, e, "a", 5)
	drainTrail(t, seq)
	st, err := c.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Segment != 1 || st.SeqFrom != 1 || st.SeqTo != 5 {
		t.Fatalf("segment 1: %+v", st)
	}
	if got := e.adminQuery("SELECT open_segment FROM audit.head"); got != "2" {
		t.Fatalf("open segment %s", got)
	}
	// The checkpoint event is in the trail (the SIEM copy, AC-10) with the
	// statement and signature, and it is recorded in the next segment.
	ev := e.adminQuery(`SELECT body::text FROM audit.intake WHERE body->>'type' = 'audit.checkpoint'`)
	var body struct {
		Target     string            `json:"target"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(ev), &body); err != nil {
		t.Fatalf("checkpoint event: %v (%s)", err, ev)
	}
	stored := e.checkpoints()
	sig, _ := base64.StdEncoding.DecodeString(body.Attributes["signature"])
	if body.Target != "checkpoint:1" || body.Attributes["segment"] != "1" || body.Attributes["seq_from"] != "1" || body.Attributes["seq_to"] != "5" ||
		body.Attributes["statement"] != string(stored[0].statement) || string(sig) != string(stored[0].signature) || body.Attributes["key_id"] != st.KeyID {
		t.Fatalf("checkpoint event %s", ev)
	}
	// An empty segment closes too (the event of the last close is in
	// intake, not yet sequenced).
	st, err = c.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Segment != 2 || st.SeqFrom != 6 || st.SeqTo != 5 || st.Count() != 0 || st.MerkleRoot != integrity.Root(nil) {
		t.Fatalf("empty segment 2: %+v", st)
	}
	// The checkpoint events are sequenced into segment 3 with more events.
	submitN(t, e, "b", 3)
	drainTrail(t, seq)
	if got := e.adminQuery("SELECT string_agg(DISTINCT segment::text, ',') FROM audit.record WHERE type = 'audit.checkpoint'"); got != "3" {
		t.Fatalf("checkpoint events in segment %s", got)
	}
	if _, err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// Rotation: a new key retires the old one; checkpoints made with either
	// still verify, and the chain of statements is unbroken.
	key2 := newCheckpointKey(t)
	c2 := checkpointer(t, pool, key2)
	if _, err := c.Close(ctx); err == nil || !strings.Contains(err.Error(), "PF014") {
		t.Fatalf("the retired key closed a segment: %v", err)
	}
	if err := c.RegisterKey(ctx); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("a retired key was registered again: %v", err)
	}
	if err := c2.RegisterKey(ctx); err != nil { // re-registering the active key is a no-op
		t.Fatal(err)
	}
	submitN(t, e, "c", 4)
	drainTrail(t, seq)
	if _, err := c2.Close(ctx); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, seq)
	if _, err := c2.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT count(*) FILTER (WHERE retired_at IS NULL) || ':' || count(*) FROM audit.signing_key"); got != "1:2" {
		t.Fatalf("signing keys %s", got)
	}
	sts := e.verifyCheckpoints(t)
	if len(sts) != 5 {
		t.Fatalf("%d checkpoints", len(sts))
	}
	id1, _ := integrity.KeyID(&key1.PublicKey)
	id2, _ := integrity.KeyID(&key2.PublicKey)
	if sts[2].KeyID != id1 || sts[3].KeyID != id2 {
		t.Fatalf("keys %s %s", sts[2].KeyID, sts[3].KeyID)
	}
	// Every record is covered by exactly one checkpoint, in order.
	recs := e.verifyTrail(t)
	if last := sts[len(sts)-1]; last.SeqTo != uint64(len(recs)) { // #nosec G115 -- test counts
		t.Fatalf("checkpoints end at %d, trail at %d", last.SeqTo, len(recs))
	}
}

func TestAuditCheckpointCadence(t *testing.T) {
	e := setup(t)
	pool := e.auditPool()
	c := checkpointer(t, pool, newCheckpointKey(t))
	// Run closes a segment each interval, empty ones included (AC-09).
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var errs []error
	_ = c.Run(ctx, 200*time.Millisecond, func(err error) { errs = append(errs, err) })
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	n, _ := strconv.Atoi(e.adminQuery("SELECT count(*) FROM audit.checkpoint"))
	if n < 4 || n > 8 {
		t.Fatalf("%d checkpoints in 1.5 s at 200 ms", n)
	}
	e.verifyCheckpoints(t)
	if auditsvc.CheckpointEvery != 15*time.Minute {
		t.Fatalf("cadence %s, design §6.3 says 15 minutes", auditsvc.CheckpointEvery)
	}
}

// The SQL Merkle root is the offline verifier's (RFC 9162).
func TestAuditMerkleRootParity(t *testing.T) {
	e := setup(t)
	for n := 0; n <= 33; n++ {
		leaves := make([]integrity.Hash, n)
		lits := make([]string, n)
		for i := range leaves {
			leaves[i] = integrity.Leaf([]byte(fmt.Sprintf(`{"n":%d,"i":%d}`, n, i)))
			lits[i] = "decode('" + leaves[i].String() + "', 'hex')"
		}
		got := e.adminQuery("SELECT encode(audit.merkle_root(ARRAY[" + strings.Join(lits, ",") + "]::bytea[]), 'hex')")
		if want := integrity.Root(leaves).String(); got != want {
			t.Fatalf("%d leaves: SQL %s, Go %s", n, got, want)
		}
	}
	if got := e.adminQuery("SELECT encode(audit.merkle_root(NULL), 'hex')"); got != integrity.Root(nil).String() {
		t.Fatalf("NULL: %s", got)
	}
}

func TestAuditCheckpointCloseRefusesForgeries(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	key := newCheckpointKey(t)
	c := checkpointer(t, pool, key)
	submitN(t, e, "f", 3)
	drainTrail(t, auditsvc.Sequencer{DB: pool})
	// Segment 1 closes honestly, so segment 2 has a real link to check.
	if _, err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, auditsvc.Sequencer{DB: pool})
	submitN(t, e, "g", 2)
	drainTrail(t, auditsvc.Sequencer{DB: pool})

	var instance string
	var segment, from, to int64
	var chain, prev []byte
	var leaves [][]byte
	if err := pool.QueryRow(ctx, "SELECT instance, segment, seq_from, seq_to, chain_hash, prev_checkpoint_hash, leaves FROM audit.checkpoint_state()").
		Scan(&instance, &segment, &from, &to, &chain, &prev, &leaves); err != nil {
		t.Fatal(err)
	}
	hs := make([]integrity.Hash, len(leaves))
	for i := range leaves {
		copy(hs[i][:], leaves[i])
	}
	keyID, _ := integrity.KeyID(&key.PublicKey)
	honest := func() map[string]any {
		st := integrity.Statement{V: 1, Instance: instance, Segment: uint64(segment), SeqFrom: uint64(from), SeqTo: uint64(to), // #nosec G115 -- test positions
			MerkleRoot: integrity.Root(hs), IssuedAt: time.Now().UTC().Truncate(time.Microsecond), KeyID: keyID}
		copy(st.ChainHash[:], chain)
		copy(st.PrevCheckpointHash[:], prev)
		b, _ := st.Marshal()
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	other := newCheckpointKey(t)
	otherID, _ := integrity.KeyID(&other.PublicKey)
	flip := func(h string) string {
		b, _ := hex.DecodeString(h)
		b[0] ^= 1
		return hex.EncodeToString(b)
	}
	sig := []byte("0123456789abcdef")
	try := func(name string, stmt []byte, sig []byte) {
		t.Helper()
		if _, err := pool.Exec(ctx, "SELECT audit.checkpoint_close($1, $2)", stmt, sig); err == nil || !strings.Contains(err.Error(), "PF014") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(m map[string]any){
		"wrong version":    func(m map[string]any) { m["v"] = 2 },
		"no version":       func(m map[string]any) { delete(m, "v") },
		"another instance": func(m map[string]any) { m["instance"] = "elsewhere" },
		"another segment":  func(m map[string]any) { m["segment"] = segment + 1 },
		"no segment":       func(m map[string]any) { delete(m, "segment") },
		"seq_from moved":   func(m map[string]any) { m["seq_from"] = from + 1 },
		"seq_to short":     func(m map[string]any) { m["seq_to"] = to - 1 },
		"seq_to long":      func(m map[string]any) { m["seq_to"] = to + 1 },
		"no seq_to":        func(m map[string]any) { delete(m, "seq_to") },
		"wrong root":       func(m map[string]any) { m["merkle_root"] = flip(m["merkle_root"].(string)) },
		"no root":          func(m map[string]any) { delete(m, "merkle_root") },
		"wrong chain":      func(m map[string]any) { m["chain_hash"] = flip(m["chain_hash"].(string)) },
		"no chain":         func(m map[string]any) { delete(m, "chain_hash") },
		"broken link":      func(m map[string]any) { m["prev_checkpoint_hash"] = flip(m["prev_checkpoint_hash"].(string)) },
		"no link":          func(m map[string]any) { delete(m, "prev_checkpoint_hash") },
		"unknown key":      func(m map[string]any) { m["key_id"] = otherID },
		"no key":           func(m map[string]any) { delete(m, "key_id") },
		"stale issue time": func(m map[string]any) {
			m["issued_at"] = time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
		},
		"future issue time": func(m map[string]any) {
			m["issued_at"] = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
		},
		"no issue time":      func(m map[string]any) { delete(m, "issued_at") },
		"garbled issue time": func(m map[string]any) { m["issued_at"] = "yesterday" },
	} {
		m := honest()
		mut(m)
		b, _ := json.Marshal(m)
		try(name, b, sig)
	}
	try("not JSON", []byte("not json"), sig)
	try("a JSON array", []byte("[1]"), sig)
	h, _ := json.Marshal(honest())
	try("no signature", h, nil)
	try("a short signature", h, []byte("x"))
	// A retired key is refused like an unknown one.
	c2 := checkpointer(t, pool, newCheckpointKey(t))
	try("a retired key", h, sig)
	if n := e.adminQuery("SELECT count(*) FROM audit.checkpoint"); n != "1" {
		t.Fatalf("%s checkpoints after forgeries", n)
	}
	if _, err := c2.Close(ctx); err != nil {
		t.Fatal(err)
	}
	e.verifyCheckpoints(t)

	// Keys: the id must be the key's, and the PEM a public key.
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sum := sha256.Sum256(der)
	for name, args := range map[string][2]string{
		"a retired key's id": {keyID, p},
		"an unknown id":      {strings.Repeat("ab", 32), p},
		"a malformed id":     {"abc", p},
		"not PEM":            {hex.EncodeToString(sum[:]), "-----BEGIN PRIVATE KEY-----"},
	} {
		if _, err := pool.Exec(ctx, "SELECT audit.signing_key_register($1, $2)", args[0], args[1]); err == nil || !strings.Contains(err.Error(), "PF004") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The write-once copy's key is set once, and only on a checkpoint.
	if _, err := pool.Exec(ctx, "SELECT audit.checkpoint_set_worm(1, '')"); err == nil || !strings.Contains(err.Error(), "PF004") {
		t.Errorf("empty object key: %v", err)
	}
	if _, err := pool.Exec(ctx, "SELECT audit.checkpoint_set_worm(1, 'checkpoints/x/1.json')"); err != nil {
		t.Fatal(err)
	}
	for _, seg := range []string{"1", "99"} {
		if _, err := pool.Exec(ctx, "SELECT audit.checkpoint_set_worm("+seg+", 'checkpoints/x/other.json')"); err == nil || !strings.Contains(err.Error(), "PF003") {
			t.Errorf("segment %s: %v", seg, err)
		}
	}
	// Only the audit service checkpoints.
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		e.mustFail(role, "SELECT * FROM audit.checkpoint_state()", "permission denied")
		e.mustFail(role, "SELECT audit.checkpoint_close('{}', 'x')", "permission denied")
		e.mustFail(role, "SELECT audit.signing_key_register('a', 'b')", "permission denied")
		e.mustFail(role, "SELECT * FROM audit.checkpoint_unsaved(1)", "permission denied")
		e.mustFail(role, "SELECT audit.checkpoint_set_worm(1, 'k')", "permission denied")
		e.mustFail(role, "SELECT audit.merkle_root('{}')", "permission denied")
	}
	e.mustFail("app_audit", "SELECT audit.merkle_root('{}')", "permission denied")
}

// testWORM is a write-once bucket on the S3 test server (FAIR_TEST_S3=1,
// scripts/s3-test-server.sh), as internal/objstore's contract tests use.
func testWORM(t *testing.T) (*objstore.Store, *minio.Client, string) {
	t.Helper()
	if os.Getenv("FAIR_TEST_S3") != "1" {
		t.Skip("set FAIR_TEST_S3=1 (scripts/s3-test-server.sh) to test write-once checkpoint copies")
	}
	ep, ak, sk, ca := os.Getenv("FAIR_TEST_S3_ENDPOINT"), os.Getenv("FAIR_TEST_S3_ACCESS_KEY"), os.Getenv("FAIR_TEST_S3_SECRET_KEY"), os.Getenv("FAIR_TEST_S3_CA_FILE")
	dir := t.TempDir()
	akf, skf := filepath.Join(dir, "ak"), filepath.Join(dir, "sk")
	if err := os.WriteFile(akf, []byte(ak), 0o600); err != nil { // #nosec G703 -- a test temp dir
		t.Fatal(err)
	}
	if err := os.WriteFile(skf, []byte(sk), 0o600); err != nil { // #nosec G703 -- a test temp dir
		t.Fatal(err)
	}
	bucket := fmt.Sprintf("cp%d", time.Now().UnixNano())
	st, err := objstore.New(objstore.Config{Endpoint: ep, Bucket: bucket, AccessKeyFile: akf, SecretKeyFile: skf, CAFile: ca, Env: "production"})
	if err != nil {
		t.Fatal(err)
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
	if err := admin.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{ObjectLocking: true, Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckBucket(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st, admin, bucket
}

// AC-10: every checkpoint is copied to write-once storage, locked for the
// total retention, and recorded; copies that fail are retried.
func TestAuditCheckpointWORMCopies(t *testing.T) {
	e := setup(t)
	worm, admin, bucket := testWORM(t)
	ctx := context.Background()
	pool := e.auditPool()
	c := checkpointer(t, pool, newCheckpointKey(t))
	c.Retain = func() time.Duration { return 48 * time.Hour }
	submitN(t, e, "w", 3)
	drainTrail(t, auditsvc.Sequencer{DB: pool})
	// Two closes before the store is reachable: both copies are pending.
	for i := 0; i < 2; i++ {
		if _, err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := c.SaveCopies(ctx); n != 0 || err != nil { // no store configured
		t.Fatalf("without a store: %d %v", n, err)
	}
	c.WORM = worm
	n, err := c.SaveCopies(ctx)
	if err != nil || n != 2 {
		t.Fatalf("saved %d: %v", n, err)
	}
	if n, err := c.SaveCopies(ctx); n != 0 || err != nil {
		t.Fatalf("saved again: %d %v", n, err)
	}
	instance := e.adminQuery("SELECT instance FROM audit.head")
	for _, cp := range e.checkpoints() {
		if want := auditsvc.CopyKey(instance, cp.segment); cp.wormKey != want {
			t.Fatalf("segment %d recorded at %q, want %q", cp.segment, cp.wormKey, want)
		}
		objs, err := worm.List(ctx, cp.wormKey)
		if err != nil || len(objs) != 1 {
			t.Fatalf("segment %d: %+v %v", cp.segment, objs, err)
		}
		v := objstore.Version{Key: objs[0].Key, VersionID: objs[0].VersionID}
		data, err := worm.Get(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		var copyOf integrity.Checkpoint
		if err := json.Unmarshal(data, &copyOf); err != nil || string(copyOf.Statement) != string(cp.statement) || string(copyOf.Signature) != string(cp.signature) {
			t.Fatalf("segment %d copy %s (%v)", cp.segment, data, err)
		}
		until, err := worm.RetainedUntil(ctx, v)
		if err != nil || time.Until(until) < 47*time.Hour {
			t.Fatalf("segment %d retained until %s (%v)", cp.segment, until, err)
		}
		// Locked in compliance mode: not even the bucket owner deletes it.
		if err := admin.RemoveObject(ctx, bucket, v.Key, minio.RemoveObjectOptions{VersionID: v.VersionID, GovernanceBypass: true}); err == nil {
			t.Fatalf("segment %d copy deleted", cp.segment)
		}
	}
	e.verifyCheckpoints(t)
}

// T-10 (AC-11): evidence built from a real trail verifies offline with
// fair-audit-verify's code: segment archives, an export of a filtered set,
// and the platform's checkpoints against the checkpoint events forwarded to
// a SIEM (the trail's own audit.checkpoint record bodies).
func TestAuditEvidenceFromTheTrail(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	seq := auditsvc.Sequencer{DB: pool}
	c := checkpointer(t, pool, newCheckpointKey(t))
	for i, n := range []int{4, 0, 6, 3} {
		submitN(t, e, fmt.Sprintf("s%d", i), n)
		drainTrail(t, seq)
		if i == 2 { // rotate the key mid-trail
			c = checkpointer(t, pool, newCheckpointKey(t))
		}
		if _, err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	keys := evidence.Keys(e.signingKeys())
	stored := e.checkpoints()
	cps := make([]integrity.Checkpoint, len(stored))
	for i, s := range stored {
		cps[i] = integrity.Checkpoint{Statement: s.statement, Signature: s.signature}
	}
	chain, err := evidence.VerifyChain(cps, keys)
	if err != nil {
		t.Fatal(err)
	}
	recs := e.trailRecords()
	bySeg := map[uint64][]integrity.Record{}
	segOf := map[uint64]uint64{}
	for _, st := range chain.Statements {
		for _, r := range recs {
			if r.seq >= st.SeqFrom && r.seq <= st.SeqTo {
				var l, ch integrity.Hash
				copy(l[:], r.leaf)
				copy(ch[:], r.chain)
				bySeg[st.Segment] = append(bySeg[st.Segment], integrity.Record{Seq: r.seq, Body: r.body, Leaf: l, Chain: ch})
				segOf[r.seq] = st.Segment
			}
		}
	}

	// Archives of every closed segment.
	var archives []evidence.NamedArchive
	for i, st := range chain.Statements {
		var buf bytes.Buffer
		if err := evidence.WriteSegment(&buf, evidence.Segment{Checkpoint: cps[i], Records: bySeg[st.Segment]}); err != nil {
			t.Fatal(err)
		}
		b := buf.Bytes()
		archives = append(archives, evidence.NamedArchive{Name: evidence.SegmentKey(st.Instance, st.Segment),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }})
	}
	res, err := evidence.VerifyArchives(archives, cps, keys)
	if err != nil || len(res.Segments) != len(cps) || !res.Anchored {
		t.Fatalf("archives: %+v %v", res, err)
	}

	// An export of every other covered record, signed with the current key.
	in := evidence.ExportInput{Manifest: evidence.Manifest{Instance: chain.Instance(), ExportID: "x", CreatedAt: time.Now().UTC(),
		RequestedBy: "auditor", Reason: "test", Filter: evidence.Filter{Description: "every other record"}}, Checkpoints: cps, Keys: keys}
	for _, r := range recs {
		seg, ok := segOf[r.seq]
		if !ok || r.seq%2 == 0 {
			continue
		}
		st, _ := chain.Segment(seg)
		var leaves []integrity.Hash
		for _, x := range bySeg[seg] {
			leaves = append(leaves, x.Leaf)
		}
		path, err := integrity.NewTree(leaves).Path(r.seq - st.SeqFrom)
		if err != nil {
			t.Fatal(err)
		}
		in.Bodies = append(in.Bodies, r.body)
		in.Proofs = append(in.Proofs, evidence.Proof{Seq: r.seq, Segment: seg, Path: path})
	}
	var bundle bytes.Buffer
	if err := evidence.WriteExport(&bundle, in, c.Key); err != nil {
		t.Fatal(err)
	}
	if res, err := evidence.VerifyExport(bytes.NewReader(bundle.Bytes()), int64(bundle.Len()), keys); err != nil || res.Records != len(in.Bodies) || res.Records == 0 {
		t.Fatalf("export: %+v %v", res, err)
	}

	// The SIEM's copy: the checkpoint events as recorded in the trail
	// (each close's event is sequenced after it; the drain records the
	// last one).
	drainTrail(t, seq)
	var siem bytes.Buffer
	for _, r := range e.trailRecords() {
		siem.Write(append(r.body, '\n'))
	}
	ext, err := evidence.ReadCheckpointStream(&siem, "trail")
	if err != nil {
		t.Fatal(err)
	}
	platform := evidence.CheckpointSet{}
	for i, st := range chain.Statements {
		platform[st.Segment] = cps[i]
	}
	if d := evidence.Compare(platform, ext, 1, uint64(len(cps))); d != nil { // #nosec G115 -- test count
		t.Fatalf("SIEM copy: %v", d)
	}
}

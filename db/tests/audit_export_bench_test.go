package tests

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-002 T-15 (design §6.6: 1 million records in at most 5 minutes): one
// export of 1 million records, filed under the F-001 target-scale tree
// (2,000 BUs), by an auditor at the root, through the export job's code
// (audit.Exporter: closing checkpoint, batched reads, Merkle paths, the
// streamed bundle and its upload). The bundle is then verified as
// fair-audit-verify does.

const (
	auditExportRecords = 1_000_000
	auditExportBudget  = 5 * time.Minute
	auditExportSegment = 50_000 // records per segment (about 15 minutes at 55 events a second)
)

// fileStore keeps bundles in a directory (a million-record bundle is too
// large to hold in memory twice).
type fileStore struct{ dir string }

func (s fileStore) PutStream(_ context.Context, key string, r io.Reader, _ int64, _ time.Time) (objstore.Version, error) {
	p := filepath.Join(s.dir, strings.ReplaceAll(key, "/", "_"))
	f, err := os.Create(p) // #nosec G304 -- a test temp dir
	if err != nil {
		return objstore.Version{}, err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, r); err != nil {
		return objstore.Version{}, err
	}
	return objstore.Version{Key: key, VersionID: "1"}, f.Close()
}

func (s fileStore) Open(_ context.Context, v objstore.Version) (io.ReadCloser, error) {
	return os.Open(filepath.Join(s.dir, strings.ReplaceAll(v.Key, "/", "_"))) // #nosec G304 -- a test temp dir
}

func TestBenchmarkGateAuditExport(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	ctx := context.Background()
	n := auditExportRecords
	if s := os.Getenv("FAIR_BENCH_AUDIT_EXPORT_RECORDS"); s != "" { // a smaller run, by hand
		n, _ = strconv.Atoi(s)
	}
	pool := e.auditPool()
	cp := checkpointer(t, pool, newCheckpointKey(t))

	// An auditor at the root.
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('benchexport@example.test', 'Bench Export')`)
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Auditor'), (SELECT id FROM iam.bu WHERE parent_id IS NULL), '%s'
		FROM iam.app_user u WHERE u.email = 'benchexport@example.test'`, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	row := strings.Split(e.mustOwner(`SELECT u.id || '|' || s.scope_version FROM iam.app_user u JOIN authz.user_scope s ON s.user_id = u.id
		WHERE u.email = 'benchexport@example.test'`), "|")
	userID := row[0]
	version, _ := strconv.ParseInt(row[1], 10, 64)

	// The records, with real leaf hashes over canonical bodies (ADR-011),
	// over the last 30 days, cycling through the BUs the auditor can see (so
	// all of them are exported; restricted BUs need their own assignment).
	start := time.Now()
	if _, err := pool.Exec(ctx, "SELECT * FROM audit.sequence_head()"); err != nil { // the head (instance)
		t.Fatal(err)
	}
	for m := 0; m <= 1; m++ {
		e.adminQuery(fmt.Sprintf("SELECT audit.ensure_partition(now() - interval '%d months')", m))
	}
	const batch = 250_000
	for lo := 1; lo <= n; lo += batch {
		hi := min(lo+batch-1, n)
		e.admin(e.db, fmt.Sprintf(`SET session_replication_role = replica;
			WITH b AS (SELECT array_agg(v.value::uuid ORDER BY md5(v.value)) AS ids
			           FROM authz.user_scope s, jsonb_array_elements_text(s.read_bus -> 'audit') v WHERE s.user_id = '%[5]s'),
			     x AS (SELECT i, now() - interval '30 days' + ((i::float8 / %[3]d) * interval '30 days') AS t, b.ids[1 + i %% cardinality(b.ids)] AS bu,
			                  'type.' || (i %% 20) AS ty, 'actor-' || (i %% 5000) AS actor, 'target:' || (i %% 100000) AS target
			           FROM generate_series(%[1]d, %[2]d) i, b),
			     y AS (SELECT x.*, convert_to('{"actor":"' || actor || '","bu_id":"' || bu || '","id":"ev-' || i || '","severity":"low","target":"' ||
			                  target || '","time":"' || to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '","type":"' || ty || '"}', 'UTF8') AS body
			           FROM x)
			INSERT INTO audit.record (seq, event_id, event_time, received_at, producer, type, category, severity, actor, target, bu_id,
			                          request_id, source_ip, approval_id, skew, body, leaf_hash, chain_hash, segment)
			SELECT i, 'ev-' || i, t, t, 'app_rw', ty, 'access', 'low', actor, target, bu, NULL, NULL, NULL, false,
			       body, sha256('\x00'::bytea || body), decode(repeat('00', 32), 'hex'), (i - 1) / %[4]d + 1
			FROM y`, lo, hi, n, auditExportSegment, userID))
	}
	e.admin(e.db, "ANALYZE audit.record")
	t.Logf("loaded %d records in %v", n, time.Since(start).Round(time.Second))

	// Their segments, closed by the checkpointer as the leader would.
	segments := (n-1)/auditExportSegment + 1
	for s := 1; s <= segments; s++ {
		to := min(s*auditExportSegment, n)
		e.admin(e.db, fmt.Sprintf("UPDATE audit.head SET seq = %d, open_segment = %d", to, s))
		if _, err := cp.Close(ctx); err != nil {
			t.Fatalf("segment %d: %v", s, err)
		}
	}
	t.Logf("%d segments closed: %v", segments, time.Since(start).Round(time.Second))

	// The export: requested in the auditor's DB context, then made.
	tok, err := authz.MintDBContext(ctxKey1, userID, version, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", tok); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT audit.export_request('{}', 'jsonl', 'benchmark')::text").Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	x := auditsvc.Exporter{DB: pool, Checkpointer: &cp, Store: fileStore{dir: dir}, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), TempDir: dir}
	t0 := time.Now()
	res, err := x.Run(ctx, id)
	took := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, strings.ReplaceAll(res.Object.Key, "/", "_")))
	var size int64
	if st != nil {
		size = st.Size()
	}
	visible := e.mustOwner("SELECT jsonb_array_length(read_bus -> 'audit') FROM authz.user_scope WHERE user_id = '" + userID + "'")
	rep := fmt.Sprintf("F-002 audit export: %d records over %d segments, filed under the %s BUs an auditor at the root sees (of 2,011); %v (budget %v), bundle %d MiB\n",
		res.Records, segments+1, visible, took.Round(time.Second), auditExportBudget, size>>20)
	t.Log(rep)
	if path := os.Getenv("FAIR_BENCH_REPORT"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- CI report path
		if err == nil {
			_, _ = f.WriteString("\n" + rep)
			_ = f.Close()
		}
	}
	if res.Records != uint64(n) { // #nosec G115
		t.Fatalf("exported %d of %d records", res.Records, n)
	}
	if took > auditExportBudget {
		t.Fatalf("export over budget: %v", took)
	}

	// The bundle verifies.
	f, err := fileStore{dir: dir}.Open(ctx, res.Object)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	v, err := evidence.VerifyExport(f.(*os.File), size, evidence.Keys(e.signingKeys()))
	if err != nil || v.Records != n {
		t.Fatalf("verify: %d records, %v", v.Records, err)
	}
}

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/objstore"
	events "github.com/rformer/fair-app/pkg/audit"
)

// ExportStore keeps export bundles (objstore.Store: the audit store,
// FAIR_AUDIT_STORE_*).
type ExportStore interface {
	PutStream(ctx context.Context, key string, r io.Reader, size int64, retainUntil time.Time) (objstore.Version, error)
	Open(ctx context.Context, v objstore.Version) (io.ReadCloser, error)
}

// ExportRetention is how long a bundle is locked in the store.
const ExportRetention = 30 * 24 * time.Hour

// exportBatch is how many records one read returns.
const exportBatch = 10_000

// ErrExportGone is returned for an export that does not exist.
var ErrExportGone = errors.New("audit export: no such export")

// ExportKey is where an export's bundle is stored.
func ExportKey(instance, id string) string { return fmt.Sprintf("exports/%s/%s.zip", instance, id) }

// ExportCSVHeader is the CSV view's header (record format csv); the bodies
// in bodies.jsonl are what is verified.
var ExportCSVHeader = []string{"seq", "event_id", "time", "received_at", "producer", "type", "category", "severity", "actor", "target",
	"bu_id", "request_id", "source_ip", "approval_id", "skew", "segment", "reason"}

// Exporter makes evidence exports (F-002 T-15, AC-32 to AC-34; design §6.6):
// it closes a segment so the export ends at a fresh signed checkpoint, reads
// the records matching the export's filter in the scope captured when it
// was requested (audit.export_rows), writes the bundle (internal/audit/
// evidence: records, proofs, checkpoints, keys, signed manifest) to a
// temporary file, stores it, then marks the export ready and records
// audit.exported in one transaction.
type Exporter struct {
	DB           *pgxpool.Pool // app_audit
	Checkpointer *Checkpointer // closes the export's segment; its key signs the manifest
	Store        ExportStore
	Audit        events.Emitter
	TempDir      string // "" for the system's
	Now          func() time.Time
}

// ExportResult describes a finished export.
type ExportResult struct {
	ID      string
	Records uint64
	Digest  integrity.Hash // SHA-256 of the bundle
	Segment uint64         // the closing checkpoint
	Object  objstore.Version
	Created bool // false: the export was already finished
}

type exportJob struct {
	requestedBy string
	filter      []byte
	format      string
	reason      string
	scope       []string
	status      string
}

func (x Exporter) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

func (x Exporter) job(ctx context.Context, id string) (exportJob, error) {
	var j exportJob
	var created time.Time
	err := x.DB.QueryRow(ctx, "SELECT requested_by::text, filter, format, reason, scope_bus::text[], status, created_at FROM audit.export_job($1)", id).
		Scan(&j.requestedBy, &j.filter, &j.format, &j.reason, &j.scope, &j.status, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrExportGone
	}
	return j, err
}

// Run makes export id. An export that is no longer pending is left alone.
func (x Exporter) Run(ctx context.Context, id string) (ExportResult, error) {
	res := ExportResult{ID: id}
	if x.Checkpointer == nil || x.Store == nil || x.Audit == nil {
		return res, errors.New("audit export: no checkpoint key, store or audit emitter")
	}
	j, err := x.job(ctx, id)
	if err != nil {
		return res, err
	}
	if j.status != "pending" {
		return res, nil
	}
	// The export ends at a checkpoint closed for it.
	st, err := x.Checkpointer.Close(ctx)
	if err != nil {
		return res, err
	}
	res.Segment = st.Segment

	f, err := os.CreateTemp(x.TempDir, "fair-export-*.zip")
	if err != nil {
		return res, fmt.Errorf("audit export: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	h := sha256.New()
	created := x.now().UTC().Truncate(time.Second)
	m := evidence.Manifest{Instance: st.Instance, ExportID: id, CreatedAt: created, RequestedBy: j.requestedBy, Reason: j.reason,
		Filter: evidence.Filter{Description: DescribeFilter(j.filter), Data: j.filter}, BUScope: j.scope, RecordFormat: j.format}
	var header []string
	if j.format == "csv" {
		header = ExportCSVHeader
	}
	w, err := evidence.NewExportWriter(io.MultiWriter(f, h), m, x.Checkpointer.Key, x.TempDir, header)
	if err != nil {
		return res, err
	}
	defer w.Close()
	first, err := x.records(ctx, id, st, j.format == "csv", w)
	if err != nil {
		return res, err
	}
	if first == 0 {
		first = st.Segment
	}
	cps, keys, err := x.evidence(ctx, first, st.Segment)
	if err != nil {
		return res, err
	}
	if _, err := w.Finish(cps, keys); err != nil {
		return res, err
	}
	res.Records = w.Records()
	h.Sum(res.Digest[:0])
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return res, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return res, err
	}
	key := ExportKey(st.Instance, id)
	if res.Object, err = x.Store.PutStream(ctx, key, f, size, x.now().Add(ExportRetention)); err != nil {
		return res, fmt.Errorf("audit export: store: %w", err)
	}
	err = pgx.BeginFunc(ctx, x.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT audit.export_complete($1, $2, $3, $4, $5, $6)",
			id, int64(res.Records), res.Digest[:], int64(st.Segment), res.Object.Key, res.Object.VersionID); err != nil { // #nosec G115 -- counts
			return err
		}
		return x.Audit.Emit(events.WithTx(ctx, tx), events.Event{Type: "audit.exported", Severity: events.SeverityHigh, Actor: j.requestedBy,
			Target: "audit:export:" + id, Reason: j.reason, Attributes: map[string]string{
				"export_id": id, "status": "ready", "filter": string(j.filter), "format": j.format,
				"record_count": strconv.FormatUint(res.Records, 10), "digest": res.Digest.String(),
				"checkpoint_segment": strconv.FormatUint(st.Segment, 10), "bu_scope_count": strconv.Itoa(len(j.scope))}})
	})
	if err != nil {
		return res, fmt.Errorf("audit export: complete: %w", err)
	}
	res.Created = true
	return res, nil
}

// records writes the export's records with their proofs and returns the
// first segment they are in (0: none).
func (x Exporter) records(ctx context.Context, id string, st integrity.Statement, withCSV bool, w *evidence.ExportWriter) (uint64, error) {
	var first, curSeg, segFrom uint64
	var tree *integrity.Tree
	after := int64(0)
	for {
		rows, err := x.DB.Query(ctx, `SELECT seq, event_id, segment, body, event_time, received_at, producer, type, category, severity, actor,
			coalesce(target, ''), bu_id::text, coalesce(request_id, ''), coalesce(source_ip, ''), coalesce(approval_id, ''), skew
			FROM audit.export_rows($1, $2, $3, $4)`, id, after, int64(st.SeqTo), exportBatch) // #nosec G115 -- positions
		if err != nil {
			return 0, fmt.Errorf("audit export: read: %w", err)
		}
		type row struct {
			Seq                                                                          int64
			EventID                                                                      string
			Segment                                                                      int64
			Body                                                                         []byte
			Time, Received                                                               time.Time
			Producer, Type, Category, Severity, Actor, Target, BU, Request, IP, Approval string
			Skew                                                                         bool
		}
		batch, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
		if err != nil {
			return 0, fmt.Errorf("audit export: read: %w", err)
		}
		for _, r := range batch {
			seq, seg := uint64(r.Seq), uint64(r.Segment) // #nosec G115 -- positions
			if first == 0 {
				first = seg
			}
			if tree == nil || seg != curSeg {
				var from int64
				var leaves [][]byte
				if err := x.DB.QueryRow(ctx, "SELECT seq_from, leaves FROM audit.segment_leaves($1)", r.Segment).Scan(&from, &leaves); err != nil {
					return 0, fmt.Errorf("audit export: segment %d: %w", seg, err)
				}
				hs := make([]integrity.Hash, len(leaves))
				for i, l := range leaves {
					copy(hs[i][:], l)
				}
				tree, curSeg, segFrom = integrity.NewTree(hs), seg, uint64(from) // #nosec G115
			}
			path, err := tree.Path(seq - segFrom)
			if err != nil {
				return 0, fmt.Errorf("audit export: record %d: %w", seq, err)
			}
			var csvRow []string
			if withCSV {
				var body struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(r.Body, &body) // bodies are JSON (ADR-011); a missing reason is empty
				csvRow = []string{strconv.FormatInt(r.Seq, 10), r.EventID, r.Time.UTC().Format(time.RFC3339Nano), r.Received.UTC().Format(time.RFC3339Nano),
					r.Producer, r.Type, r.Category, r.Severity, r.Actor, r.Target, r.BU, r.Request, r.IP, r.Approval, strconv.FormatBool(r.Skew),
					strconv.FormatInt(r.Segment, 10), csvSafe(body.Reason)}
				for i := range csvRow[:len(csvRow)-1] {
					csvRow[i] = csvSafe(csvRow[i])
				}
			}
			if err := w.AddRecord(r.Body, evidence.Proof{Seq: seq, Segment: seg, Path: path}, csvRow); err != nil {
				return 0, err
			}
		}
		if len(batch) < exportBatch {
			return first, nil
		}
		after = batch[len(batch)-1].Seq
	}
}

// csvSafe keeps a spreadsheet from reading a value as a formula (values
// starting with =, +, - or @ get a leading apostrophe; OWASP CSV injection).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// evidence reads the checkpoints from segment first through last and the
// public keys.
func (x Exporter) evidence(ctx context.Context, first, last uint64) ([]integrity.Checkpoint, evidence.Keys, error) {
	var cps []integrity.Checkpoint
	for next := first; next <= last; {
		rows, err := x.DB.Query(ctx, "SELECT segment, statement, signature FROM audit.verify_checkpoints($1, $2)", int64(next), 10000) // #nosec G115
		if err != nil {
			return nil, nil, fmt.Errorf("audit export: checkpoints: %w", err)
		}
		type cpRow struct {
			Segment   int64
			Statement []byte
			Signature []byte
		}
		batch, err := pgx.CollectRows(rows, pgx.RowToStructByPos[cpRow])
		if err != nil {
			return nil, nil, fmt.Errorf("audit export: checkpoints: %w", err)
		}
		if len(batch) == 0 {
			return nil, nil, fmt.Errorf("audit export: checkpoint %d is missing", next)
		}
		for _, c := range batch {
			if uint64(c.Segment) > last { // #nosec G115
				break
			}
			cps = append(cps, integrity.Checkpoint{Statement: c.Statement, Signature: c.Signature})
		}
		next = uint64(batch[len(batch)-1].Segment) + 1 // #nosec G115
	}
	rows, err := x.DB.Query(ctx, "SELECT key_id, public_pem FROM audit.verify_keys()")
	if err != nil {
		return nil, nil, fmt.Errorf("audit export: keys: %w", err)
	}
	type keyRow struct{ ID, PEM string }
	krs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[keyRow])
	if err != nil {
		return nil, nil, fmt.Errorf("audit export: keys: %w", err)
	}
	keys := evidence.Keys{}
	for _, k := range krs {
		parsed, err := evidence.ParseKeys([]byte(k.PEM))
		if err != nil || parsed[k.ID] == nil {
			return nil, nil, fmt.Errorf("audit export: signing key %s does not match its id", k.ID)
		}
		keys[k.ID] = parsed[k.ID]
	}
	return cps, keys, nil
}

// Fail marks export id failed (after its last attempt) and records
// audit.exported with status failed, in one transaction. It reports
// whether the export was still pending.
func (x Exporter) Fail(ctx context.Context, id string, cause error) (bool, error) {
	j, err := x.job(ctx, id)
	if err != nil {
		return false, err
	}
	why := "the export could not be made"
	if cause != nil {
		why = cause.Error()
	}
	var failed bool
	err = pgx.BeginFunc(ctx, x.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT audit.export_fail($1, $2)", id, why).Scan(&failed); err != nil || !failed {
			return err
		}
		return x.Audit.Emit(events.WithTx(ctx, tx), events.Event{Type: "audit.exported", Severity: events.SeverityHigh, Actor: j.requestedBy,
			Target: "audit:export:" + id, Reason: j.reason, Attributes: map[string]string{
				"export_id": id, "status": "failed", "filter": string(j.filter), "format": j.format, "failure": truncate(why, 500),
				"bu_scope_count": strconv.Itoa(len(j.scope))}})
	})
	return failed, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// filterWords names each filter in words (AC-33), in the search form's order.
var filterWords = []struct{ key, words string }{
	{"from", "recorded at or after"}, {"to", "recorded before"}, {"type", "of type"}, {"category", "in category"},
	{"severity", "of severity"}, {"actor", "by actor"}, {"target", "concerning target"}, {"bu", "filed under BU"},
	{"request_id", "of request"}, {"source_ip", "from source address"}, {"approval_id", "naming approval"},
}

// DescribeFilter states an export's filter in words (the manifest's
// filter.description, AC-33).
func DescribeFilter(filter []byte) string {
	var f map[string]string
	_ = json.Unmarshal(filter, &f)
	var parts []string
	for _, w := range filterWords {
		if v, ok := f[w.key]; ok {
			parts = append(parts, w.words+" "+v)
		}
	}
	scope := "in the BUs where the requester could read audit records and held audit.export when the export was requested (bu_scope)"
	if len(parts) == 0 {
		return "Every audit record " + scope + ", up to the export's closing checkpoint. Archived records are not included."
	}
	return "The audit records " + strings.Join(parts, ", ") + ", " + scope + ", up to the export's closing checkpoint. Archived records are not included."
}

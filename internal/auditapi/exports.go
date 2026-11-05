package auditapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// --- Evidence exports (F-002 T-15; AC-32 to AC-34; design §5, §6.6) ---------

// BundleOpener reads stored export bundles (the audit store).
type BundleOpener interface {
	Open(ctx context.Context, v objstore.Version) (io.ReadCloser, error)
}

// Export is an export as the API shows it.
type Export struct {
	ID                string          `json:"export_id"`
	RequestedBy       string          `json:"requested_by"`
	Filter            json.RawMessage `json:"filter"`
	Format            string          `json:"format"`
	Reason            string          `json:"reason"`
	BUScope           []string        `json:"bu_scope"`
	Status            string          `json:"status"` // pending, ready or failed
	RecordCount       *int64          `json:"record_count"`
	Digest            *string         `json:"digest"` // hex SHA-256 of the bundle
	CheckpointSegment *int64          `json:"checkpoint_segment"`
	Failure           *string         `json:"failure"`
	CreatedAt         time.Time       `json:"created_at"`
	CompletedAt       *time.Time      `json:"completed_at"`

	object objstore.Version
}

// exporter requires audit.view somewhere (else the API does not exist for
// the caller: 404) and audit.export somewhere (else 403).
func (a *API) exporter(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	if !a.viewer(w, r, p) {
		return false
	}
	bus, err := a.Authz.BUsWith(r.Context(), p, "audit.export")
	if err != nil {
		server.WriteAuthzError(w, err)
		return false
	}
	if len(bus) == 0 {
		problem(w, http.StatusForbidden, "forbidden", "audit.export is required")
		return false
	}
	return true
}

// createExport: POST /exports {filter, format, reason}. The export is
// recorded with the caller's scope and its job queued in one transaction;
// 202 with the export.
func (a *API) createExport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.exporter(w, r, p) {
		return
	}
	var body struct {
		Filter map[string]string `json:"filter"`
		Format string            `json:"format"`
		Reason string            `json:"reason"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is {filter, format, reason}")
		return
	}
	if body.Filter == nil {
		body.Filter = map[string]string{}
	}
	if msg := checkFilter(body.Filter); msg != "" {
		problem(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if body.Format != "jsonl" && body.Format != "csv" {
		problem(w, http.StatusBadRequest, "invalid_request", "format is jsonl or csv")
		return
	}
	if a.Enqueue == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "exports are not configured")
		return
	}
	fj, _ := json.Marshal(body.Filter)
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), "SELECT audit.export_request($1, $2, $3)::text", fj, body.Format, body.Reason).Scan(&id); err != nil {
			return err
		}
		return a.Enqueue(r.Context(), tx, id)
	})
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe) && pe.Code == "PF008":
		problem(w, http.StatusForbidden, "forbidden", "audit.export is required")
		return
	case err != nil:
		fail(w, err)
		return
	}
	e, err := a.loadExport(r.Context(), p, id, "")
	if err != nil || e == nil {
		fail(w, err)
		return
	}
	w.Header().Set("Location", Prefix+"/exports/"+id)
	writeJSON(w, http.StatusAccepted, e)
}

// checkFilter refuses what search refuses before the database sees it.
func checkFilter(f map[string]string) string {
	for k, v := range f {
		known := k == "approval_id"
		for _, fk := range filterKeys {
			known = known || k == fk
		}
		if !known {
			return "unknown filter " + k
		}
		if v == "" {
			return "filter " + k + " is a non-empty string"
		}
	}
	for _, k := range []string{"from", "to"} {
		if v, ok := f[k]; ok {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return k + " is an RFC 3339 time"
			}
		}
	}
	if v, ok := f["source_ip"]; ok {
		if _, err := netip.ParsePrefix(v); err != nil {
			if _, err := netip.ParseAddr(v); err != nil {
				return "source_ip is an address or a CIDR range"
			}
		}
	}
	return ""
}

// loadExport reads one export visible to the caller (its requester, or a
// holder of audit.export at the root) and, when view is set, records the
// read as audit.searched in the same transaction. nil: not visible.
func (a *API) loadExport(ctx context.Context, p authz.Principal, id, view string) (*Export, error) {
	if !isUUID(id) {
		return nil, nil
	}
	var e *Export
	load := func(tx pgx.Tx) (int, error) {
		var x Export
		var digest []byte
		var key, version *string
		err := tx.QueryRow(ctx, `SELECT id::text, requested_by::text, filter, format, reason, scope_bus::text[], status, record_count, digest,
			checkpoint_segment, object_key, object_version, failure, created_at, completed_at FROM audit.export_view($1)`, id).
			Scan(&x.ID, &x.RequestedBy, &x.Filter, &x.Format, &x.Reason, &x.BUScope, &x.Status, &x.RecordCount, &digest,
				&x.CheckpointSegment, &key, &version, &x.Failure, &x.CreatedAt, &x.CompletedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		if digest != nil {
			d := hex.EncodeToString(digest)
			x.Digest = &d
		}
		if key != nil && version != nil {
			x.object = objstore.Version{Key: *key, VersionID: *version}
		}
		e = &x
		return 1, nil
	}
	if view == "" {
		err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error { _, err := load(tx); return err })
		return e, err
	}
	fj, _ := json.Marshal(map[string]string{"export": id})
	err := a.read(ctx, p, audit.Event{Type: "audit.searched", Target: "audit:export:" + id,
		Attributes: map[string]string{"view": view, "filter": string(fj)}}, load)
	return e, err
}

// getExport: GET /exports/{id}.
func (a *API) getExport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.exporter(w, r, p) {
		return
	}
	e, err := a.loadExport(r.Context(), p, r.PathValue("id"), "export")
	if err != nil {
		fail(w, err)
		return
	}
	if e == nil {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// exportBundle: GET /exports/{id}/bundle. The download is recorded
// (audit.export_fetched) before a byte is sent.
func (a *API) exportBundle(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.exporter(w, r, p) {
		return
	}
	id := r.PathValue("id")
	e, err := a.loadExport(r.Context(), p, id, "")
	if err != nil {
		fail(w, err)
		return
	}
	if e == nil {
		notFound(w)
		return
	}
	if e.Status != "ready" {
		problem(w, http.StatusConflict, "not_ready", "the export is "+e.Status)
		return
	}
	if a.Bundles == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "exports are not configured")
		return
	}
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return a.Audit.Emit(audit.WithTx(r.Context(), tx), audit.Event{Type: "audit.export_fetched", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "audit:export:" + e.ID, Attributes: map[string]string{"export_id": e.ID, "digest": *e.Digest}})
	})
	if err != nil {
		fail(w, err)
		return
	}
	rc, err := a.Bundles.Open(r.Context(), e.object)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	defer func() { _ = rc.Close() }()
	d, _ := hex.DecodeString(*e.Digest)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="fair-audit-export-`+e.ID+`.zip"`)
	w.Header().Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(d)+":")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// IdempotencyStore keeps the Audit API's mutation outcomes per user and
// Idempotency-Key (migration 0078) for server.Idempotent.
type IdempotencyStore struct {
	DB *pgxpool.Pool // app_audit
}

var _ server.IdempotencyStore = IdempotencyStore{}

// Begin implements server.IdempotencyStore.
func (s IdempotencyStore) Begin(ctx context.Context, user, key, hash string) (*server.StoredResponse, error) {
	var outcome string
	var status *int
	var ct *string
	var body []byte
	if err := s.DB.QueryRow(ctx, "SELECT outcome, status, content_type, body FROM audit.idempotency_begin($1, $2, $3)",
		user, key, hash).Scan(&outcome, &status, &ct, &body); err != nil {
		return nil, err
	}
	switch outcome {
	case "mismatch":
		return nil, server.ErrIdempotencyMismatch
	case "in_progress":
		return nil, server.ErrIdempotencyInProgress
	case "replay":
		r := &server.StoredResponse{Status: *status, Body: bytes.Clone(body)}
		if ct != nil {
			r.ContentType = *ct
		}
		return r, nil
	}
	return nil, nil
}

// Complete implements server.IdempotencyStore.
func (s IdempotencyStore) Complete(ctx context.Context, user, key string, r server.StoredResponse) error {
	_, err := s.DB.Exec(ctx, "SELECT audit.idempotency_complete($1, $2, $3, $4, $5)", user, key, r.Status, r.ContentType, r.Body)
	return err
}

// Abandon implements server.IdempotencyStore.
func (s IdempotencyStore) Abandon(ctx context.Context, user, key string) error {
	_, err := s.DB.Exec(ctx, "SELECT audit.idempotency_abandon($1, $2)", user, key)
	return err
}

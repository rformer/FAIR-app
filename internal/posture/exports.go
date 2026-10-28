package posture

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Signed, recorded and reproducible exports (F-015 T-35; AC-47; design
// §6.9 integrity; migration 0034). An export is built from a snapshot
// (T-33/T-34), validated against the pinned OSCAL schema, and recorded with
// that snapshot, the SHA-256 of the document and of the snapshot, and a
// detached ECDSA P-256 signature over a statement naming the export, its
// as_of, its creation time and both digests (the signed timestamp). The
// record and its audit event are written in one transaction, so an audit
// failure records nothing. A recorded export is never stored as a document:
// fetching or reproducing it rebuilds the document from the snapshot and
// refuses it unless the digest and the signature still match.

// Export kinds.
const (
	KindAssessmentResults = "assessment_results"
	KindPOAM              = "poam"
)

// Export audit events.
const (
	EventExported         = "posture.exported"
	EventExportFetched    = "posture.export_fetched"
	EventExportMismatched = "posture.export_mismatch"
)

// StatementType identifies an export statement.
const StatementType = "fair-posture-export"

var (
	// ErrExportNotFound means no export has that id, or none of that kind
	// was made at that as_of.
	ErrExportNotFound = errors.New("posture: no such export")
	// ErrNotReproducible means a recorded export no longer rebuilds to the
	// document it recorded, or its signature does not verify (tampering or
	// a generator change); it is never served.
	ErrNotReproducible = errors.New("posture: the export cannot be reproduced from its record")
	// ErrExportSignature is VerifyExport refusing the document.
	ErrExportSignature = errors.New("posture: export signature or digest does not verify")
)

var uuidText = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Statement is what an export's signature covers.
type Statement struct {
	Type           string    `json:"type"`
	ExportID       string    `json:"export_id"`
	Kind           string    `json:"kind"`
	AsOf           time.Time `json:"as_of"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
	OSCALVersion   string    `json:"oscal_version"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	DocumentSHA256 string    `json:"document_sha256"`
	KeyID          string    `json:"key_id"`
}

// Export is a recorded export with its document.
type Export struct {
	ID, Kind       string
	AsOf           time.Time
	CreatedAt      time.Time
	CreatedBy      string
	Document       []byte // the OSCAL JSON
	Statement      []byte // the exact bytes signed
	Signature      string // base64 ASN.1 DER ECDSA over SHA-256 of Statement
	DocumentDigest string
	SnapshotDigest string
	KeyID          string
}

// ExportSummary is a record without its document (the export history).
type ExportSummary struct {
	ID, Kind       string
	AsOf           time.Time
	CreatedAt      time.Time
	CreatedBy      string
	DocumentDigest string
	SnapshotDigest string
	KeyID          string
}

// Exports creates and serves exports. Connect as app_posture.
type Exports struct {
	DB    *pgxpool.Pool
	Audit audit.Emitter
	Key   *ecdsa.PrivateKey // the installation's export signing key (P-256)
	Now   func() time.Time  // default time.Now
}

// KeyID is the hex SHA-256 of the PKIX encoding of a public key.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(der)
	return hex.EncodeToString(d[:]), nil
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// buildDocument is the OSCAL document of kind for s.
func buildDocument(kind string, s ExportSnapshot) ([]byte, error) {
	switch kind {
	case KindAssessmentResults:
		return ExportAssessmentResults(s)
	case KindPOAM:
		return ExportPOAM(s)
	}
	return nil, fmt.Errorf("%w: export kind %q", ErrInvalidValue, kind)
}

func (x Exports) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

func (x Exports) keyID() (string, error) {
	if x.Key == nil || x.Key.Curve.Params().Name != "P-256" {
		return "", fmt.Errorf("%w: no ECDSA P-256 export signing key", ErrConfiguration)
	}
	return KeyID(&x.Key.PublicKey)
}

// Create exports the current posture as p (who needs posture.export): it
// reads a consistent snapshot, builds and validates the document, signs the
// statement, and records it with its audit event. ErrNoPOAMItems when a
// POA&M has nothing to list.
func (x Exports) Create(ctx context.Context, p authz.Principal, kind string) (Export, error) {
	kid, err := x.keyID()
	if err != nil {
		return Export{}, err
	}
	snap, err := LoadExportSnapshot(ctx, x.DB)
	if err != nil {
		return Export{}, err
	}
	doc, err := buildDocument(kind, snap)
	if err != nil {
		return Export{}, err
	}
	snapBytes, err := json.Marshal(snap)
	if err != nil {
		return Export{}, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Export{}, err
	}
	id[6], id[8] = (id[6]&0x0f)|0x40, (id[8]&0x3f)|0x80
	created := x.now().UTC().Truncate(time.Microsecond)
	if created.Before(snap.AsOf) { // the database's clock ran a little ahead
		created = snap.AsOf
	}
	e := Export{
		ID:   fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]),
		Kind: kind, AsOf: snap.AsOf, CreatedAt: created, CreatedBy: p.UserID, Document: doc,
		DocumentDigest: sha256Hex(doc), SnapshotDigest: sha256Hex(snapBytes), KeyID: kid,
	}
	e.Statement, err = json.Marshal(Statement{Type: StatementType, ExportID: e.ID, Kind: kind, AsOf: e.AsOf, CreatedAt: e.CreatedAt,
		CreatedBy: p.UserID, OSCALVersion: oscal.Version, SnapshotSHA256: e.SnapshotDigest, DocumentSHA256: e.DocumentDigest, KeyID: kid})
	if err != nil {
		return Export{}, err
	}
	d := sha256.Sum256(e.Statement)
	sig, err := ecdsa.SignASN1(rand.Reader, x.Key, d[:])
	if err != nil {
		return Export{}, err
	}
	e.Signature = base64.StdEncoding.EncodeToString(sig)

	err = authz.WithDBContext(ctx, x.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT posture.record_export($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
			e.ID, kind, e.AsOf, e.CreatedAt, snapBytes, e.SnapshotDigest, e.DocumentDigest, e.Statement, e.Signature, kid); err != nil {
			return err
		}
		return x.Audit.Emit(ctx, audit.Event{Type: EventExported, Severity: audit.SeverityHigh, Actor: p.UserID,
			Target: "export:" + e.ID, Attributes: e.attrs()})
	})
	if err != nil {
		return Export{}, mapErr(err)
	}
	return e, nil
}

func (e Export) attrs() map[string]string {
	return map[string]string{"export_id": e.ID, "kind": e.Kind, "as_of": e.AsOf.UTC().Format(time.RFC3339Nano),
		"created_at": e.CreatedAt.UTC().Format(time.RFC3339Nano), "document_sha256": e.DocumentDigest,
		"snapshot_sha256": e.SnapshotDigest, "key_id": e.KeyID}
}

// Get serves a recorded export as p (posture.export), rebuilt from its
// snapshot; ErrNotReproducible (audited, critical) if the rebuilt document
// or the signature does not match the record.
func (x Exports) Get(ctx context.Context, p authz.Principal, id string) (Export, error) {
	if !uuidText.MatchString(id) {
		return Export{}, ErrExportNotFound
	}
	var e Export
	err := authz.WithDBContext(ctx, x.DB, p.DBToken, func(tx pgx.Tx) error {
		var snap []byte
		err := tx.QueryRow(ctx, `SELECT id::text, kind, as_of, created_at, created_by::text, snapshot, snapshot_digest, document_digest,
			statement, signature, key_id FROM posture.export_get($1)`, id).
			Scan(&e.ID, &e.Kind, &e.AsOf, &e.CreatedAt, &e.CreatedBy, &snap, &e.SnapshotDigest, &e.DocumentDigest, &e.Statement, &e.Signature, &e.KeyID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExportNotFound
		}
		if err != nil {
			return err
		}
		e.AsOf, e.CreatedAt = e.AsOf.UTC(), e.CreatedAt.UTC()
		if why := x.reproduce(&e, snap); why != "" {
			attrs := e.attrs()
			attrs["reason"] = why
			if err := x.Audit.Emit(ctx, audit.Event{Type: EventExportMismatched, Severity: audit.SeverityCritical, Actor: p.UserID,
				Target: "export:" + e.ID, Reason: why, Attributes: attrs}); err != nil {
				return err
			}
			return fmt.Errorf("%w: %s", ErrNotReproducible, why)
		}
		return x.Audit.Emit(ctx, audit.Event{Type: EventExportFetched, Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "export:" + e.ID, Attributes: e.attrs()})
	})
	if err != nil {
		if errors.Is(err, ErrNotReproducible) || errors.Is(err, ErrExportNotFound) {
			return Export{}, err
		}
		return Export{}, mapErr(err)
	}
	return e, nil
}

// reproduce rebuilds e.Document from the snapshot and checks it against the
// record; it returns why it does not match ("" when it does).
func (x Exports) reproduce(e *Export, snap []byte) string {
	if sha256Hex(snap) != e.SnapshotDigest {
		return "the stored snapshot does not match its digest"
	}
	var s ExportSnapshot
	if err := json.Unmarshal(snap, &s); err != nil {
		return "the stored snapshot does not decode: " + err.Error()
	}
	doc, err := buildDocument(e.Kind, s)
	if err != nil {
		return "the document cannot be rebuilt: " + err.Error()
	}
	if sha256Hex(doc) != e.DocumentDigest {
		return "the rebuilt document differs from the recorded digest"
	}
	if x.Key != nil {
		if kid, _ := x.keyID(); kid == e.KeyID {
			if err := VerifyExport(&x.Key.PublicKey, doc, e.Statement, e.Signature); err != nil {
				return "the signature does not verify"
			}
		}
	}
	e.Document = doc
	return ""
}

// Reproduce rebuilds the export of kind recorded at asOf (POST /exports
// with as_of): the same document, digest and signature as when it was made.
func (x Exports) Reproduce(ctx context.Context, p authz.Principal, kind string, asOf time.Time) (Export, error) {
	var id *string
	err := authz.WithDBContext(ctx, x.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT posture.export_at($1, $2)::text", kind, asOf).Scan(&id)
	})
	if err != nil {
		return Export{}, mapErr(err)
	}
	if id == nil {
		return Export{}, ErrExportNotFound
	}
	return x.Get(ctx, p, *id)
}

// List is the export history, newest first.
func (x Exports) List(ctx context.Context, limit int) ([]ExportSummary, error) {
	rows, err := x.DB.Query(ctx, `SELECT id::text, kind, as_of, created_at, created_by::text, document_digest, snapshot_digest, key_id
		FROM posture.export_records($1)`, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ExportSummary, error) {
		var s ExportSummary
		err := r.Scan(&s.ID, &s.Kind, &s.AsOf, &s.CreatedAt, &s.CreatedBy, &s.DocumentDigest, &s.SnapshotDigest, &s.KeyID)
		s.AsOf, s.CreatedAt = s.AsOf.UTC(), s.CreatedAt.UTC()
		return s, err
	})
}

// VerifyExport checks an export as a recipient would: the signature over
// the statement with the installation's public key, the statement's key id,
// and that the document is the one the statement names.
func VerifyExport(pub *ecdsa.PublicKey, document, statement []byte, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrExportSignature, err)
	}
	d := sha256.Sum256(statement)
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		return fmt.Errorf("%w: bad signature", ErrExportSignature)
	}
	var st Statement
	if err := json.Unmarshal(statement, &st); err != nil || st.Type != StatementType {
		return fmt.Errorf("%w: not an export statement", ErrExportSignature)
	}
	if kid, err := KeyID(pub); err != nil || kid != st.KeyID {
		return fmt.Errorf("%w: signed by another key", ErrExportSignature)
	}
	if sha256Hex(document) != st.DocumentSHA256 {
		return fmt.Errorf("%w: the document is not the one signed", ErrExportSignature)
	}
	return nil
}

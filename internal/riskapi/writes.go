package riskapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-10: library entries' and controls' writes inside a caller's
// transaction, so that accepting an integration's proposal (the imports
// API) goes through the same checks, triggers and events as POST and PUT
// /library and /controls. The handlers use the same transaction bodies.

// Sections name the resources the imports API writes.
const (
	SectionLibrary  = "library"
	SectionControls = "controls"
)

func section(name string) (resource, error) {
	switch name {
	case SectionLibrary:
		return library, nil
	case SectionControls:
		return controls, nil
	}
	return resource{}, fmt.Errorf("riskapi: no section %q", name)
}

// Write errors the imports API answers.
var (
	ErrNotFound  = errNotFound
	ErrForbidden = errors.New("riskapi: the edit permission at the BU is needed")
	ErrArchived  = errors.New("riskapi: archived; restore it before changing it")
	ErrStale     = errors.New("riskapi: the record changed since the version given")
	ErrCurrency  = errNoCurrency
)

// Head is a library entry's or control's head, as the caller reads it.
type Head struct {
	ID, BU, Kind   string
	CurrentVersion int
	Archived       bool
	Inherited      bool
	Document       json.RawMessage // the current version's
}

// ReadHead reads id's head and current document in tx, as the caller
// (RLS); ErrNotFound when they do not see it.
func ReadHead(ctx context.Context, tx pgx.Tx, sectionName, id string) (Head, error) {
	res, err := section(sectionName)
	if err != nil {
		return Head{}, err
	}
	var h Head
	err = tx.QueryRow(ctx, `SELECT h.id::text, h.bu_id::text, `+kindColumn(res)+`, h.current_version, h.archived_at IS NOT NULL,
		NOT (h.bu_id = ANY ((SELECT authz.visible_bus('`+res.resourceType+`', 'read'))::uuid[])), v.document
		FROM risk.`+res.head+` h JOIN risk.`+res.versions+` v ON v.`+res.headColumn+` = h.id AND v.version = h.current_version
		WHERE h.id = $1`, id).Scan(&h.ID, &h.BU, &h.Kind, &h.CurrentVersion, &h.Archived, &h.Inherited, &h.Document)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, ErrNotFound
	}
	return h, err
}

func kindColumn(res resource) string {
	if len(res.kinds) > 1 {
		return "h.kind"
	}
	return "'" + res.kinds[0] + "'::text"
}

// mayEdit is the edit permission at bu, as the handlers check it.
func (a *API) mayEdit(ctx context.Context, p authz.Principal, res resource, bu string) error {
	if err := a.Authz.Check(ctx, p, res.edit, bu); err != nil {
		var su *authz.StepUpError
		if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
			return err
		}
		return ErrForbidden
	}
	return nil
}

// createTx creates a head and its version 1 in tx, with the created event.
func (a *API) createTx(ctx context.Context, tx pgx.Tx, res resource, p authz.Principal, bu, kind string, doc *model.Document, note string, extra map[string]string) (string, error) {
	if err := needsCurrency(ctx, tx, doc); err != nil {
		return "", err
	}
	q, args := "INSERT INTO risk."+res.head+" (bu_id) VALUES ($1) RETURNING id::text", []any{bu}
	if len(res.kinds) > 1 {
		q, args = "INSERT INTO risk."+res.head+" (bu_id, kind) VALUES ($1, $2) RETURNING id::text", []any{bu, kind}
	}
	var id string
	if err := tx.QueryRow(ctx, q, args...).Scan(&id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO risk."+res.versions+" ("+res.headColumn+", version, document, digest, change_note) VALUES ($1, 1, $2, $3, $4)",
		id, doc.Canonical, doc.Digest, note); err != nil {
		return "", err
	}
	return id, a.event(ctx, tx, res, p, res.createdType, id, bu, kind, 1, doc, note, extra)
}

// saveTx writes version (the one after the version the change was made
// from) in tx, with the saved event.
func (a *API) saveTx(ctx context.Context, tx pgx.Tx, res resource, p authz.Principal, id, bu, kind string, version int, doc *model.Document, note string, extra map[string]string) error {
	if err := needsCurrency(ctx, tx, doc); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO risk."+res.versions+" ("+res.headColumn+", version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
		id, version, doc.Canonical, doc.Digest, note); err != nil {
		return err
	}
	return a.event(ctx, tx, res, p, res.savedType, id, bu, kind, version, doc, note, extra)
}

// archiveTx archives or restores a head in tx, with its event.
func (a *API) archiveTx(ctx context.Context, tx pgx.Tx, res resource, p authz.Principal, id, bu string, archive bool, reason string) error {
	typ := res.restoredType
	if archive {
		typ = res.archivedType
	}
	if _, err := tx.Exec(ctx, "SELECT risk.set_archived($1, $2, $3)", res.event, id, archive); err != nil {
		return err
	}
	return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: typ, Severity: audit.SeverityLow, Actor: p.UserID,
		Target: res.event + ":" + id, BUID: bu, Attributes: map[string]string{"reason": strings.TrimSpace(reason)}})
}

// Create creates a library entry (of kind) or a control at bu in tx as p:
// the edit permission at bu, the document valid (model.Problems otherwise),
// the currency set for amounts. It answers the new id and the document.
func (a *API) Create(ctx context.Context, tx pgx.Tx, p authz.Principal, sectionName, bu, kind string, raw json.RawMessage, note string, extra map[string]string) (string, *model.Document, error) {
	res, err := section(sectionName)
	if err != nil {
		return "", nil, err
	}
	if err := a.mayEdit(ctx, p, res, bu); err != nil {
		return "", nil, err
	}
	doc, problems := model.Validate(kind, raw)
	if problems != nil {
		return "", nil, problems
	}
	id, err := a.createTx(ctx, tx, res, p, bu, kind, doc, note, extra)
	return id, doc, err
}

// Save writes the version after expected of id in tx as p: the head read
// as p (ErrNotFound), the edit permission at its BU and not inherited
// (ErrForbidden), not archived (ErrArchived), still at expected (ErrStale).
func (a *API) Save(ctx context.Context, tx pgx.Tx, p authz.Principal, sectionName, id string, expected int, raw json.RawMessage, note string, extra map[string]string) (int, *model.Document, error) {
	res, err := section(sectionName)
	if err != nil {
		return 0, nil, err
	}
	h, err := ReadHead(ctx, tx, sectionName, id)
	if err != nil {
		return 0, nil, err
	}
	if h.Inherited {
		return 0, nil, ErrForbidden
	}
	if err := a.mayEdit(ctx, p, res, h.BU); err != nil {
		return 0, nil, err
	}
	if h.Archived {
		return 0, nil, ErrArchived
	}
	if h.CurrentVersion != expected {
		return 0, nil, ErrStale
	}
	doc, problems := model.Validate(h.Kind, raw)
	if problems != nil {
		return 0, nil, problems
	}
	return expected + 1, doc, a.saveTx(ctx, tx, res, p, id, h.BU, h.Kind, expected+1, doc, note, extra)
}

// Archive archives id in tx as p, with the reason (the edit permission at
// its BU; ErrArchived if it is archived already).
func (a *API) Archive(ctx context.Context, tx pgx.Tx, p authz.Principal, sectionName, id, reason string) error {
	res, err := section(sectionName)
	if err != nil {
		return err
	}
	h, err := ReadHead(ctx, tx, sectionName, id)
	if err != nil {
		return err
	}
	if h.Inherited {
		return ErrForbidden
	}
	if err := a.mayEdit(ctx, p, res, h.BU); err != nil {
		return err
	}
	if h.Archived {
		return ErrArchived
	}
	return a.archiveTx(ctx, tx, res, p, h.ID, h.BU, true, reason)
}

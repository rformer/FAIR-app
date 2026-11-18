package registerapi

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-10b: risks' writes inside a caller's transaction, so that
// accepting an integration's proposal (the imports API) goes through the
// same checks, triggers and events as POST and PUT /register/risks. The
// handlers use the same transaction bodies.

// Write errors the imports API answers.
var (
	ErrNotFound  = errNotFound
	ErrForbidden = errors.New("registerapi: register.edit at the BU is needed")
	ErrClosed    = errors.New("registerapi: the risk is closed")
	ErrStale     = errors.New("registerapi: the risk changed since the version given")
)

// Risk is a risk's head and current document as the caller reads it.
type Risk struct {
	ID, BU, State string
	Version       int
	Document      json.RawMessage
}

// ReadRisk reads a risk in tx as the caller (RLS); ErrNotFound otherwise.
func ReadRisk(ctx context.Context, tx pgx.Tx, id string) (Risk, error) {
	h, err := readHead(ctx, tx, id)
	if err != nil {
		return Risk{}, err
	}
	doc, err := currentDoc(ctx, tx, h)
	return Risk{ID: h.ID, BU: h.BU, State: h.State, Version: h.Version, Document: doc}, err
}

func (a *API) editAt(ctx context.Context, p authz.Principal, bu string) error {
	if err := a.Authz.Check(ctx, p, permEdit, bu); err != nil {
		var su *authz.StepUpError
		if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
			return err
		}
		return ErrForbidden
	}
	return nil
}

// createTx creates a risk and its version 1 in tx, with its events.
func (a *API) createTx(ctx context.Context, tx pgx.Tx, p authz.Principal, bu string, doc []byte, digest, note string) (string, error) {
	ctx = audit.WithTx(ctx, tx)
	var id string
	if err := tx.QueryRow(ctx, "INSERT INTO register.risk (bu_id) VALUES ($1) RETURNING id::text", bu).Scan(&id); err != nil {
		return "", err
	}
	if err := insertVersion(ctx, tx, id, 1, doc, digest, note); err != nil {
		return "", err
	}
	if err := a.emit(ctx, audit.Event{Type: "register.risk_created", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + id, BUID: bu,
		Attributes: map[string]string{"version": "1", "digest": digest}}); err != nil {
		return "", err
	}
	if err := a.linkEvents(ctx, p, id, bu, 1, nil, doc); err != nil {
		return "", err
	}
	return id, a.afterVersion(ctx, tx, p, id, bu, 1, nil, doc, false)
}

// saveTx writes version (after h's) in tx, with its events.
func (a *API) saveTx(ctx context.Context, tx pgx.Tx, p authz.Principal, h head, version int, doc []byte, digest, note string) error {
	ctx = audit.WithTx(ctx, tx)
	prev, err := currentDoc(ctx, tx, h)
	if err != nil {
		return err
	}
	if err := insertVersion(ctx, tx, h.ID, version, doc, digest, note); err != nil {
		return err
	}
	if err := a.emit(ctx, audit.Event{Type: "register.risk_changed", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + h.ID, BUID: h.BU,
		Attributes: map[string]string{"version": strconv.Itoa(version), "digest": digest, "change_note": note}}); err != nil {
		return err
	}
	if err := a.linkEvents(ctx, p, h.ID, h.BU, version, prev, doc); err != nil {
		return err
	}
	return a.afterVersion(ctx, tx, p, h.ID, h.BU, version, prev, doc, false)
}

// openDoc validates raw as an open risk's document.
func openDoc(raw json.RawMessage) ([]byte, string, error) {
	doc, digest, problems := register.Validate(raw)
	if problems != nil {
		return nil, "", problems
	}
	if d, _ := register.Decode(doc); d.State != "open" {
		return nil, "", model.Problems{{Pointer: "/state", Message: "is open"}}
	}
	return doc, digest, nil
}

// CreateRisk creates an open risk at bu in tx as p (register.edit at bu;
// the document valid: model.Problems otherwise).
func (a *API) CreateRisk(ctx context.Context, tx pgx.Tx, p authz.Principal, bu string, raw json.RawMessage, note string) (string, error) {
	if err := a.editAt(ctx, p, bu); err != nil {
		return "", err
	}
	doc, digest, err := openDoc(raw)
	if err != nil {
		return "", err
	}
	return a.createTx(ctx, tx, p, bu, doc, digest, note)
}

// SaveRisk writes the version after expected of risk id in tx as p: read
// as p (ErrNotFound), register.edit at its BU (ErrForbidden), open
// (ErrClosed), still at expected (ErrStale).
func (a *API) SaveRisk(ctx context.Context, tx pgx.Tx, p authz.Principal, id string, expected int, raw json.RawMessage, note string) (int, error) {
	h, err := readHead(ctx, tx, id)
	if err != nil {
		return 0, err
	}
	if err := a.editAt(ctx, p, h.BU); err != nil {
		return 0, err
	}
	if h.State == "closed" {
		return 0, ErrClosed
	}
	if h.Version != expected {
		return 0, ErrStale
	}
	doc, digest, err := openDoc(raw)
	if err != nil {
		return 0, err
	}
	return expected + 1, a.saveTx(ctx, tx, p, h, expected+1, doc, digest, note)
}

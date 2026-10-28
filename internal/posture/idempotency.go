package posture

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/server"
)

// IdempotencyStore keeps the Posture API's mutation outcomes per user and
// Idempotency-Key (F-015 T-31, migration 0033) for server.Idempotent.
type IdempotencyStore struct {
	DB *pgxpool.Pool // app_posture
}

var _ server.IdempotencyStore = IdempotencyStore{}

// Begin implements server.IdempotencyStore.
func (s IdempotencyStore) Begin(ctx context.Context, user, key, hash string) (*server.StoredResponse, error) {
	var outcome string
	var status *int
	var ct *string
	var body []byte
	if err := s.DB.QueryRow(ctx, "SELECT outcome, status, content_type, body FROM posture.idempotency_begin($1, $2, $3)",
		user, key, hash).Scan(&outcome, &status, &ct, &body); err != nil {
		return nil, err
	}
	switch outcome {
	case "mismatch":
		return nil, server.ErrIdempotencyMismatch
	case "in_progress":
		return nil, server.ErrIdempotencyInProgress
	case "replay":
		return &server.StoredResponse{Status: *status, ContentType: deref(ct), Body: body}, nil
	}
	return nil, nil
}

// Complete implements server.IdempotencyStore.
func (s IdempotencyStore) Complete(ctx context.Context, user, key string, r server.StoredResponse) error {
	_, err := s.DB.Exec(ctx, "SELECT posture.idempotency_complete($1, $2, $3, $4, $5)", user, key, r.Status, r.ContentType, r.Body)
	return err
}

// Abandon implements server.IdempotencyStore.
func (s IdempotencyStore) Abandon(ctx context.Context, user, key string) error {
	_, err := s.DB.Exec(ctx, "SELECT posture.idempotency_abandon($1, $2)", user, key)
	return err
}

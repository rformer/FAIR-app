package iamapi

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/server"
)

// IdempotencyStore keeps iam API mutation outcomes per user and
// Idempotency-Key (migration 0040) for server.Idempotent.
type IdempotencyStore struct {
	DB *pgxpool.Pool // app_rw
}

var _ server.IdempotencyStore = IdempotencyStore{}

// Begin implements server.IdempotencyStore.
func (s IdempotencyStore) Begin(ctx context.Context, user, key, hash string) (*server.StoredResponse, error) {
	var outcome string
	var status *int
	var ct *string
	var body []byte
	if err := s.DB.QueryRow(ctx, "SELECT outcome, status, content_type, body FROM iam.idempotency_begin($1, $2, $3)",
		user, key, hash).Scan(&outcome, &status, &ct, &body); err != nil {
		return nil, err
	}
	switch outcome {
	case "mismatch":
		return nil, server.ErrIdempotencyMismatch
	case "in_progress":
		return nil, server.ErrIdempotencyInProgress
	case "replay":
		resp := server.StoredResponse{Status: *status, Body: body}
		if ct != nil {
			resp.ContentType = *ct
		}
		return &resp, nil
	}
	return nil, nil
}

// Complete implements server.IdempotencyStore.
func (s IdempotencyStore) Complete(ctx context.Context, user, key string, r server.StoredResponse) error {
	_, err := s.DB.Exec(ctx, "SELECT iam.idempotency_complete($1, $2, $3, $4, $5)", user, key, r.Status, r.ContentType, r.Body)
	return err
}

// Abandon implements server.IdempotencyStore.
func (s IdempotencyStore) Abandon(ctx context.Context, user, key string) error {
	_, err := s.DB.Exec(ctx, "SELECT iam.idempotency_abandon($1, $2)", user, key)
	return err
}

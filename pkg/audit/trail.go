package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// F-002 T-06 (F-002-AC-01, AC-02; design §6.1): the audit trail sink.

// Execer runs a statement: a pgx.Tx, *pgx.Conn or *pgxpool.Pool.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Beginner starts transactions: a *pgx.Conn or *pgxpool.Pool.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

type txKey struct{}

// WithTx makes events emitted with ctx part of tx: they are recorded if and
// only if tx commits (F-002-AC-02). Use it for every event that reports a
// change made in tx.
func WithTx(ctx context.Context, tx Execer) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// Trail records events in the audit trail through audit.submit (design
// §6.1). With a transaction in the context (WithTx) it records the event in
// it; otherwise in a short transaction of its own, before Emit returns. Any
// failure is returned: callers fail closed.
type Trail struct {
	DB Beginner
	// Role, when set, is taken with SET LOCAL ROLE before submitting: the
	// installer's commands connect as app_migrator and record as fair_owner.
	Role string
}

// Emit implements Emitter. Validate first (Validating): audit.submit
// refuses what the database's copy of the catalog does not describe too.
func (t Trail) Emit(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	const submit = "SELECT audit.submit($1::jsonb)"
	if tx, ok := ctx.Value(txKey{}).(Execer); ok && tx != nil {
		if _, err := tx.Exec(ctx, submit, string(body)); err != nil {
			return fmt.Errorf("audit trail: %w", err)
		}
		return nil
	}
	if t.DB == nil {
		return errors.New("audit trail: no database")
	}
	err = pgx.BeginFunc(ctx, t.DB, func(tx pgx.Tx) error {
		if t.Role != "" {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{t.Role}.Sanitize()); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, submit, string(body))
		return err
	})
	if err != nil {
		return fmt.Errorf("audit trail: %w", err)
	}
	return nil
}

// WithTrail adds the trail to a service's emitter (FromEnv): an event is
// recorded in the trail first and written to the other sinks only once the
// trail has it; an event the trail refuses fails the operation and is
// written nowhere else.
func WithTrail(e Emitter, t Trail) Emitter {
	if v, ok := e.(Validating); ok {
		v.Next = trailFirst{trail: t, rest: v.Next}
		return v
	}
	return trailFirst{trail: t, rest: e}
}

type trailFirst struct {
	trail Emitter
	rest  Emitter
}

func (f trailFirst) Emit(ctx context.Context, e Event) error {
	e, err := Normalize(e, time.Now())
	if err != nil {
		return err
	}
	if err := f.trail.Emit(ctx, e); err != nil {
		return err
	}
	return f.rest.Emit(ctx, e)
}

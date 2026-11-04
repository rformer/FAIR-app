package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// Sequencer moves accepted events from audit.intake into the trail (F-002
// T-07, design §6.2): each batch, in one transaction, gets its records'
// positions, bodies (ADR-011) and leaf and chain hashes, which
// audit.sequence_append checks before appending. Run it on the leader only;
// the chain head's row lock keeps a second sequencer out regardless.
type Sequencer struct {
	DB    *pgxpool.Pool // connected as app_audit
	Batch int           // events per transaction; default 500
	// MaxSkew is audit.max_clock_skew in force (AC-05): records whose event
	// time and receipt differ by more are flagged. Nil: 5 minutes.
	MaxSkew func() time.Duration
}

// DefaultBatch is the default number of events per transaction.
const DefaultBatch = 500

type pending struct {
	id       int64
	eventID  string
	producer string
	body     []byte
	accepted time.Time
}

// Step sequences one batch and returns how many events it recorded.
func (s Sequencer) Step(ctx context.Context) (int, error) {
	batch := s.Batch
	if batch <= 0 {
		batch = DefaultBatch
	}
	skew := 5 * time.Minute
	if s.MaxSkew != nil {
		skew = s.MaxSkew()
	}
	n := 0
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var instance, root string
		var seq, segment int64
		var head []byte
		if err := tx.QueryRow(ctx, "SELECT instance, seq, chain_hash, open_segment, root_bu::text FROM audit.sequence_head()").
			Scan(&instance, &seq, &head, &segment, &root); err != nil {
			return fmt.Errorf("chain head: %w", err)
		}
		rows, err := tx.Query(ctx, "SELECT id, event_id, producer, body::text, accepted_at FROM audit.sequence_pending($1)", batch)
		if err != nil {
			return fmt.Errorf("pending events: %w", err)
		}
		events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
			var p pending
			var body string
			err := r.Scan(&p.id, &p.eventID, &p.producer, &body, &p.accepted)
			p.body = []byte(body)
			return p, err
		})
		if err != nil {
			return fmt.Errorf("pending events: %w", err)
		}
		if len(events) == 0 {
			return nil
		}
		var prev integrity.Hash
		if len(head) != len(prev) {
			return errors.New("chain head: not a SHA-256 hash")
		}
		copy(prev[:], head)
		start := prev
		ids := make([]int64, len(events))
		bodies := make([][]byte, len(events))
		leaves := make([][]byte, len(events))
		chains := make([][]byte, len(events))
		for i, p := range events {
			body, err := recordBody(p, root)
			if err != nil {
				return fmt.Errorf("event %s: %w", p.eventID, err)
			}
			leaf := integrity.Leaf(body)
			link := integrity.Chain(prev, uint64(seq)+uint64(i)+1, leaf) // #nosec G115 -- seq is a non-negative position
			ids[i], bodies[i], leaves[i], chains[i] = p.id, body, leaf[:], link[:]
			prev = link
		}
		var end int64
		if err := tx.QueryRow(ctx, "SELECT audit.sequence_append($1, $2, $3, $4, $5, $6, $7::interval)",
			seq, start[:], ids, bodies, leaves, chains, fmt.Sprintf("%d microseconds", skew.Microseconds())).Scan(&end); err != nil {
			return fmt.Errorf("append: %w", err)
		}
		n = len(events)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("audit sequencer: %w", err)
	}
	return n, nil
}

// recordBody is a record's body (ADR-011): the accepted event plus its
// receipt time, its producer and its BU (the root BU when it names none),
// serialized once with sorted keys. Numbers keep their exact text.
func recordBody(p pending, root string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(p.body))
	dec.UseNumber()
	var ev map[string]any
	if err := dec.Decode(&ev); err != nil {
		return nil, err
	}
	ev["producer"] = p.producer
	ev["received_at"] = p.accepted.UTC().Format(time.RFC3339Nano)
	if _, ok := ev["bu_id"]; !ok {
		ev["bu_id"] = root
	}
	return integrity.Body(ev)
}

// Run sequences until ctx ends: at once while there is a backlog, otherwise
// every idle interval (default 200 ms, well within the 5-second p95
// searchability target). Errors go to onErr (may be nil) and are retried.
func (s Sequencer) Run(ctx context.Context, idle time.Duration, onErr func(error)) error {
	if idle <= 0 {
		idle = 200 * time.Millisecond
	}
	batch := s.Batch
	if batch <= 0 {
		batch = DefaultBatch
	}
	for {
		n, err := s.Step(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if onErr != nil {
				onErr(err)
			}
		}
		if n == batch && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(idle):
		}
	}
}

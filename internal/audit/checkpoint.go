package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/objstore"
	events "github.com/rformer/fair-app/pkg/audit"
)

// CheckpointEvery is how often the leader closes a segment (design §6.3;
// a constant, AC-09: it cannot be lengthened).
const CheckpointEvery = 15 * time.Minute

// Checkpointer closes segments with signed checkpoints (F-002 T-09, AC-09,
// AC-10; ADR-011). Run it on the leader.
type Checkpointer struct {
	DB    *pgxpool.Pool // connected as app_audit
	Key   *ecdsa.PrivateKey
	Audit events.Emitter // records audit.checkpoint (the SIEM copy, AC-10)
	// WORM, when set, receives a write-once copy of every checkpoint
	// (required in SaaS), locked for Retain (audit.retention_total).
	WORM   *objstore.Store
	Retain func() time.Duration
	Now    func() time.Time
}

// KeyID is the checkpoint key's id (hex SHA-256 of its PKIX encoding).
func (c Checkpointer) KeyID() (string, error) { return integrity.KeyID(&c.Key.PublicKey) }

// RegisterKey records the checkpoint key's public half (the service does
// this at startup). A new key retires the previous one; a retired key is
// refused.
func (c Checkpointer) RegisterKey(ctx context.Context) error {
	id, err := c.KeyID()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(&c.Key.PublicKey)
	if err != nil {
		return err
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := c.DB.Exec(ctx, "SELECT audit.signing_key_register($1, $2)", id, pemKey); err != nil {
		return fmt.Errorf("audit checkpoint key: %w", err)
	}
	return nil
}

func (c Checkpointer) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Close closes the open segment (empty or not) with a signed checkpoint and
// records audit.checkpoint in the same transaction. It returns the
// statement. The write-once copy follows (SaveCopies).
func (c Checkpointer) Close(ctx context.Context) (integrity.Statement, error) {
	keyID, err := c.KeyID()
	if err != nil {
		return integrity.Statement{}, err
	}
	var st integrity.Statement
	err = pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		var instance string
		var segment, from, to int64
		var chain, prev []byte
		var leaves [][]byte
		if err := tx.QueryRow(ctx, "SELECT instance, segment, seq_from, seq_to, chain_hash, prev_checkpoint_hash, leaves FROM audit.checkpoint_state()").
			Scan(&instance, &segment, &from, &to, &chain, &prev, &leaves); err != nil {
			return fmt.Errorf("checkpoint state: %w", err)
		}
		hs := make([]integrity.Hash, len(leaves))
		for i, l := range leaves {
			copy(hs[i][:], l)
		}
		st = integrity.Statement{V: integrity.Version, Instance: instance, Segment: uint64(segment), SeqFrom: uint64(from), SeqTo: uint64(to), // #nosec G115 -- positions are non-negative
			MerkleRoot: integrity.Root(hs), IssuedAt: c.now().UTC().Truncate(time.Microsecond), KeyID: keyID}
		copy(st.ChainHash[:], chain)
		copy(st.PrevCheckpointHash[:], prev)
		body, err := st.Marshal()
		if err != nil {
			return err
		}
		sig, err := integrity.Sign(c.Key, body)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT audit.checkpoint_close($1, $2)", body, sig); err != nil {
			return fmt.Errorf("checkpoint close: %w", err)
		}
		if c.Audit == nil {
			return errors.New("checkpoint: no audit emitter")
		}
		return c.Audit.Emit(events.WithTx(ctx, tx), events.Event{Type: "audit.checkpoint", Severity: events.SeverityInfo, Actor: "system:audit",
			Target: "checkpoint:" + strconv.FormatInt(segment, 10), Attributes: map[string]string{
				"segment": strconv.FormatInt(segment, 10), "seq_from": strconv.FormatInt(from, 10), "seq_to": strconv.FormatInt(to, 10),
				"key_id": keyID, "statement": string(body), "signature": base64.StdEncoding.EncodeToString(sig)}})
	})
	if err != nil {
		return integrity.Statement{}, fmt.Errorf("audit checkpoint: %w", err)
	}
	return st, nil
}

// CopyKey is where a checkpoint's write-once copy lives.
func CopyKey(instance string, segment int64) string {
	return fmt.Sprintf("checkpoints/%s/%d.json", instance, segment)
}

// SaveCopies writes the write-once copy of every checkpoint that has none
// yet, oldest first, and records where each went. A copy that fails stays
// pending and is retried on the next call. Without a WORM store it does
// nothing.
func (c Checkpointer) SaveCopies(ctx context.Context) (int, error) {
	if c.WORM == nil {
		return 0, nil
	}
	rows, err := c.DB.Query(ctx, "SELECT segment, statement, signature, instance FROM audit.checkpoint_unsaved(100)")
	if err != nil {
		return 0, fmt.Errorf("audit checkpoint copies: %w", err)
	}
	type unsaved struct {
		segment   int64
		stmt, sig []byte
		instance  string
	}
	pending, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (unsaved, error) {
		var u unsaved
		err := r.Scan(&u.segment, &u.stmt, &u.sig, &u.instance)
		return u, err
	})
	if err != nil {
		return 0, fmt.Errorf("audit checkpoint copies: %w", err)
	}
	retain := 7 * 365 * 24 * time.Hour
	if c.Retain != nil {
		retain = c.Retain()
	}
	n := 0
	for _, u := range pending {
		body, err := json.Marshal(integrity.Checkpoint{Statement: u.stmt, Signature: u.sig}) // the evidence format
		if err != nil {
			return n, err
		}
		key := CopyKey(u.instance, u.segment)
		if _, err := c.WORM.Put(ctx, key, body, c.now().Add(retain)); err != nil {
			return n, fmt.Errorf("audit checkpoint %d copy: %w", u.segment, err)
		}
		if _, err := c.DB.Exec(ctx, "SELECT audit.checkpoint_set_worm($1, $2)", u.segment, key); err != nil {
			return n, fmt.Errorf("audit checkpoint %d copy: %w", u.segment, err)
		}
		n++
	}
	return n, nil
}

// Run closes a segment every interval (CheckpointEvery when zero) and
// saves the write-once copies, until ctx ends. Errors go to onErr.
func (c Checkpointer) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = CheckpointEvery
	}
	report := func(err error) {
		if err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_, err := c.Close(ctx)
			report(err)
			_, err = c.SaveCopies(ctx)
			report(err)
		}
	}
}

// Package evidence defines the audit trail's evidence files and verifies
// them offline (F-002 T-10, AC-11; design §11; ADR-011): export bundles
// (§6.6), segment archives (§6.7), checkpoint files and the external copies
// of checkpoints (the SIEM stream and the write-once copies, AC-10).
//
// It is what fair-audit-verify runs, so it uses only the standard library
// and internal/audit/integrity (SHA-256 and ECDSA P-256 from the FIPS 140
// module), and never touches the network. The writers here are the ones the
// audit service uses, so what it produces is what the verifier reads.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// MaxLine bounds one line of an evidence file (a record body, a proof or a
// checkpoint).
const MaxLine = 16 << 20

// ErrInvalid marks evidence that is malformed or does not verify. Failures
// at a record or checkpoint are *integrity.Failure (which names it); other
// failures wrap ErrInvalid.
var ErrInvalid = errors.New("evidence")

// ErrInsufficient is returned when the input cannot decide the question,
// for example checkpoints that do not reach back far enough.
var ErrInsufficient = errors.New("evidence: insufficient input")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Keys maps key ids (ADR-011) to public keys.
type Keys map[string]*ecdsa.PublicKey

// IDs lists the key ids, sorted.
func (k Keys) IDs() []string {
	ids := make([]string, 0, len(k))
	for id := range k {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ParseKeys reads PEM "PUBLIC KEY" blocks (ECDSA P-256) and indexes them by
// key id. Anything else in the input is refused.
func ParseKeys(b []byte) (Keys, error) {
	keys := Keys{}
	rest := bytes.TrimSpace(b)
	for len(rest) > 0 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, invalid("keys: not PEM")
		}
		if blk.Type != "PUBLIC KEY" {
			return nil, invalid("keys: a %s block; only public keys belong here", blk.Type)
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, invalid("keys: %v", err)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, invalid("keys: not an ECDSA key")
		}
		id, err := integrity.KeyID(pub)
		if err != nil {
			return nil, invalid("keys: %v", err)
		}
		keys[id] = pub
		rest = bytes.TrimSpace(rest)
	}
	if len(keys) == 0 {
		return nil, invalid("keys: none")
	}
	return keys, nil
}

// EncodeKeys writes keys as PEM, in key id order.
func EncodeKeys(keys Keys) ([]byte, error) {
	var buf bytes.Buffer
	for _, id := range keys.IDs() {
		der, err := x509.MarshalPKIXPublicKey(keys[id])
		if err != nil {
			return nil, err
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// lines calls fn with each line of r (without its newline) and its number
// from 1. A final line without a newline counts; an empty last line does
// not.
func lines(r io.Reader, fn func(n int, line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	n := 0
	for sc.Scan() {
		n++
		if err := fn(n, sc.Bytes()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return invalid("line %d: %v", n+1, err)
	}
	return nil
}

// WriteCheckpoints writes a checkpoints file: one JSON checkpoint
// (integrity.Checkpoint) per line.
func WriteCheckpoints(w io.Writer, cps []integrity.Checkpoint) error {
	for _, cp := range cps {
		b, err := json.Marshal(cp)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// ReadCheckpoints reads a checkpoints file.
func ReadCheckpoints(r io.Reader) ([]integrity.Checkpoint, error) {
	var cps []integrity.Checkpoint
	err := lines(r, func(n int, line []byte) error {
		var cp integrity.Checkpoint
		if err := strictJSON(line, &cp); err != nil || len(cp.Statement) == 0 || len(cp.Signature) == 0 {
			return invalid("checkpoints line %d: not a checkpoint", n)
		}
		cps = append(cps, cp)
		return nil
	})
	return cps, err
}

// strictJSON decodes one JSON value, refusing unknown fields and trailing
// data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Chain is a verified run of consecutive checkpoints.
type Chain struct {
	Statements []integrity.Statement
	// Anchored is true when the run starts at segment 1, so it is linked
	// all the way to the instance's genesis. A run starting later is
	// anchored on its first statement's own link, which is signed but not
	// checked against anything earlier.
	Anchored  bool
	bySegment map[uint64]int
}

// Segment returns the verified statement of a segment.
func (c Chain) Segment(n uint64) (integrity.Statement, bool) {
	i, ok := c.bySegment[n]
	if !ok {
		return integrity.Statement{}, false
	}
	return c.Statements[i], true
}

// PrevChain is the chain hash before segment n's first record: the chain
// hash of segment n−1's statement, or the genesis for segment 1.
func (c Chain) PrevChain(n uint64) (integrity.Hash, bool) {
	if n == 1 && len(c.Statements) > 0 {
		return integrity.Genesis(c.Statements[0].Instance), true
	}
	s, ok := c.Segment(n - 1)
	return s.ChainHash, ok
}

// Instance is the chain's instance.
func (c Chain) Instance() string {
	if len(c.Statements) == 0 {
		return ""
	}
	return c.Statements[0].Instance
}

// VerifyChain checks a run of consecutive checkpoints: canonical, signed by
// one of keys, numbered on, contiguous, and each linked to the one before;
// segment 1 to the genesis.
func VerifyChain(cps []integrity.Checkpoint, keys Keys) (Chain, error) {
	if len(cps) == 0 {
		return Chain{}, invalid("no checkpoints")
	}
	first, err := integrity.ParseStatement(cps[0].Statement)
	if err != nil {
		return Chain{}, invalid("checkpoints line 1: %v", err)
	}
	prev, next := first.PrevCheckpointHash, first.SeqFrom
	anchored := first.Segment == 1
	if anchored {
		prev, next = integrity.Genesis(first.Instance), 1
	}
	sts, err := integrity.VerifyCheckpoints(first.Instance, prev, next, cps, keys)
	if err != nil {
		return Chain{}, err
	}
	c := Chain{Statements: sts, Anchored: anchored, bySegment: make(map[uint64]int, len(sts))}
	for i, s := range sts {
		c.bySegment[s.Segment] = i
	}
	return c, nil
}

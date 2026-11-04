// Package integrity holds the audit trail's integrity primitives (F-002
// T-01, ADR-011; F-002-AC-07, AC-11): record bodies, leaf and chain hashes,
// RFC 9162 Merkle trees and inclusion proofs over a segment's leaves, and
// signed checkpoint statements.
//
// It uses only the standard library (SHA-256 and ECDSA P-256 run in the FIPS
// 140 module in our builds), so the offline verifier fair-audit-verify can
// depend on it without network access or third-party code.
package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the trail format version (ADR-011). A change of algorithm is a
// new version with a new genesis.
const Version = 1

// genesisLabel prefixes the instance id in chain(0).
const genesisLabel = "fair-audit-v1"

// Hash is a SHA-256 digest. In JSON it is lowercase hex.
type Hash [sha256.Size]byte

// String is the lowercase hex form.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText implements encoding.TextMarshaler (lowercase hex).
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler; only lowercase hex of
// the right length is accepted, so every hash has one spelling.
func (h *Hash) UnmarshalText(b []byte) error {
	p, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = p
	return nil
}

// ParseHash parses lowercase hex.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*len(h) {
		return h, fmt.Errorf("integrity: hash %q: want %d hex digits", s, 2*len(h))
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return h, fmt.Errorf("integrity: hash %q: lowercase hex only", s)
		}
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, err
	}
	return h, nil
}

// Body serializes v as a record body or checkpoint statement: JSON with
// object keys sorted, no insignificant whitespace, no HTML escaping, numbers
// kept exactly as given. The trail stores these bytes and hashes them as they
// are; verifiers never re-serialize them.
func Body(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil { // maps encode with sorted keys
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// IsBody reports whether b is exactly what Body produces for its own value,
// so a document has one byte form.
func IsBody(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return false
	}
	c, err := Body(v)
	return err == nil && bytes.Equal(c, b)
}

// Leaf is the RFC 9162 leaf hash of a body: SHA-256(0x00 ‖ body).
func Leaf(body []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(body)
	var out Hash
	h.Sum(out[:0])
	return out
}

// Genesis is chain(0) of an instance: SHA-256("fair-audit-v1" ‖ instance).
// It is also segment 1's previous checkpoint hash.
func Genesis(instance string) Hash {
	return sha256.Sum256([]byte(genesisLabel + instance))
}

// Chain links a record to the one before it:
// SHA-256(0x01 ‖ prev ‖ seq as 8 bytes, big-endian ‖ leaf). Its input is
// always 73 bytes, a Merkle node's 65, so the shared prefix byte cannot make
// one pass for the other.
func Chain(prev Hash, seq uint64, leaf Hash) Hash {
	var in [1 + 32 + 8 + 32]byte
	in[0] = 0x01
	copy(in[1:33], prev[:])
	binary.BigEndian.PutUint64(in[33:41], seq)
	copy(in[41:], leaf[:])
	return sha256.Sum256(in[:])
}

// Record is a stored record as a verifier sees it.
type Record struct {
	Seq   uint64
	Body  []byte
	Leaf  Hash // as stored
	Chain Hash // as stored
}

// Failure says where verification failed: the first record (Seq) or
// checkpoint (Segment) that does not verify.
type Failure struct {
	Seq     uint64 // 0 when the failure is a checkpoint's
	Segment uint64 // 0 when the failure is a record's
	Reason  string
}

func (f *Failure) Error() string {
	if f.Segment != 0 {
		return fmt.Sprintf("integrity: segment %d: %s", f.Segment, f.Reason)
	}
	return fmt.Sprintf("integrity: record %d: %s", f.Seq, f.Reason)
}

// ErrEmpty is returned for an empty input where one is required.
var ErrEmpty = errors.New("integrity: nothing to verify")

// VerifyRecords replays the chain over recs, which must follow the record
// with chain hash prev and sequence number firstSeq−1. It returns the chain
// hash of the last record, or a *Failure naming the first record that is out
// of sequence, whose leaf does not match its body, or whose chain hash does
// not follow.
func VerifyRecords(prev Hash, firstSeq uint64, recs []Record) (Hash, error) {
	want := firstSeq
	for _, r := range recs {
		if r.Seq != want {
			return prev, &Failure{Seq: want, Reason: fmt.Sprintf("missing or out of order (found %d)", r.Seq)}
		}
		leaf := Leaf(r.Body)
		if leaf != r.Leaf {
			return prev, &Failure{Seq: r.Seq, Reason: "body does not match its leaf hash"}
		}
		c := Chain(prev, r.Seq, leaf)
		if c != r.Chain {
			return prev, &Failure{Seq: r.Seq, Reason: "chain hash does not follow the previous record"}
		}
		prev = c
		want++
	}
	return prev, nil
}

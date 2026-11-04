package integrity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Statement is a checkpoint statement (ADR-011): the state of the trail when
// a segment closed. Its serialized form (Marshal) is what is signed, hashed
// into the next statement, stored and exported.
type Statement struct {
	V                  int       `json:"v"`
	Instance           string    `json:"instance"`
	Segment            uint64    `json:"segment"`  // from 1
	SeqFrom            uint64    `json:"seq_from"` // previous SeqTo + 1
	SeqTo              uint64    `json:"seq_to"`   // SeqFrom − 1 when the segment is empty
	MerkleRoot         Hash      `json:"merkle_root"`
	ChainHash          Hash      `json:"chain_hash"` // chain hash at SeqTo
	PrevCheckpointHash Hash      `json:"prev_checkpoint_hash"`
	IssuedAt           time.Time `json:"issued_at"` // UTC
	KeyID              string    `json:"key_id"`
}

// Count is the number of records the segment covers.
func (s Statement) Count() uint64 { return s.SeqTo + 1 - s.SeqFrom }

// Marshal serializes the statement as a body (sorted keys, compact).
func (s Statement) Marshal() ([]byte, error) {
	if s.V != Version {
		return nil, fmt.Errorf("integrity: statement version %d, want %d", s.V, Version)
	}
	if s.SeqFrom == 0 || s.SeqTo+1 < s.SeqFrom || s.Segment == 0 || s.Instance == "" || s.KeyID == "" {
		return nil, errors.New("integrity: statement needs an instance, a key id, segment ≥ 1 and seq_from ≥ 1 with seq_to ≥ seq_from − 1")
	}
	s.IssuedAt = s.IssuedAt.UTC()
	return Body(s)
}

// ParseStatement parses a serialized statement and refuses any byte form
// other than the one Marshal produces, so a statement has one hash.
func ParseStatement(b []byte) (Statement, error) {
	var s Statement
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("integrity: statement: %w", err)
	}
	again, err := s.Marshal()
	if err != nil {
		return s, err
	}
	if string(again) != string(b) {
		return s, errors.New("integrity: statement is not in canonical form")
	}
	return s, nil
}

// StatementHash is the hash a statement is linked by: SHA-256 of its bytes.
func StatementHash(statement []byte) Hash { return sha256.Sum256(statement) }

// KeyID is the hex SHA-256 of the PKIX encoding of a public key (the form
// posture exports use).
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(der)
	return hex.EncodeToString(d[:]), nil
}

// ErrKey is returned for a key that is not ECDSA P-256.
var ErrKey = errors.New("integrity: checkpoint keys are ECDSA P-256")

// Sign signs a serialized statement: ECDSA P-256 over SHA-256, ASN.1.
func Sign(key *ecdsa.PrivateKey, statement []byte) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	d := sha256.Sum256(statement)
	return ecdsa.SignASN1(rand.Reader, key, d[:])
}

// VerifySignature checks a statement's signature.
func VerifySignature(pub *ecdsa.PublicKey, statement, sig []byte) bool {
	if pub == nil || pub.Curve != elliptic.P256() {
		return false
	}
	d := sha256.Sum256(statement)
	return ecdsa.VerifyASN1(pub, d[:], sig)
}

// Checkpoint is a signed statement as stored and exported.
type Checkpoint struct {
	Statement []byte // serialized, canonical
	Signature []byte
}

// VerifyCheckpoints checks a run of consecutive checkpoints of one instance:
// each statement canonical and signed by a known key, segments numbered on
// from the first, sequence numbers contiguous, and each statement linked to
// the one before. prev is the statement hash before the first checkpoint
// (Genesis(instance) when it is segment 1) and nextSeq its expected seq_from.
// keys maps key ids to public keys. It returns the parsed statements, or a
// *Failure naming the first checkpoint that does not verify.
func VerifyCheckpoints(instance string, prev Hash, nextSeq uint64, cps []Checkpoint, keys map[string]*ecdsa.PublicKey) ([]Statement, error) {
	out := make([]Statement, 0, len(cps))
	var seg uint64
	for i, cp := range cps {
		s, err := ParseStatement(cp.Statement)
		if err != nil {
			return out, &Failure{Segment: seg + 1, Reason: err.Error()}
		}
		if i == 0 {
			seg = s.Segment
		} else {
			seg++
		}
		switch {
		case s.Segment != seg:
			return out, &Failure{Segment: seg, Reason: fmt.Sprintf("missing or out of order (found segment %d)", s.Segment)}
		case s.Instance != instance:
			return out, &Failure{Segment: seg, Reason: fmt.Sprintf("belongs to instance %q", s.Instance)}
		case s.SeqFrom != nextSeq:
			return out, &Failure{Segment: seg, Reason: fmt.Sprintf("starts at record %d, want %d", s.SeqFrom, nextSeq)}
		case s.PrevCheckpointHash != prev:
			return out, &Failure{Segment: seg, Reason: "not linked to the previous checkpoint"}
		}
		pub, ok := keys[s.KeyID]
		if !ok {
			return out, &Failure{Segment: seg, Reason: fmt.Sprintf("signed by unknown key %s", s.KeyID)}
		}
		if !VerifySignature(pub, cp.Statement, cp.Signature) {
			return out, &Failure{Segment: seg, Reason: "signature does not verify"}
		}
		out = append(out, s)
		prev = StatementHash(cp.Statement)
		nextSeq = s.SeqTo + 1
	}
	return out, nil
}

// VerifySegment checks a segment's records against its (already verified)
// statement: the records are exactly seq_from..seq_to, each chained from
// prevChain (the chain hash at seq_from − 1), ending at the statement's chain
// hash, with the statement's Merkle root over their leaves. It returns a
// *Failure naming the first record or the segment that does not verify.
func VerifySegment(s Statement, prevChain Hash, recs []Record) error {
	if uint64(len(recs)) != s.Count() {
		if _, err := VerifyRecords(prevChain, s.SeqFrom, recs); err != nil {
			return err
		}
		return &Failure{Segment: s.Segment, Reason: fmt.Sprintf("has %d records, the checkpoint covers %d", len(recs), s.Count())}
	}
	end, err := VerifyRecords(prevChain, s.SeqFrom, recs)
	if err != nil {
		return err
	}
	if s.Count() > 0 && end != s.ChainHash {
		return &Failure{Segment: s.Segment, Reason: "chain does not end at the checkpoint's chain hash"}
	}
	if s.Count() == 0 && s.ChainHash != prevChain {
		return &Failure{Segment: s.Segment, Reason: "empty segment's chain hash differs from the previous one"}
	}
	leaves := make([]Hash, len(recs))
	for i, r := range recs {
		leaves[i] = r.Leaf
	}
	if Root(leaves) != s.MerkleRoot {
		return &Failure{Segment: s.Segment, Reason: "Merkle root does not match the checkpoint"}
	}
	return nil
}

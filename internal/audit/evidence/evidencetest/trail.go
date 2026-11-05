// Package evidencetest builds synthetic audit trails for tests of the
// evidence formats and fair-audit-verify: records, segments and signed
// checkpoints made with the integrity primitives, as the sequencer and the
// checkpointer make the real ones.
package evidencetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// Trail is a synthetic trail.
type Trail struct {
	Instance    string
	Keys        []*ecdsa.PrivateKey // two; the second signs from the rotation on
	Records     []integrity.Record  // Records[i].Seq == i+1
	Checkpoints []integrity.Checkpoint
	Statements  []integrity.Statement
	segmentOf   map[uint64]uint64
}

// New builds segments of the given sizes (0: an empty segment). The key
// rotates at segment rotateAt (0: never).
func New(t testing.TB, sizes []int, rotateAt int) *Trail {
	t.Helper()
	tr := &Trail{Instance: "inst-test", segmentOf: map[uint64]uint64{}}
	for i := 0; i < 2; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tr.Keys = append(tr.Keys, k)
	}
	chain := integrity.Genesis(tr.Instance)
	prevStmt := chain
	seq := uint64(0)
	issued := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for si, n := range sizes {
		segment := uint64(si + 1) // #nosec G115 -- test sizes
		from := seq + 1
		var leaves []integrity.Hash
		for j := 0; j < n; j++ {
			seq++
			body, err := integrity.Body(map[string]any{"id": fmt.Sprintf("ev-%d", seq), "type": "db.migrated", "severity": "info",
				"actor": "x", "producer": "app_rw", "received_at": issued.Format(time.RFC3339Nano),
				"attributes": map[string]any{"n": seq, "text": "a \"quoted\" <tag> & é"}})
			if err != nil {
				t.Fatal(err)
			}
			leaf := integrity.Leaf(body)
			chain = integrity.Chain(chain, seq, leaf)
			tr.Records = append(tr.Records, integrity.Record{Seq: seq, Body: body, Leaf: leaf, Chain: chain})
			tr.segmentOf[seq] = segment
			leaves = append(leaves, leaf)
		}
		key := tr.Keys[0]
		if rotateAt > 0 && si+1 >= rotateAt {
			key = tr.Keys[1]
		}
		id, err := integrity.KeyID(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		st := integrity.Statement{V: integrity.Version, Instance: tr.Instance, Segment: segment, SeqFrom: from, SeqTo: seq,
			MerkleRoot: integrity.Root(leaves), ChainHash: chain, PrevCheckpointHash: prevStmt,
			IssuedAt: issued.Add(time.Duration(si) * 15 * time.Minute), KeyID: id}
		b, err := st.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := integrity.Sign(key, b)
		if err != nil {
			t.Fatal(err)
		}
		tr.Checkpoints = append(tr.Checkpoints, integrity.Checkpoint{Statement: b, Signature: sig})
		tr.Statements = append(tr.Statements, st)
		prevStmt = integrity.StatementHash(b)
	}
	return tr
}

// PublicKeys maps both keys' ids to their public keys.
func (tr *Trail) PublicKeys() map[string]*ecdsa.PublicKey {
	ks := map[string]*ecdsa.PublicKey{}
	for _, k := range tr.Keys {
		id, _ := integrity.KeyID(&k.PublicKey)
		ks[id] = &k.PublicKey
	}
	return ks
}

// SegmentRecords are segment n's records.
func (tr *Trail) SegmentRecords(n uint64) []integrity.Record {
	st := tr.Statements[n-1]
	return append([]integrity.Record(nil), tr.Records[st.SeqFrom-1:st.SeqTo]...)
}

// Proof places record seq in its segment: the segment and the inclusion
// path.
func (tr *Trail) Proof(t testing.TB, seq uint64) (uint64, []integrity.Hash) {
	t.Helper()
	seg := tr.segmentOf[seq]
	st := tr.Statements[seg-1]
	var leaves []integrity.Hash
	for _, r := range tr.SegmentRecords(seg) {
		leaves = append(leaves, r.Leaf)
	}
	path, err := integrity.NewTree(leaves).Path(seq - st.SeqFrom)
	if err != nil {
		t.Fatal(err)
	}
	return seg, path
}

package integrity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"
	"time"
)

// F-002 T-01 (AC-07, AC-11; ADR-011).

func h(t *testing.T, s string) Hash {
	t.Helper()
	x, err := ParseHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// The Certificate Transparency test vectors (RFC 6962/9162 trees): roots of
// the first n leaves and inclusion paths.
var ctLeaves = [][]byte{
	{}, {0x00}, {0x10}, {0x20, 0x21}, {0x30, 0x31}, {0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

var ctRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func ctLeafHashes() []Hash {
	out := make([]Hash, len(ctLeaves))
	for i, l := range ctLeaves {
		out[i] = Leaf(l)
	}
	return out
}

func TestMerkleCTVectors(t *testing.T) {
	if EmptyRoot.String() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", EmptyRoot)
	}
	if Root(nil) != EmptyRoot {
		t.Fatal("Root(nil) is not the empty root")
	}
	leaves := ctLeafHashes()
	for n := 1; n <= len(leaves); n++ {
		if got := Root(leaves[:n]); got.String() != ctRoots[n-1] {
			t.Errorf("root of %d leaves: %s, want %s", n, got, ctRoots[n-1])
		}
	}
	for _, tc := range []struct {
		index, size uint64
		path        []string
	}{
		{0, 8, []string{"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"}},
		{5, 8, []string{"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
		{2, 3, []string{"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"}},
		{1, 5, []string{"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"}},
	} {
		tree := NewTree(leaves[:tc.size])
		path, err := tree.Path(tc.index)
		if err != nil {
			t.Fatal(err)
		}
		if len(path) != len(tc.path) {
			t.Fatalf("path(%d, %d) has %d hashes, want %d", tc.index, tc.size, len(path), len(tc.path))
		}
		for i := range path {
			if path[i].String() != tc.path[i] {
				t.Errorf("path(%d, %d)[%d] = %s, want %s", tc.index, tc.size, i, path[i], tc.path[i])
			}
		}
		if !VerifyInclusion(leaves[tc.index], tc.index, tc.size, path, h(t, ctRoots[tc.size-1])) {
			t.Errorf("path(%d, %d) does not verify", tc.index, tc.size)
		}
	}
}

// refRoot and refPath are RFC 9162 §2.1.1 and §2.1.3.1 written as recursion,
// to check Tree's level-by-level construction against.
func refRoot(d []Hash) Hash {
	switch len(d) {
	case 0:
		return EmptyRoot
	case 1:
		return d[0]
	}
	k := 1
	for k*2 < len(d) {
		k *= 2
	}
	return node(refRoot(d[:k]), refRoot(d[k:]))
}

func refPath(m int, d []Hash) []Hash {
	if len(d) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(d) {
		k *= 2
	}
	if m < k {
		return append(refPath(m, d[:k]), refRoot(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refRoot(d[:k]))
}

func leavesN(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = Leaf([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	return out
}

func TestTreeMatchesRFCAndProofsVerify(t *testing.T) {
	for n := 0; n <= 70; n++ {
		d := leavesN(n)
		tree := NewTree(d)
		if tree.Root() != refRoot(d) {
			t.Fatalf("n=%d: root differs from RFC 9162", n)
		}
		if _, err := tree.Path(uint64(n)); !errors.Is(err, ErrIndex) {
			t.Fatalf("n=%d: path past the end: %v", n, err)
		}
		for m := 0; m < n; m++ {
			p, err := tree.Path(uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			want := refPath(m, d)
			if len(p) != len(want) {
				t.Fatalf("n=%d m=%d: path length %d, want %d", n, m, len(p), len(want))
			}
			for i := range p {
				if p[i] != want[i] {
					t.Fatalf("n=%d m=%d: path differs from RFC 9162 at %d", n, m, i)
				}
			}
			root := tree.Root()
			if !VerifyInclusion(d[m], uint64(m), uint64(n), p, root) {
				t.Fatalf("n=%d m=%d: proof does not verify", n, m)
			}
			// Wrong leaf, index, size, path or root: refused.
			other := Leaf([]byte("other"))
			if VerifyInclusion(other, uint64(m), uint64(n), p, root) {
				t.Fatalf("n=%d m=%d: a different leaf verified", n, m)
			}
			if n > 1 && VerifyInclusion(d[m], uint64((m+1)%n), uint64(n), p, root) {
				t.Fatalf("n=%d m=%d: the proof verified at another index", n, m)
			}
			if len(p) > 0 {
				bad := append([]Hash(nil), p...)
				bad[len(bad)/2][0] ^= 1
				if VerifyInclusion(d[m], uint64(m), uint64(n), bad, root) {
					t.Fatalf("n=%d m=%d: an altered path verified", n, m)
				}
				if VerifyInclusion(d[m], uint64(m), uint64(n), p[:len(p)-1], root) {
					t.Fatalf("n=%d m=%d: a shortened path verified", n, m)
				}
			}
			if VerifyInclusion(d[m], uint64(m), uint64(n), append(append([]Hash(nil), p...), other), root) {
				t.Fatalf("n=%d m=%d: a lengthened path verified", n, m)
			}
			bad := root
			bad[0] ^= 1
			if VerifyInclusion(d[m], uint64(m), uint64(n), p, bad) {
				t.Fatalf("n=%d m=%d: verified against another root", n, m)
			}
		}
	}
	if VerifyInclusion(Leaf(nil), 0, 0, nil, EmptyRoot) {
		t.Fatal("a proof into an empty tree verified")
	}
}

func TestBody(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{map[string]any{"b": 1, "a": "x<y&z", "c": []any{true, nil}}, `{"a":"x<y&z","b":1,"c":[true,null]}`},
		{struct {
			Z string         `json:"z"`
			A map[string]int `json:"a"`
		}{"é", map[string]int{"y": 2, "x": 1}}, `{"a":{"x":1,"y":2},"z":"é"}`},
		{[]byte(`{"n":1.0,"big":123456789012345678901234567890,"e":1e400}`), ""},
	} {
		if raw, ok := tc.in.([]byte); ok {
			// Numbers are kept exactly as given.
			var v any
			if err := jsonUnmarshalNumber(raw, &v); err != nil {
				t.Fatal(err)
			}
			got, err := Body(v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != `{"big":123456789012345678901234567890,"e":1e400,"n":1.0}` {
				t.Errorf("numbers: %s", got)
			}
			continue
		}
		got, err := Body(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("Body = %s, want %s", got, tc.want)
		}
		if !IsBody(got) {
			t.Errorf("%s is not a body", got)
		}
	}
	for _, s := range []string{`{"b":1,"a":2}`, `{"a": 1}`, `{"a":"` + string(rune(92)) + `u003c"}`, `{"a":1}` + "\n", `{"a":1}{}`, `nope`} {
		if IsBody([]byte(s)) {
			t.Errorf("%q passed as a body", s)
		}
	}
}

func TestChainVectors(t *testing.T) {
	g := Genesis("inst-1")
	if g.String() != "7b9fa466a67f419eae91255e071713796733961bf410b73bf53f7efe03a55d76" {
		t.Fatalf("genesis %s", g)
	}
	body, err := Body(map[string]any{"b": "x<y", "a": 1})
	if err != nil || string(body) != `{"a":1,"b":"x<y"}` {
		t.Fatalf("body %s: %v", body, err)
	}
	leaf := Leaf(body)
	if leaf.String() != "6f0688be1c01170d21e2299c076ad4b1fc67d8ab057f2ac1a9add39b3eb95e12" {
		t.Fatalf("leaf %s", leaf)
	}
	if c := Chain(g, 1, leaf); c.String() != "256a34a34a6160d959b524abb3aa4d17c96b136e34409757321f1fd35a3667fa" {
		t.Fatalf("chain %s", c)
	}
	if Genesis("inst-2") == g {
		t.Fatal("instances share a genesis")
	}
}

func TestParseHash(t *testing.T) {
	good := "6f0688be1c01170d21e2299c076ad4b1fc67d8ab057f2ac1a9add39b3eb95e12"
	if _, err := ParseHash(good); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", good[:62], good + "00", "6F0688be1c01170d21e2299c076ad4b1fc67d8ab057f2ac1a9add39b3eb95e12", "zz" + good[2:]} {
		if _, err := ParseHash(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

// --- a trail built in memory --------------------------------------------

type trail struct {
	instance string
	key      *ecdsa.PrivateKey
	keyID    string
	recs     []Record // all records, seq from 1
	cps      []Checkpoint
	stmts    []Statement
	ends     []Hash // chain hash before each segment
}

func newTrail(t *testing.T, sizes ...int) *trail {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := KeyID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tr := &trail{instance: "inst-1", key: key, keyID: id}
	chain := Genesis(tr.instance)
	prevCP := Genesis(tr.instance)
	seq := uint64(1)
	for si, n := range sizes {
		tr.ends = append(tr.ends, chain)
		from := seq
		var leaves []Hash
		for i := 0; i < n; i++ {
			body, err := Body(map[string]any{"id": fmt.Sprintf("e%d", seq), "type": "test.event", "n": seq})
			if err != nil {
				t.Fatal(err)
			}
			leaf := Leaf(body)
			chain = Chain(chain, seq, leaf)
			tr.recs = append(tr.recs, Record{Seq: seq, Body: body, Leaf: leaf, Chain: chain})
			leaves = append(leaves, leaf)
			seq++
		}
		s := Statement{V: Version, Instance: tr.instance, Segment: uint64(si + 1), SeqFrom: from, SeqTo: seq - 1,
			MerkleRoot: Root(leaves), ChainHash: chain, PrevCheckpointHash: prevCP,
			IssuedAt: time.Date(2026, 11, 4, 10, 15*si, 0, 0, time.UTC), KeyID: id}
		b, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(key, b)
		if err != nil {
			t.Fatal(err)
		}
		tr.cps = append(tr.cps, Checkpoint{Statement: b, Signature: sig})
		tr.stmts = append(tr.stmts, s)
		prevCP = StatementHash(b)
	}
	return tr
}

func (tr *trail) keys() map[string]*ecdsa.PublicKey {
	return map[string]*ecdsa.PublicKey{tr.keyID: &tr.key.PublicKey}
}

func (tr *trail) segmentRecords(i int) []Record {
	s := tr.stmts[i]
	return append([]Record(nil), tr.recs[s.SeqFrom-1:s.SeqTo]...)
}

// verifyAll checks every checkpoint and every segment, as the verifier does.
func (tr *trail) verifyAll(cps []Checkpoint, segs [][]Record) error {
	stmts, err := VerifyCheckpoints(tr.instance, Genesis(tr.instance), 1, cps, tr.keys())
	if err != nil {
		return err
	}
	prev := Genesis(tr.instance)
	for i, s := range stmts {
		if err := VerifySegment(s, prev, segs[i]); err != nil {
			return err
		}
		prev = s.ChainHash
	}
	return nil
}

func (tr *trail) segments() [][]Record {
	out := make([][]Record, len(tr.stmts))
	for i := range tr.stmts {
		out[i] = tr.segmentRecords(i)
	}
	return out
}

func TestIntactTrailVerifies(t *testing.T) {
	tr := newTrail(t, 5, 0, 1, 17, 3)
	if err := tr.verifyAll(tr.cps, tr.segments()); err != nil {
		t.Fatal(err)
	}
	if end, err := VerifyRecords(Genesis(tr.instance), 1, tr.recs); err != nil || end != tr.recs[len(tr.recs)-1].Chain {
		t.Fatalf("whole chain: %v", err)
	}
	if tr.stmts[1].Count() != 0 || tr.stmts[1].SeqTo+1 != tr.stmts[1].SeqFrom {
		t.Fatal("empty segment bounds")
	}
	// Every record proves its inclusion against its checkpoint's root.
	for i, s := range tr.stmts {
		seg := tr.segmentRecords(i)
		leaves := make([]Hash, len(seg))
		for j, r := range seg {
			leaves[j] = r.Leaf
		}
		tree := NewTree(leaves)
		for j := range seg {
			p, _ := tree.Path(uint64(j))
			if !VerifyInclusion(seg[j].Leaf, uint64(j), s.Count(), p, s.MerkleRoot) {
				t.Fatalf("segment %d record %d: inclusion", s.Segment, j)
			}
		}
	}
}

// Every way of changing the records is detected, and named at the first
// position affected (AC-07, AC-11).
func TestTamperingIsDetected(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2)) // #nosec G404 -- seeded for reproducible property tests
	for round := 0; round < 200; round++ {
		tr := newTrail(t, 4, 9, 6)
		segs := tr.segments()
		si := rng.IntN(len(segs))
		segNo := uint64(si) + 1 // #nosec G115 -- a small index
		seg := segs[si]
		j := rng.IntN(len(seg))
		want := seg[j].Seq
		kind := round % 8
		switch kind {
		case 0: // alter a body
			seg[j].Body = bytes.Replace(seg[j].Body, []byte("test.event"), []byte("test.evenT"), 1)
		case 1: // alter a body and recompute its leaf
			seg[j].Body = bytes.Replace(seg[j].Body, []byte("test.event"), []byte("test.evenT"), 1)
			seg[j].Leaf = Leaf(seg[j].Body)
		case 2: // alter a body, recompute leaf and chain from there on
			seg[j].Body = bytes.Replace(seg[j].Body, []byte("test.event"), []byte("test.evenT"), 1)
			prev := tr.ends[si]
			if j > 0 {
				prev = seg[j-1].Chain
			}
			for k := j; k < len(seg); k++ {
				seg[k].Leaf = Leaf(seg[k].Body)
				seg[k].Chain = Chain(prev, seg[k].Seq, seg[k].Leaf)
				prev = seg[k].Chain
			}
		case 3: // remove a record
			seg = append(seg[:j:j], seg[j+1:]...)
			if j == len(seg) { // the last one: the segment is short
				want = 0
			}
		case 4: // insert a record
			body := []byte(`{"id":"forged"}`)
			ins := Record{Seq: want, Body: body, Leaf: Leaf(body)}
			seg = append(seg[:j:j], append([]Record{ins}, seg[j:]...)...)
		case 5: // swap two records
			if j == len(seg)-1 {
				j--
				want = seg[j].Seq
			}
			seg[j], seg[j+1] = seg[j+1], seg[j]
		case 6: // truncate the segment
			seg = seg[:j]
			want = 0 // a segment failure, not a record's
		case 7: // remove a record and renumber and rechain the rest
			seg = append(seg[:j:j], seg[j+1:]...)
			prev := tr.ends[si]
			if j > 0 {
				prev = seg[j-1].Chain
			}
			for k := j; k < len(seg); k++ {
				seg[k].Seq--
				seg[k].Chain = Chain(prev, seg[k].Seq, seg[k].Leaf)
				prev = seg[k].Chain
			}
			want = 0
		}
		segs[si] = seg
		err := tr.verifyAll(tr.cps, segs)
		var f *Failure
		if !errors.As(err, &f) {
			t.Fatalf("round %d kind %d: not detected (%v)", round, kind, err)
		}
		switch {
		case want != 0 && f.Seq != want && (kind != 2 || f.Segment != segNo):
			t.Fatalf("round %d kind %d: failure at %v, want record %d", round, kind, f, want)
		case want == 0 && f.Segment != segNo:
			t.Fatalf("round %d kind %d: failure at %v, want segment %d", round, kind, f, si+1)
		}
	}
}

func TestCheckpointTamperingIsDetected(t *testing.T) {
	tr := newTrail(t, 2, 3, 0, 4)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resign := func(s Statement, key *ecdsa.PrivateKey) Checkpoint {
		b, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := Sign(key, b)
		return Checkpoint{Statement: b, Signature: sig}
	}
	for name, tc := range map[string]struct {
		mutate  func([]Checkpoint) []Checkpoint
		segment uint64
	}{
		"statement byte flipped": {func(c []Checkpoint) []Checkpoint {
			c[1].Statement = bytes.Replace(c[1].Statement, []byte(`"segment":2`), []byte(`"segment":7`), 1)
			return c
		}, 2},
		"signature by an unknown key": {func(c []Checkpoint) []Checkpoint {
			c[2] = resign(tr.stmts[2], other)
			return c
		}, 3},
		"forged statement with an unknown key id": {func(c []Checkpoint) []Checkpoint {
			s := tr.stmts[2]
			s.KeyID, _ = KeyID(&other.PublicKey)
			c[2] = resign(s, other)
			return c
		}, 3},
		"checkpoint removed": {func(c []Checkpoint) []Checkpoint { return append(c[:1:1], c[2:]...) }, 2},
		"checkpoints reordered": {func(c []Checkpoint) []Checkpoint {
			c[1], c[2] = c[2], c[1]
			return c
		}, 2},
		"re-signed with a broken link": {func(c []Checkpoint) []Checkpoint {
			s := tr.stmts[3]
			s.PrevCheckpointHash = Genesis("x")
			c[3] = resign(s, tr.key)
			return c
		}, 4},
		"re-signed with a gap in sequence numbers": {func(c []Checkpoint) []Checkpoint {
			s := tr.stmts[3]
			s.SeqFrom++
			c[3] = resign(s, tr.key)
			return c
		}, 4},
		"another instance's statement": {func(c []Checkpoint) []Checkpoint {
			s := tr.stmts[0]
			s.Instance = "inst-2"
			c[0] = resign(s, tr.key)
			return c
		}, 1},
		"not canonical": {func(c []Checkpoint) []Checkpoint {
			c[0].Statement = bytes.Replace(c[0].Statement, []byte(`{"chain_hash"`), []byte(`{ "chain_hash"`), 1)
			sig, _ := Sign(tr.key, c[0].Statement)
			c[0].Signature = sig
			return c
		}, 1},
	} {
		cps := append([]Checkpoint(nil), tr.cps...)
		for i := range cps {
			cps[i].Statement = append([]byte(nil), cps[i].Statement...)
		}
		_, err := VerifyCheckpoints(tr.instance, Genesis(tr.instance), 1, tc.mutate(cps), tr.keys())
		var f *Failure
		if !errors.As(err, &f) || f.Segment != tc.segment {
			t.Errorf("%s: %v, want a failure at segment %d", name, err, tc.segment)
		}
	}
	// A statement re-signed with the real key but a different root is
	// accepted as a checkpoint, and caught against the records.
	s := tr.stmts[1]
	s.MerkleRoot = EmptyRoot
	cps := append([]Checkpoint(nil), tr.cps...)
	cps[1] = resign(s, tr.key)
	cps[2] = resign(func() Statement { x := tr.stmts[2]; x.PrevCheckpointHash = StatementHash(cps[1].Statement); return x }(), tr.key)
	cps[3] = resign(func() Statement { x := tr.stmts[3]; x.PrevCheckpointHash = StatementHash(cps[2].Statement); return x }(), tr.key)
	err := tr.verifyAll(cps, tr.segments())
	var f *Failure
	if !errors.As(err, &f) || f.Segment != 2 {
		t.Fatalf("root mismatch: %v", err)
	}
}

func TestStatementRules(t *testing.T) {
	tr := newTrail(t, 1)
	s, err := ParseStatement(tr.cps[0].Statement)
	if err != nil {
		t.Fatal(err)
	}
	if s != tr.stmts[0] {
		t.Fatalf("round trip: %+v", s)
	}
	if !bytes.HasPrefix(tr.cps[0].Statement, []byte(`{"chain_hash":"`)) || !bytes.Contains(tr.cps[0].Statement, []byte(`"issued_at":"2026-11-04T10:00:00Z"`)) {
		t.Fatalf("statement form: %s", tr.cps[0].Statement)
	}
	for name, mut := range map[string]func(*Statement){
		"version":        func(s *Statement) { s.V = 2 },
		"segment 0":      func(s *Statement) { s.Segment = 0 },
		"seq_from 0":     func(s *Statement) { s.SeqFrom = 0 },
		"negative count": func(s *Statement) { s.SeqTo = s.SeqFrom - 2 },
		"no instance":    func(s *Statement) { s.Instance = "" },
		"no key id":      func(s *Statement) { s.KeyID = "" },
	} {
		x := tr.stmts[0]
		x.SeqFrom = 5
		x.SeqTo = 7
		mut(&x)
		if _, err := x.Marshal(); err == nil {
			t.Errorf("%s: marshalled", name)
		}
	}
	// A non-UTC time is written as UTC.
	x := tr.stmts[0]
	x.IssuedAt = time.Date(2026, 11, 4, 5, 0, 0, 0, time.FixedZone("EST", -5*3600))
	b, _ := x.Marshal()
	if !bytes.Contains(b, []byte(`"issued_at":"2026-11-04T10:00:00Z"`)) {
		t.Fatalf("UTC: %s", b)
	}
	// Unknown fields and other spellings are refused.
	for _, bad := range [][]byte{
		bytes.Replace(tr.cps[0].Statement, []byte(`{"chain_hash"`), []byte(`{"extra":1,"chain_hash"`), 1),
		bytes.Replace(tr.cps[0].Statement, []byte(`"issued_at":"2026-11-04T10:00:00Z"`), []byte(`"issued_at":"2026-11-04T10:00:00+00:00"`), 1),
	} {
		if _, err := ParseStatement(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestSigningKeys(t *testing.T) {
	tr := newTrail(t, 1)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Sign(p384, tr.cps[0].Statement); !errors.Is(err, ErrKey) {
		t.Fatalf("P-384 signing: %v", err)
	}
	if _, err := Sign(nil, tr.cps[0].Statement); !errors.Is(err, ErrKey) {
		t.Fatalf("nil key: %v", err)
	}
	if VerifySignature(&p384.PublicKey, tr.cps[0].Statement, tr.cps[0].Signature) || VerifySignature(nil, nil, nil) {
		t.Fatal("verified with a wrong key")
	}
	if !VerifySignature(&tr.key.PublicKey, tr.cps[0].Statement, tr.cps[0].Signature) {
		t.Fatal("does not verify")
	}
	id, _ := KeyID(&tr.key.PublicKey)
	if len(id) != 2*sha256.Size || id != tr.keyID {
		t.Fatalf("key id %s", id)
	}
}

// A key rotation between checkpoints verifies when both keys are known.
func TestKeyRotation(t *testing.T) {
	tr := newTrail(t, 2, 2)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id2, _ := KeyID(&k2.PublicKey)
	s := tr.stmts[1]
	s.KeyID = id2
	b, _ := s.Marshal()
	sig, _ := Sign(k2, b)
	cps := []Checkpoint{tr.cps[0], {Statement: b, Signature: sig}}
	keys := tr.keys()
	if _, err := VerifyCheckpoints(tr.instance, Genesis(tr.instance), 1, cps, keys); err == nil {
		t.Fatal("verified without the new key")
	}
	keys[id2] = &k2.PublicKey
	if _, err := VerifyCheckpoints(tr.instance, Genesis(tr.instance), 1, cps, keys); err != nil {
		t.Fatal(err)
	}
}

func jsonUnmarshalNumber(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

// Edge cases each rule needs on its own (found by mutation testing).
func TestVerificationEdgeCases(t *testing.T) {
	// A stored leaf altered while its body is intact is named at that record.
	tr := newTrail(t, 5)
	recs := append([]Record(nil), tr.recs...)
	recs[2].Leaf[0] ^= 1
	_, err := VerifyRecords(Genesis(tr.instance), 1, recs)
	var f *Failure
	if !errors.As(err, &f) || f.Seq != 3 || f.Reason != "body does not match its leaf hash" {
		t.Fatalf("altered leaf: %v", err)
	}

	// A proof cannot claim a bigger tree, or a leaf just past the end.
	for _, n := range []int{1, 2, 4, 8, 16} {
		d := leavesN(n)
		tree := NewTree(d)
		for m := 0; m < n; m++ {
			p, _ := tree.Path(uint64(m))
			if VerifyInclusion(d[m], uint64(m), uint64(n+1), p, tree.Root()) { // #nosec G115 -- small test sizes
				t.Fatalf("n=%d m=%d: verified as a tree of %d", n, m, n+1)
			}
		}
		if VerifyInclusion(d[n-1], uint64(n), uint64(n), nil, tree.Root()) { // #nosec G115 -- small test sizes
			t.Fatalf("n=%d: index n verified", n)
		}
	}

	// A re-signed statement with the wrong segment number.
	tr = newTrail(t, 2, 2, 2)
	s := tr.stmts[1]
	s.Segment = 5
	b, _ := s.Marshal()
	sig, _ := Sign(tr.key, b)
	cps := append([]Checkpoint(nil), tr.cps...)
	cps[1] = Checkpoint{Statement: b, Signature: sig}
	s2 := tr.stmts[2]
	s2.PrevCheckpointHash = StatementHash(b)
	b2, _ := s2.Marshal()
	sig2, _ := Sign(tr.key, b2)
	cps[2] = Checkpoint{Statement: b2, Signature: sig2}
	if _, err := VerifyCheckpoints(tr.instance, Genesis(tr.instance), 1, cps, tr.keys()); !errors.As(err, &f) || f.Segment != 2 {
		t.Fatalf("segment number: %v", err)
	}

	// An empty last segment must carry the chain hash it was closed at.
	tr = newTrail(t, 2, 0)
	s = tr.stmts[1]
	s.ChainHash = Genesis("x")
	b, _ = s.Marshal()
	sig, _ = Sign(tr.key, b)
	cps = []Checkpoint{tr.cps[0], {Statement: b, Signature: sig}}
	if err := tr.verifyAll(cps, tr.segments()); !errors.As(err, &f) || f.Segment != 2 {
		t.Fatalf("empty segment chain hash: %v", err)
	}
}

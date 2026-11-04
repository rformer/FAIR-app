package integrity

import (
	"crypto/sha256"
	"errors"
)

// EmptyRoot is the Merkle tree hash of an empty segment: SHA-256("").
var EmptyRoot = Hash(sha256.Sum256(nil))

// node is an RFC 9162 interior node: SHA-256(0x01 ‖ left ‖ right).
func node(l, r Hash) Hash {
	var in [1 + 32 + 32]byte
	in[0] = 0x01
	copy(in[1:33], l[:])
	copy(in[33:], r[:])
	return sha256.Sum256(in[:])
}

// Tree is the RFC 9162 Merkle tree over a segment's leaf hashes. It keeps
// every level, so inclusion paths cost O(log n) after one O(n) build. An
// unpaired last node is carried up unchanged, which gives the same root and
// paths as RFC 9162's split at the largest power of two below n.
type Tree struct {
	levels [][]Hash // levels[0] = leaves; the last level has one node
}

// NewTree builds the tree over leaves (copied).
func NewTree(leaves []Hash) *Tree {
	t := &Tree{levels: [][]Hash{append([]Hash(nil), leaves...)}}
	for cur := t.levels[0]; len(cur) > 1; {
		next := make([]Hash, 0, (len(cur)+1)/2)
		for i := 0; i+1 < len(cur); i += 2 {
			next = append(next, node(cur[i], cur[i+1]))
		}
		if len(cur)%2 == 1 {
			next = append(next, cur[len(cur)-1])
		}
		t.levels = append(t.levels, next)
		cur = next
	}
	return t
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.levels[0])) }

// Root is the Merkle tree hash (EmptyRoot for no leaves).
func (t *Tree) Root() Hash {
	if len(t.levels[0]) == 0 {
		return EmptyRoot
	}
	return t.levels[len(t.levels)-1][0]
}

// ErrIndex is returned for a leaf index outside the tree.
var ErrIndex = errors.New("integrity: leaf index out of range")

// Path is the RFC 9162 inclusion path of leaf m, from the leaf's sibling up.
func (t *Tree) Path(m uint64) ([]Hash, error) {
	if m >= t.Size() {
		return nil, ErrIndex
	}
	var path []Hash
	for _, level := range t.levels[:len(t.levels)-1] {
		if s := m ^ 1; s < uint64(len(level)) {
			path = append(path, level[s])
		}
		m >>= 1
	}
	return path, nil
}

// Root is the Merkle tree hash over leaves.
func Root(leaves []Hash) Hash { return NewTree(leaves).Root() }

// VerifyInclusion checks that leaf is at index in a tree of size leaves with
// the given root, by the RFC 9162 §2.1.3.2 algorithm.
func VerifyInclusion(leaf Hash, index, size uint64, path []Hash, root Hash) bool {
	if index >= size {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

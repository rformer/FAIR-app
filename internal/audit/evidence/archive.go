package evidence

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// SegmentFormat names the segment archive format (design §6.7):
//
//	segments/<instance>/<segment>.jsonl.gz
//
// gzip of JSON lines: a header {"format", "checkpoint"} with the segment's
// signed checkpoint, then one line per record in sequence order,
// {"seq", "leaf", "chain", "body"}, where body is the record's exact bytes
// (ADR-011) and leaf and chain are lowercase hex.
const SegmentFormat = "fair-audit-segment-v1"

// SegmentKey is where a segment's archive lives in object storage.
func SegmentKey(instance string, segment uint64) string {
	return fmt.Sprintf("segments/%s/%d.jsonl.gz", instance, segment)
}

var segmentName = regexp.MustCompile(`^([0-9]+)\.jsonl\.gz$`)

// SegmentFromName is the segment number in an archive's file name, if it
// has the SegmentKey form.
func SegmentFromName(name string) (uint64, bool) {
	m := segmentName.FindStringSubmatch(path.Base(name))
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	return n, err == nil
}

// Segment is an archived segment: its checkpoint and records.
type Segment struct {
	Checkpoint integrity.Checkpoint
	Records    []integrity.Record
}

type segmentHeader struct {
	Format     string               `json:"format"`
	Checkpoint integrity.Checkpoint `json:"checkpoint"`
}

type segmentLine struct {
	Seq   uint64          `json:"seq"`
	Leaf  integrity.Hash  `json:"leaf"`
	Chain integrity.Hash  `json:"chain"`
	Body  json.RawMessage `json:"body"`
}

// WriteSegment writes a segment archive.
func WriteSegment(w io.Writer, s Segment) error {
	zw := gzip.NewWriter(w)
	h, err := json.Marshal(segmentHeader{Format: SegmentFormat, Checkpoint: s.Checkpoint})
	if err != nil {
		return err
	}
	if _, err := zw.Write(append(h, '\n')); err != nil {
		return err
	}
	for _, r := range s.Records {
		if bytes.ContainsAny(r.Body, "\n\r") || !json.Valid(r.Body) {
			return fmt.Errorf("evidence: record %d: a body is one line of JSON", r.Seq)
		}
		// Written by hand so the body keeps its exact bytes.
		if _, err := fmt.Fprintf(zw, `{"seq":%d,"leaf":"%s","chain":"%s","body":%s}`+"\n", r.Seq, r.Leaf, r.Chain, r.Body); err != nil {
			return err
		}
	}
	return zw.Close()
}

// ReadSegment reads a segment archive.
func ReadSegment(r io.Reader) (Segment, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return Segment{}, invalid("archive: %v", err)
	}
	defer func() { _ = zr.Close() }()
	var s Segment
	err = lines(zr, func(n int, line []byte) error {
		if n == 1 {
			var h segmentHeader
			if err := strictJSON(line, &h); err != nil || h.Format != SegmentFormat {
				return invalid("archive: not a %s header", SegmentFormat)
			}
			s.Checkpoint = h.Checkpoint
			return nil
		}
		var l segmentLine
		if err := strictJSON(line, &l); err != nil {
			return invalid("archive line %d: %v", n, err)
		}
		// The body as it appears in the line: RawMessage keeps its bytes.
		s.Records = append(s.Records, integrity.Record{Seq: l.Seq, Body: []byte(l.Body), Leaf: l.Leaf, Chain: l.Chain})
		return nil
	})
	if err != nil {
		return Segment{}, err
	}
	if len(s.Checkpoint.Statement) == 0 {
		return Segment{}, invalid("archive: empty")
	}
	return s, nil
}

// NamedArchive is an archive to verify and the name it was found under.
type NamedArchive struct {
	Name string
	Open func() (io.ReadCloser, error)
}

// ArchiveResult summarizes verified archives.
type ArchiveResult struct {
	Segments []uint64
	Records  int
	Anchored bool
}

// VerifyArchives checks segment archives against a checkpoints file
// verified with keys: each archive's checkpoint is the chain's for its
// segment, its name (when it has the SegmentKey form) names that segment,
// and its records replay the chain from the previous checkpoint to the
// checkpoint's chain hash and Merkle root. Archives are checked in segment
// order; the first failure is returned.
func VerifyArchives(archives []NamedArchive, cps []integrity.Checkpoint, keys Keys) (ArchiveResult, error) {
	chain, err := VerifyChain(cps, keys)
	if err != nil {
		return ArchiveResult{}, err
	}
	type loaded struct {
		name string
		seg  Segment
		st   integrity.Statement
	}
	var all []loaded
	for _, a := range archives {
		rc, err := a.Open()
		if err != nil {
			return ArchiveResult{}, err
		}
		seg, err := ReadSegment(rc)
		_ = rc.Close()
		if err != nil {
			return ArchiveResult{}, fmt.Errorf("%s: %w", a.Name, err)
		}
		st, err := integrity.ParseStatement(seg.Checkpoint.Statement)
		if err != nil {
			return ArchiveResult{}, fmt.Errorf("%s: %w", a.Name, &integrity.Failure{Segment: st.Segment, Reason: err.Error()})
		}
		all = append(all, loaded{name: a.Name, seg: seg, st: st})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].st.Segment < all[j].st.Segment })
	res := ArchiveResult{Anchored: chain.Anchored}
	for _, l := range all {
		n := l.st.Segment
		if named, ok := SegmentFromName(l.name); ok && named != n {
			return res, &integrity.Failure{Segment: named, Reason: fmt.Sprintf("%s holds segment %d", l.name, n)}
		}
		want, ok := chain.Segment(n)
		if !ok {
			return res, fmt.Errorf("%w: segment %d (%s) is not in the checkpoints", ErrInsufficient, n, l.name)
		}
		if want.Instance != l.st.Instance || !bytes.Equal(cpStatement(cps, chain, n), l.seg.Checkpoint.Statement) {
			return res, &integrity.Failure{Segment: n, Reason: l.name + ": its checkpoint is not the one in the checkpoints"}
		}
		prev, ok := chain.PrevChain(n)
		if !ok {
			return res, fmt.Errorf("%w: segment %d needs the checkpoint of segment %d", ErrInsufficient, n, n-1)
		}
		if err := integrity.VerifySegment(want, prev, l.seg.Records); err != nil {
			return res, err
		}
		res.Segments = append(res.Segments, n)
		res.Records += len(l.seg.Records)
	}
	return res, nil
}

func cpStatement(cps []integrity.Checkpoint, c Chain, n uint64) []byte {
	return cps[c.bySegment[n]].Statement
}

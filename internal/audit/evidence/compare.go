package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// CheckpointSet is the checkpoints one copy holds, by segment.
type CheckpointSet map[uint64]integrity.Checkpoint

// Segments lists the segments, ascending.
func (s CheckpointSet) Segments() []uint64 {
	out := make([]uint64, 0, len(s))
	for n := range s {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s CheckpointSet) add(cp integrity.Checkpoint, where string) error {
	st, err := integrity.ParseStatement(cp.Statement)
	if err != nil {
		return invalid("%s: %v", where, err)
	}
	if old, ok := s[st.Segment]; ok {
		// A stream may deliver a copy twice; two different ones is a
		// divergence within the copy itself.
		if !bytes.Equal(old.Statement, cp.Statement) || !bytes.Equal(old.Signature, cp.Signature) {
			return &integrity.Failure{Segment: st.Segment, Reason: where + ": two different checkpoints for this segment"}
		}
		return nil
	}
	s[st.Segment] = cp
	return nil
}

// streamLine is a line of a checkpoints file or of a SIEM export: either a
// checkpoint, or an audit event (only audit.checkpoint events count).
type streamLine struct {
	Statement  []byte            `json:"statement"`
	Signature  []byte            `json:"signature"`
	Type       string            `json:"type"`
	Attributes map[string]string `json:"attributes"`
}

// ReadCheckpointStream reads checkpoints from a checkpoints file or a SIEM
// export of audit events (JSON lines; the events' statement and signature
// attributes, design §6.3). Lines of other events are skipped.
func ReadCheckpointStream(r io.Reader, name string) (CheckpointSet, error) {
	set := CheckpointSet{}
	err := lines(r, func(n int, line []byte) error {
		if len(bytes.TrimSpace(line)) == 0 {
			return nil
		}
		var l streamLine
		if err := json.Unmarshal(line, &l); err != nil {
			return invalid("%s line %d: %v", name, n, err)
		}
		where := fmt.Sprintf("%s line %d", name, n)
		switch {
		case len(l.Statement) > 0:
			return set.add(integrity.Checkpoint{Statement: l.Statement, Signature: l.Signature}, where)
		case l.Type == "audit.checkpoint":
			sig, err := base64.StdEncoding.DecodeString(l.Attributes["signature"])
			if err != nil || l.Attributes["statement"] == "" {
				return invalid("%s: an audit.checkpoint event without a statement and signature", where)
			}
			return set.add(integrity.Checkpoint{Statement: []byte(l.Attributes["statement"]), Signature: sig}, where)
		}
		return nil
	})
	return set, err
}

// ReadCheckpointDir reads write-once copies (<segment>.json files, each one
// JSON checkpoint) from a directory, as downloaded from
// checkpoints/<instance>/.
func ReadCheckpointDir(fsys fs.FS) (CheckpointSet, error) {
	set := CheckpointSet{}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		var cp integrity.Checkpoint
		if err := strictJSON(b, &cp); err != nil || len(cp.Statement) == 0 {
			return nil, invalid("%s: not a checkpoint copy", e.Name())
		}
		st, err := integrity.ParseStatement(cp.Statement)
		if err != nil {
			return nil, invalid("%s: %v", e.Name(), err)
		}
		if want := fmt.Sprintf("%d.json", st.Segment); e.Name() != want {
			return nil, &integrity.Failure{Segment: st.Segment, Reason: fmt.Sprintf("%s holds segment %d", e.Name(), st.Segment)}
		}
		if err := set.add(cp, e.Name()); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// Difference is where two copies of the checkpoints first differ.
type Difference struct {
	Segment uint64
	Reason  string
}

func (d *Difference) Error() string { return fmt.Sprintf("segment %d: %s", d.Segment, d.Reason) }

// Compare reports the first segment in from..to (to 0: no upper bound)
// where the platform's checkpoints and an external copy differ: missing in
// one or both, or a different statement or signature. nil means they agree
// over the range.
func Compare(platform, external CheckpointSet, from, to uint64) *Difference {
	all := map[uint64]bool{}
	for n := range platform {
		all[n] = true
	}
	for n := range external {
		all[n] = true
	}
	segs := make([]uint64, 0, len(all))
	for n := range all {
		if n >= from && (to == 0 || n <= to) {
			segs = append(segs, n)
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i] < segs[j] })
	if len(segs) == 0 {
		return &Difference{Segment: from, Reason: "neither copy has checkpoints in the range"}
	}
	expect := segs[0]
	if from > 0 {
		expect = from
	}
	for _, n := range segs {
		if n != expect {
			return &Difference{Segment: expect, Reason: "missing in both copies"}
		}
		expect = n + 1
		p, inP := platform[n]
		x, inX := external[n]
		switch {
		case !inX:
			return &Difference{Segment: n, Reason: "missing in the external copy"}
		case !inP:
			return &Difference{Segment: n, Reason: "missing in the platform's checkpoints"}
		case !bytes.Equal(p.Statement, x.Statement):
			return &Difference{Segment: n, Reason: "the statements differ: " + statementDiff(p.Statement, x.Statement)}
		case !bytes.Equal(p.Signature, x.Signature):
			return &Difference{Segment: n, Reason: "the signatures differ"}
		}
	}
	if to != 0 && expect <= to {
		return &Difference{Segment: expect, Reason: "missing in both copies"}
	}
	return nil
}

// statementDiff names the statement fields that differ.
func statementDiff(a, b []byte) string {
	var ma, mb map[string]any
	_ = json.Unmarshal(a, &ma)
	_ = json.Unmarshal(b, &mb)
	var fields []string
	for k, v := range ma {
		if fmt.Sprint(v) != fmt.Sprint(mb[k]) {
			fields = append(fields, k)
		}
	}
	for k := range mb {
		if _, ok := ma[k]; !ok {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	if len(fields) == 0 {
		return "byte form"
	}
	return strings.Join(fields, ", ")
}

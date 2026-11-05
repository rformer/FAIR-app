package evidence

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rformer/fair-app/internal/audit/evidence/evidencetest"
	"github.com/rformer/fair-app/internal/audit/integrity"
)

// trail wraps a synthetic trail with the evidence writers.
type trail struct{ *evidencetest.Trail }

func newTrail(t *testing.T, sizes []int, rotateAt int) *trail {
	return &trail{evidencetest.New(t, sizes, rotateAt)}
}

func (tr *trail) keyset() Keys { return Keys(tr.PublicKeys()) }

func (tr *trail) segment(_ *testing.T, n uint64) Segment {
	return Segment{Checkpoint: tr.Checkpoints[n-1], Records: tr.SegmentRecords(n)}
}

func archiveBytes(t *testing.T, s Segment) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSegment(&buf, s); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func named(name string, b []byte) NamedArchive {
	return NamedArchive{Name: name, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }}
}

// export builds an export of the records with the given sequence numbers,
// signed with the second key.
func (tr *trail) export(t *testing.T, seqs []uint64, mut func(in *ExportInput)) []byte {
	t.Helper()
	in := ExportInput{Manifest: Manifest{Instance: tr.Instance, ExportID: "exp-1", CreatedAt: time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC),
		RequestedBy: "auditor-1", Reason: "annual review", Filter: Filter{Description: "actor x, all of 2026", Data: json.RawMessage(`{"actor":"x"}`)},
		BUScope: []string{"bu-root"}}, Checkpoints: tr.Checkpoints, Keys: tr.keyset()}
	for _, seq := range seqs {
		seg, path := tr.Proof(t, seq)
		in.Bodies = append(in.Bodies, tr.Records[seq-1].Body)
		in.Proofs = append(in.Proofs, Proof{Seq: seq, Segment: seg, Path: path})
	}
	if mut != nil {
		mut(&in)
	}
	var buf bytes.Buffer
	if err := WriteExport(&buf, in, tr.Keys[1]); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rezip rewrites a bundle's files (and, with resign, its manifest digests
// and signature, as someone holding the key could).
func rezip(t *testing.T, bundle []byte, edit func(files map[string][]byte)) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	var order []string
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		files[f.Name] = b
		order = append(order, f.Name)
	}
	edit(files)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	seen := map[string]bool{}
	for _, n := range order {
		if b, ok := files[n]; ok {
			w, _ := zw.Create(n)
			_, _ = w.Write(b)
			seen[n] = true
		}
	}
	for n, b := range files {
		if !seen[n] {
			w, _ := zw.Create(n)
			_, _ = w.Write(b)
		}
	}
	_ = zw.Close()
	return buf.Bytes()
}

func editLines(b []byte, fn func(ls [][]byte) [][]byte) []byte {
	ls := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	ls = fn(ls)
	return append(bytes.Join(ls, []byte("\n")), '\n')
}

func failureAt(t *testing.T, err error, seq, segment uint64) {
	t.Helper()
	var f *integrity.Failure
	if !errors.As(err, &f) {
		t.Fatalf("want a failure at record %d / segment %d, got %v", seq, segment, err)
	}
	if f.Seq != seq || f.Segment != segment {
		t.Fatalf("failure at record %d / segment %d (%s), want record %d / segment %d", f.Seq, f.Segment, f.Reason, seq, segment)
	}
}

func TestArchivesVerify(t *testing.T) {
	tr := newTrail(t, []int{5, 0, 7, 1, 4}, 4)
	var archives []NamedArchive
	for n := uint64(1); n <= 5; n++ {
		archives = append(archives, named(SegmentKey(tr.Instance, n), archiveBytes(t, tr.segment(t, n))))
	}
	res, err := VerifyArchives(archives, tr.Checkpoints, tr.keyset())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 17 || len(res.Segments) != 5 || !res.Anchored {
		t.Fatalf("%+v", res)
	}
	// A later run of checkpoints still verifies a segment it reaches.
	res, err = VerifyArchives(archives[3:4], tr.Checkpoints[2:], tr.keyset())
	if err != nil || res.Anchored {
		t.Fatalf("%+v %v", res, err)
	}
	// One that cannot decide says so.
	if _, err := VerifyArchives(archives[2:3], tr.Checkpoints[2:], tr.keyset()); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("no previous checkpoint: %v", err)
	}
	if _, err := VerifyArchives(archives[0:1], tr.Checkpoints[2:], tr.keyset()); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("segment outside the checkpoints: %v", err)
	}
	// Bodies keep their exact bytes through the archive.
	seg, err := ReadSegment(bytes.NewReader(archiveBytes(t, tr.segment(t, 1))))
	if err != nil || !bytes.Equal(seg.Records[2].Body, tr.Records[2].Body) {
		t.Fatalf("body changed: %v", err)
	}
}

// The tamper corpus for archives (T-10): each change is found and reported
// at the first failing position.
func TestArchiveTamperCorpus(t *testing.T) {
	tr := newTrail(t, []int{5, 0, 7, 3}, 0)
	keys := tr.keyset()
	seg3 := tr.segment(t, 3) // records 6..12
	cases := []struct {
		name          string
		archive       func() NamedArchive
		cps           []integrity.Checkpoint
		seq, segment  uint64
		wantNotFailed bool
	}{
		{name: "altered body", seq: 8, archive: func() NamedArchive {
			s := tr.segment(t, 3)
			s.Records[2].Body = bytes.Replace(bytes.Clone(s.Records[2].Body), []byte(`"actor":"x"`), []byte(`"actor":"y"`), 1)
			return named("3.jsonl.gz", archiveBytes(t, s))
		}},
		// Without the original hashes, the segment is the first provable failure.
		{name: "altered body with recomputed hashes", archive: func() NamedArchive {
			s := tr.segment(t, 3)
			recs := append([]integrity.Record(nil), s.Records...)
			recs[2].Body = bytes.Replace(bytes.Clone(recs[2].Body), []byte(`"actor":"x"`), []byte(`"actor":"y"`), 1)
			recs[2].Leaf = integrity.Leaf(recs[2].Body)
			prev := recs[1].Chain
			for i := 2; i < len(recs); i++ {
				recs[i].Leaf = integrity.Leaf(recs[i].Body)
				recs[i].Chain = integrity.Chain(prev, recs[i].Seq, recs[i].Leaf)
				prev = recs[i].Chain
			}
			s.Records = recs
			return named("3.jsonl.gz", archiveBytes(t, s))
		}, segment: 3},
		{name: "removed record", seq: 9, archive: func() NamedArchive {
			s := tr.segment(t, 3)
			s.Records = append(append([]integrity.Record(nil), s.Records[:3]...), s.Records[4:]...)
			return named("3.jsonl.gz", archiveBytes(t, s))
		}},
		{name: "reordered records", seq: 7, archive: func() NamedArchive {
			s := tr.segment(t, 3)
			recs := append([]integrity.Record(nil), s.Records...)
			recs[1], recs[2] = recs[2], recs[1]
			s.Records = recs
			return named("3.jsonl.gz", archiveBytes(t, s))
		}},
		{name: "truncated tail", segment: 3, archive: func() NamedArchive {
			s := tr.segment(t, 3)
			s.Records = s.Records[:5]
			return named("3.jsonl.gz", archiveBytes(t, s))
		}},
		{name: "swapped archive object", segment: 3, archive: func() NamedArchive {
			return named(SegmentKey(tr.Instance, 3), archiveBytes(t, tr.segment(t, 4)))
		}},
		{name: "forged checkpoint in the archive", segment: 3, archive: func() NamedArchive {
			s := tr.segment(t, 3)
			st := tr.Statements[2]
			st.IssuedAt = st.IssuedAt.Add(time.Second)
			b, _ := st.Marshal()
			s.Checkpoint = integrity.Checkpoint{Statement: b, Signature: tr.Checkpoints[2].Signature}
			return named("3.jsonl.gz", archiveBytes(t, s))
		}},
		{name: "forged checkpoint in the checkpoints", segment: 3, archive: func() NamedArchive {
			return named("3.jsonl.gz", archiveBytes(t, seg3))
		}, cps: func() []integrity.Checkpoint {
			cps := append([]integrity.Checkpoint(nil), tr.Checkpoints...)
			st := tr.Statements[2]
			st.MerkleRoot[0] ^= 1
			b, _ := st.Marshal()
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			sig, _ := integrity.Sign(other, b)
			cps[2] = integrity.Checkpoint{Statement: b, Signature: sig}
			return cps
		}()},
		{name: "removed checkpoint", segment: 3, archive: func() NamedArchive {
			return named("3.jsonl.gz", archiveBytes(t, seg3))
		}, cps: append(append([]integrity.Checkpoint(nil), tr.Checkpoints[:2]...), tr.Checkpoints[3:]...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cps := c.cps
			if cps == nil {
				cps = tr.Checkpoints
			}
			_, err := VerifyArchives([]NamedArchive{c.archive()}, cps, keys)
			failureAt(t, err, c.seq, c.segment)
		})
	}
	// An unaltered archive verifies, as a control.
	if _, err := VerifyArchives([]NamedArchive{named("3.jsonl.gz", archiveBytes(t, seg3))}, tr.Checkpoints, keys); err != nil {
		t.Fatal(err)
	}
	// Garbage is malformed, not a crash.
	for name, b := range map[string][]byte{"not gzip": []byte("plain"), "empty gzip": func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_ = zw.Close()
		return buf.Bytes()
	}()} {
		if _, err := VerifyArchives([]NamedArchive{named("3.jsonl.gz", b)}, tr.Checkpoints, keys); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExportVerifies(t *testing.T) {
	tr := newTrail(t, []int{5, 0, 7, 3}, 3)
	bundle := tr.export(t, []uint64{1, 4, 6, 9, 12, 15}, nil)
	pinned, err := VerifyExport(bytes.NewReader(bundle), int64(len(bundle)), tr.keyset())
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Records != 6 || pinned.Segments != 4 || !pinned.Pinned || !pinned.Anchored || len(pinned.KeyIDs) != 2 ||
		pinned.Manifest.Filter.Description != "actor x, all of 2026" || pinned.Manifest.RecordCount != 6 {
		t.Fatalf("%+v", pinned)
	}
	unpinned, err := VerifyExport(bytes.NewReader(bundle), int64(len(bundle)), nil)
	if err != nil || unpinned.Pinned {
		t.Fatalf("%+v %v", unpinned, err)
	}
	// Pinned to other keys: refused, whatever the bundle's keys.pem says.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oid, _ := integrity.KeyID(&other.PublicKey)
	if _, err := VerifyExport(bytes.NewReader(bundle), int64(len(bundle)), Keys{oid: &other.PublicKey}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other keys: %v", err)
	}
	// Pinned to the manifest key only: the checkpoints by the older key fail.
	mid, _ := integrity.KeyID(&tr.Keys[1].PublicKey)
	if _, err := VerifyExport(bytes.NewReader(bundle), int64(len(bundle)), Keys{mid: &tr.Keys[1].PublicKey}); err == nil {
		t.Fatal("verified with a key missing")
	}
	// CSV form: the bodies are verified, the CSV only by digest.
	csv := tr.export(t, []uint64{2, 3}, func(in *ExportInput) {
		in.Manifest.RecordFormat = "csv"
		in.CSV = []byte("seq,type\n2,db.migrated\n3,db.migrated\n")
	})
	if res, err := VerifyExport(bytes.NewReader(csv), int64(len(csv)), tr.keyset()); err != nil || res.Records != 2 {
		t.Fatalf("csv: %+v %v", res, err)
	}
	// An empty export verifies too.
	empty := tr.export(t, nil, nil)
	if res, err := VerifyExport(bytes.NewReader(empty), int64(len(empty)), tr.keyset()); err != nil || res.Records != 0 {
		t.Fatalf("empty: %+v %v", res, err)
	}
}

// The tamper corpus for exports (T-10).
func TestExportTamperCorpus(t *testing.T) {
	tr := newTrail(t, []int{5, 0, 7, 3}, 0)
	seqs := []uint64{1, 4, 6, 9, 12, 15}
	bundle := tr.export(t, seqs, nil)
	keys := tr.keyset()
	type want struct {
		seq, segment uint64
		invalid      string // a failure without a position: wraps ErrInvalid and contains this
	}
	cases := []struct {
		name string
		zip  []byte
		want want
	}{
		{"altered body", rezip(t, bundle, func(f map[string][]byte) {
			f[FileRecords] = editLines(f[FileRecords], func(ls [][]byte) [][]byte {
				ls[2] = bytes.Replace(ls[2], []byte(`"actor":"x"`), []byte(`"actor":"y"`), 1)
				return ls
			})
		}), want{seq: 6}},
		{"altered body, manifest re-signed", tr.export(t, seqs, func(in *ExportInput) {
			in.Bodies[3] = bytes.Replace(bytes.Clone(in.Bodies[3]), []byte(`"actor":"x"`), []byte(`"actor":"y"`), 1)
		}), want{seq: 9}},
		{"removed record", rezip(t, bundle, func(f map[string][]byte) {
			f[FileRecords] = editLines(f[FileRecords], func(ls [][]byte) [][]byte { return append(ls[:1], ls[2:]...) })
		}), want{seq: 4}},
		{"removed record and its proof", rezip(t, bundle, func(f map[string][]byte) {
			drop := func(ls [][]byte) [][]byte { return append(ls[:1], ls[2:]...) }
			f[FileRecords] = editLines(f[FileRecords], drop)
			f[FileProofs] = editLines(f[FileProofs], drop)
		}), want{invalid: "5 records and 5 proofs, the manifest says 6"}},
		{"reordered records", rezip(t, bundle, func(f map[string][]byte) {
			f[FileRecords] = editLines(f[FileRecords], func(ls [][]byte) [][]byte { ls[1], ls[2] = ls[2], ls[1]; return ls })
		}), want{seq: 4}},
		{"reordered records and proofs", rezip(t, bundle, func(f map[string][]byte) {
			swap := func(ls [][]byte) [][]byte { ls[1], ls[2] = ls[2], ls[1]; return ls }
			f[FileRecords] = editLines(f[FileRecords], swap)
			f[FileProofs] = editLines(f[FileProofs], swap)
		}), want{seq: 4}},
		{"truncated tail", rezip(t, bundle, func(f map[string][]byte) {
			drop := func(ls [][]byte) [][]byte { return ls[:4] }
			f[FileRecords] = editLines(f[FileRecords], drop)
			f[FileProofs] = editLines(f[FileProofs], drop)
		}), want{invalid: "4 records and 4 proofs, the manifest says 6"}},
		{"forged checkpoint", rezip(t, bundle, func(f map[string][]byte) {
			f[FileCheckpoints] = editLines(f[FileCheckpoints], func(ls [][]byte) [][]byte {
				var cp integrity.Checkpoint
				_ = json.Unmarshal(ls[2], &cp)
				st, _ := integrity.ParseStatement(cp.Statement)
				st.MerkleRoot[0] ^= 1
				cp.Statement, _ = st.Marshal()
				ls[2], _ = json.Marshal(cp)
				return ls
			})
		}), want{segment: 3}},
		{"removed checkpoint", rezip(t, bundle, func(f map[string][]byte) {
			f[FileCheckpoints] = editLines(f[FileCheckpoints], func(ls [][]byte) [][]byte { return append(ls[:1], ls[2:]...) })
		}), want{segment: 2}},
		{"proof moved to another segment", rezip(t, bundle, func(f map[string][]byte) {
			f[FileProofs] = editLines(f[FileProofs], func(ls [][]byte) [][]byte {
				ls[2] = bytes.Replace(ls[2], []byte(`"segment":3`), []byte(`"segment":1`), 1)
				return ls
			})
		}), want{seq: 6}},
		{"manifest changed", rezip(t, bundle, func(f map[string][]byte) {
			f[FileManifest] = bytes.Replace(f[FileManifest], []byte("actor x, all of 2026"), []byte("actor x, January"), 1)
		}), want{invalid: "signature does not verify"}},
		{"signature removed", rezip(t, bundle, func(f map[string][]byte) { delete(f, FileSignature) }), want{invalid: "manifest.sig is missing"}},
		{"file added", rezip(t, bundle, func(f map[string][]byte) { f["extra.txt"] = []byte("x") }), want{invalid: "extra.txt is not in the manifest"}},
		{"CSV view changed", rezip(t, tr.export(t, seqs, func(in *ExportInput) {
			in.Manifest.RecordFormat, in.CSV = "csv", []byte("a,b\n")
		}), func(f map[string][]byte) { f[FileRecordsCSV] = []byte("a,c\n") }), want{invalid: "records.csv does not match its digest"}},
		{"keys replaced (unpinned run below)", rezip(t, bundle, func(f map[string][]byte) {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			oid, _ := integrity.KeyID(&other.PublicKey)
			f[FileKeys], _ = EncodeKeys(Keys{oid: &other.PublicKey})
		}), want{invalid: "keys.pem does not match its digest"}},
		{"not a zip", []byte("PK nothing"), want{invalid: "bundle"}},
		{"another instance's manifest", tr.export(t, seqs, func(in *ExportInput) { in.Manifest.Instance = "elsewhere" }), want{invalid: "belong to instance"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := VerifyExport(bytes.NewReader(c.zip), int64(len(c.zip)), keys)
			if c.want.invalid != "" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want.invalid) {
					t.Fatalf("got %v, want %q", err, c.want.invalid)
				}
				return
			}
			failureAt(t, err, c.want.seq, c.want.segment)
		})
	}
	// Unpinned, a replaced keys.pem is caught by its digest or the
	// manifest signature.
	c := cases[len(cases)-2].zip
	if _, err := VerifyExport(bytes.NewReader(c), int64(len(c)), nil); err == nil {
		t.Fatal("replaced keys accepted")
	}
	// A duplicate entry (two files of one name) is refused.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 2; i++ {
		w, _ := zw.Create(FileManifest)
		_, _ = w.Write([]byte("{}"))
	}
	_ = zw.Close()
	if _, err := VerifyExport(bytes.NewReader(buf.Bytes()), int64(buf.Len()), keys); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestCompare(t *testing.T) {
	tr := newTrail(t, []int{2, 0, 3, 1}, 0)
	platform := CheckpointSet{}
	for _, cp := range tr.Checkpoints {
		if err := platform.add(cp, "p"); err != nil {
			t.Fatal(err)
		}
	}
	// A SIEM export: audit events, the checkpoint events among them (one
	// delivered twice), in any order.
	var siem bytes.Buffer
	for i := len(tr.Checkpoints) - 1; i >= 0; i-- {
		cp := tr.Checkpoints[i]
		fmt.Fprintf(&siem, `{"type":"service.started","attributes":{"env":"production"}}`+"\n")
		ev, _ := json.Marshal(map[string]any{"type": "audit.checkpoint", "attributes": map[string]string{"statement": string(cp.Statement),
			"signature": base64.StdEncoding.EncodeToString(cp.Signature), "segment": fmt.Sprint(i + 1)}})
		siem.Write(append(ev, '\n'))
		if i == 1 {
			siem.Write(append(ev, '\n'))
		}
	}
	ext, err := ReadCheckpointStream(bytes.NewReader(siem.Bytes()), "siem.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if d := Compare(platform, ext, 0, 0); d != nil {
		t.Fatalf("identical copies differ: %v", d)
	}
	// Write-once copies, as a directory.
	dir := fstest.MapFS{}
	for i, cp := range tr.Checkpoints {
		b, _ := json.Marshal(cp)
		dir[fmt.Sprintf("%d.json", i+1)] = &fstest.MapFile{Data: b}
	}
	worm, err := ReadCheckpointDir(dir)
	if err != nil || Compare(platform, worm, 0, 0) != nil {
		t.Fatalf("worm: %v", err)
	}
	// A checkpoints file reads the same.
	var file bytes.Buffer
	_ = WriteCheckpoints(&file, tr.Checkpoints)
	if f, err := ReadCheckpointStream(&file, "checkpoints.jsonl"); err != nil || Compare(platform, f, 0, 0) != nil {
		t.Fatalf("file: %v", err)
	}

	// Divergences, reported at the first segment.
	rewritten := CheckpointSet{}
	for n, cp := range platform {
		rewritten[n] = cp
	}
	st := tr.Statements[2]
	st.ChainHash[0] ^= 1
	b, _ := st.Marshal()
	sig, _ := integrity.Sign(tr.Keys[0], b)
	rewritten[3] = integrity.Checkpoint{Statement: b, Signature: sig}
	if d := Compare(rewritten, ext, 0, 0); d == nil || d.Segment != 3 || !strings.Contains(d.Reason, "chain_hash") {
		t.Fatalf("rewritten: %v", d)
	}
	resigned := CheckpointSet{}
	for n, cp := range platform {
		resigned[n] = cp
	}
	sig2, _ := integrity.Sign(tr.Keys[0], tr.Checkpoints[1].Statement)
	resigned[2] = integrity.Checkpoint{Statement: tr.Checkpoints[1].Statement, Signature: sig2}
	if d := Compare(resigned, ext, 0, 0); d == nil || d.Segment != 2 || d.Reason != "the signatures differ" {
		t.Fatalf("re-signed: %v", d)
	}
	truncated := CheckpointSet{1: platform[1], 2: platform[2]}
	if d := Compare(truncated, ext, 0, 0); d == nil || d.Segment != 3 || d.Reason != "missing in the platform's checkpoints" {
		t.Fatalf("truncated: %v", d)
	}
	if d := Compare(platform, CheckpointSet{1: platform[1], 2: platform[2], 4: platform[4]}, 0, 0); d == nil || d.Segment != 3 || d.Reason != "missing in the external copy" {
		t.Fatalf("missing externally: %v", d)
	}
	gap := CheckpointSet{1: platform[1], 3: platform[3]}
	if d := Compare(gap, gap, 0, 0); d == nil || d.Segment != 2 || d.Reason != "missing in both copies" {
		t.Fatalf("gap: %v", d)
	}
	// A range: an external copy that starts later agrees from where it starts.
	late := CheckpointSet{3: platform[3], 4: platform[4]}
	if d := Compare(platform, late, 3, 0); d != nil {
		t.Fatalf("range: %v", d)
	}
	if d := Compare(platform, late, 0, 0); d == nil || d.Segment != 1 {
		t.Fatalf("no range: %v", d)
	}
	if d := Compare(platform, platform, 1, 9); d == nil || d.Segment != 5 {
		t.Fatalf("beyond the end: %v", d)
	}
	// Two different copies of one segment in one stream.
	var dup bytes.Buffer
	_ = WriteCheckpoints(&dup, []integrity.Checkpoint{tr.Checkpoints[0], {Statement: tr.Checkpoints[0].Statement, Signature: sig2}})
	if _, err := ReadCheckpointStream(&dup, "x"); err == nil {
		t.Fatal("conflicting duplicates accepted")
	}
	// A copy filed under another segment's name.
	b1, _ := json.Marshal(tr.Checkpoints[0])
	if _, err := ReadCheckpointDir(fstest.MapFS{"2.json": &fstest.MapFile{Data: b1}}); err == nil {
		t.Fatal("misfiled copy accepted")
	}
}

func TestKeys(t *testing.T) {
	tr := newTrail(t, []int{1}, 0)
	b, err := EncodeKeys(tr.keyset())
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKeys(b)
	if err != nil || len(k) != 2 {
		t.Fatalf("%v %v", k, err)
	}
	for name, in := range map[string]string{
		"empty":       "",
		"not PEM":     "hello",
		"private key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"garbage key": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		// A valid key under another label is still refused.
		"another label": strings.ReplaceAll(string(b), "PUBLIC KEY", "CERTIFICATE"),
	} {
		if _, err := ParseKeys([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Segment 1 must link to the instance's genesis and start at record 1, even
// when its signature is good (a signer's mistake, or a chain started over).
func TestChainAnchorsSegmentOne(t *testing.T) {
	tr := newTrail(t, []int{2, 1}, 0)
	for name, mut := range map[string]func(st *integrity.Statement){
		"not linked to the genesis": func(st *integrity.Statement) { st.PrevCheckpointHash[0] ^= 1 },
		"not starting at record 1":  func(st *integrity.Statement) { st.SeqFrom, st.SeqTo = 2, 3 },
	} {
		st := tr.Statements[0]
		mut(&st)
		b, _ := st.Marshal()
		sig, _ := integrity.Sign(tr.Keys[0], b)
		if _, err := VerifyChain([]integrity.Checkpoint{{Statement: b, Signature: sig}}, tr.keyset()); err == nil {
			t.Errorf("segment 1 %s was accepted", name)
		}
	}
}

// Evidence lines are read strictly: an unknown field means another format.
func TestStrictLines(t *testing.T) {
	tr := newTrail(t, []int{1}, 0)
	line, _ := json.Marshal(map[string]any{"statement": tr.Checkpoints[0].Statement, "signature": tr.Checkpoints[0].Signature, "segment": 1})
	if _, err := ReadCheckpoints(bytes.NewReader(line)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	h, _ := json.Marshal(map[string]any{"format": SegmentFormat, "checkpoint": tr.Checkpoints[0], "note": "x"})
	_, _ = zw.Write(append(h, '\n'))
	_ = zw.Close()
	if _, err := ReadSegment(&buf); !errors.Is(err, ErrInvalid) {
		t.Fatalf("archive header with an unknown field: %v", err)
	}
}

package evidence

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

// F-002 T-15: the streaming writer the audit service uses writes what
// WriteExport writes, and its bundles verify.
func TestExportWriter(t *testing.T) {
	tr := newTrail(t, []int{5, 0, 7, 3}, 3)
	seqs := []uint64{1, 4, 6, 9, 12, 13, 15}
	m := Manifest{Instance: tr.Instance, ExportID: "exp-1", CreatedAt: time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC),
		RequestedBy: "auditor-1", Reason: "annual review", Filter: Filter{Description: "actor x, all of 2026", Data: json.RawMessage(`{"actor":"x"}`)},
		BUScope: []string{"bu-root"}}

	write := func(t *testing.T, format string, rows func(seq uint64) []string) []byte {
		t.Helper()
		dir := t.TempDir()
		mm := m
		mm.RecordFormat = format
		var header []string
		if format == "csv" {
			header = []string{"seq", "type"}
		}
		var buf bytes.Buffer
		x, err := NewExportWriter(&buf, mm, tr.Keys[1], dir, header)
		if err != nil {
			t.Fatal(err)
		}
		defer x.Close()
		for _, seq := range seqs {
			seg, path := tr.Proof(t, seq)
			var row []string
			if rows != nil {
				row = rows(seq)
			}
			if err := x.AddRecord(tr.Records[seq-1].Body, Proof{Seq: seq, Segment: seg, Path: path}, row); err != nil {
				t.Fatal(err)
			}
		}
		// Out of order, or twice, is refused.
		if err := x.AddRecord(tr.Records[0].Body, Proof{Seq: 1}, nil); err == nil {
			t.Fatal("a record out of order was added")
		}
		last := seqs[len(seqs)-1]
		if err := x.AddRecord(tr.Records[last-1].Body, Proof{Seq: last}, nil); err == nil {
			t.Fatal("a record was added twice")
		}
		got, err := x.Finish(tr.Checkpoints, tr.keyset())
		if err != nil {
			t.Fatal(err)
		}
		if got.RecordCount != uint64(len(seqs)) || got.Format != ExportFormat || got.KeyID == "" {
			t.Fatalf("manifest %+v", got)
		}
		if x.Records() != uint64(len(seqs)) {
			t.Fatalf("%d records", x.Records())
		}
		x.Close()
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Fatalf("temporary files left: %v", left)
		}
		return buf.Bytes()
	}

	// JSON lines: verifies, and every file is the one WriteExport writes.
	streamed := write(t, "jsonl", nil)
	res, err := VerifyExport(bytes.NewReader(streamed), int64(len(streamed)), tr.keyset())
	if err != nil || res.Records != len(seqs) || !res.Pinned {
		t.Fatalf("streamed: %+v %v", res, err)
	}
	whole := tr.export(t, seqs, nil)
	if a, b := zipFiles(t, streamed), zipFiles(t, whole); len(a) != len(b) {
		t.Fatalf("files %d and %d", len(a), len(b))
	} else {
		for name, content := range b {
			if name != FileSignature && !bytes.Equal(a[name], content) { // ECDSA signatures are randomized
				t.Errorf("%s differs from WriteExport's", name)
			}
		}
	}

	// CSV: the view plus the bodies; the bodies verify.
	types := map[uint64]string{}
	csvBundle := write(t, "csv", func(seq uint64) []string {
		types[seq] = "t," + strconv.FormatUint(seq, 10) // a comma, quoted by the writer
		return []string{strconv.FormatUint(seq, 10), types[seq]}
	})
	res, err = VerifyExport(bytes.NewReader(csvBundle), int64(len(csvBundle)), tr.keyset())
	if err != nil || res.Records != len(seqs) || res.Manifest.RecordFormat != "csv" {
		t.Fatalf("csv: %+v %v", res, err)
	}
	files := zipFiles(t, csvBundle)
	rows, err := csv.NewReader(bytes.NewReader(files[FileRecordsCSV])).ReadAll()
	if err != nil || len(rows) != len(seqs)+1 || rows[0][0] != "seq" || rows[2][1] != types[seqs[1]] {
		t.Fatalf("csv view %q %v", rows, err)
	}
	if _, ok := files[FileRecords]; ok {
		t.Fatal("a CSV export with records.jsonl")
	}

	// Unknown formats and a CSV without a header are refused.
	bad := m
	bad.RecordFormat = "xml"
	if _, err := NewExportWriter(io.Discard, bad, tr.Keys[1], t.TempDir(), nil); err == nil {
		t.Fatal("an xml export")
	}
	bad.RecordFormat = "csv"
	if _, err := NewExportWriter(io.Discard, bad, tr.Keys[1], t.TempDir(), nil); err == nil {
		t.Fatal("a CSV export without a header")
	}
}

func zipFiles(t *testing.T, bundle []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		out[f.Name] = b
	}
	return out
}

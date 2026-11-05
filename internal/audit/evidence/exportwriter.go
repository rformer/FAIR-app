package evidence

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// ExportWriter writes an export bundle (ExportFormat) one record at a time,
// for exports too large to hold in memory (F-002 T-15: the audit service's
// exports, design §6.6). The records file goes straight into the ZIP; the
// proofs, and with CSV the bodies, are spooled to temporary files and added
// by Finish, followed by the checkpoints, the keys, the manifest and its
// signature. What it writes is what WriteExport writes for the same input.
//
// Call Close when done, also after Finish or an error: it removes the
// temporary files.
type ExportWriter struct {
	zw      *zip.Writer
	m       Manifest
	key     *ecdsa.PrivateKey
	records io.Writer // the open records entry, through recHash
	recHash hash.Hash
	csv     *csv.Writer
	bodies  *spool // with CSV
	proofs  *spool
	n       uint64
	last    uint64
	done    bool
}

// NewExportWriter starts a bundle for m (its Format, Files, RecordCount and
// KeyID are filled in by Finish) signed with key. tempDir holds the
// spooled files ("" for the system's). With RecordFormat "csv", csvHeader
// is the CSV view's header row and AddRecord takes a row per record.
func NewExportWriter(w io.Writer, m Manifest, key *ecdsa.PrivateKey, tempDir string, csvHeader []string) (*ExportWriter, error) {
	if m.RecordFormat == "" {
		m.RecordFormat = "jsonl"
	}
	x := &ExportWriter{zw: zip.NewWriter(w), m: m, key: key, recHash: sha256.New()}
	name := FileRecords
	switch m.RecordFormat {
	case "jsonl":
	case "csv":
		name = FileRecordsCSV
		if len(csvHeader) == 0 {
			return nil, errors.New("evidence: a CSV export needs a header")
		}
	default:
		return nil, fmt.Errorf("evidence: record format %q", m.RecordFormat)
	}
	var err error
	if x.proofs, err = newSpool(tempDir); err != nil {
		return nil, err
	}
	if m.RecordFormat == "csv" {
		if x.bodies, err = newSpool(tempDir); err != nil {
			x.Close()
			return nil, err
		}
	}
	f, err := x.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: m.CreatedAt})
	if err != nil {
		x.Close()
		return nil, err
	}
	x.records = io.MultiWriter(f, x.recHash)
	if m.RecordFormat == "csv" {
		x.csv = csv.NewWriter(x.records)
		if err := x.csv.Write(csvHeader); err != nil {
			x.Close()
			return nil, err
		}
	}
	return x, nil
}

// AddRecord adds one record: its exact body, its proof and, with CSV, its
// row in the CSV view. Records come in strictly increasing sequence order.
func (x *ExportWriter) AddRecord(body []byte, p Proof, csvRow []string) error {
	if x.done {
		return errors.New("evidence: the export is finished")
	}
	if bytes.ContainsAny(body, "\n\r") {
		return fmt.Errorf("evidence: a body is one line")
	}
	if x.n > 0 && p.Seq <= x.last {
		return fmt.Errorf("evidence: record %d after %d", p.Seq, x.last)
	}
	x.n, x.last = x.n+1, p.Seq
	if p.Path == nil {
		p.Path = []integrity.Hash{}
	}
	pj, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := x.proofs.line(pj); err != nil {
		return err
	}
	if x.csv == nil {
		if _, err := x.records.Write(body); err != nil {
			return err
		}
		_, err := x.records.Write([]byte{'\n'})
		return err
	}
	if err := x.bodies.line(body); err != nil {
		return err
	}
	return x.csv.Write(csvRow)
}

// Records is how many records have been added.
func (x *ExportWriter) Records() uint64 { return x.n }

// Finish adds the checkpoints covering the records, the keys, the spooled
// files and the signed manifest, and closes the ZIP. It returns the
// manifest as written.
func (x *ExportWriter) Finish(checkpoints []integrity.Checkpoint, keys Keys) (Manifest, error) {
	if x.done {
		return Manifest{}, errors.New("evidence: the export is finished")
	}
	x.done = true
	m := x.m
	m.Format, m.RecordCount = ExportFormat, x.n
	id, err := integrity.KeyID(&x.key.PublicKey)
	if err != nil {
		return Manifest{}, err
	}
	m.KeyID = id
	if m.BUScope == nil {
		m.BUScope = []string{}
	}
	if len(m.Filter.Data) == 0 {
		m.Filter.Data = json.RawMessage("{}")
	}
	m.Files = map[string]integrity.Hash{}
	if x.csv != nil {
		x.csv.Flush()
		if err := x.csv.Error(); err != nil {
			return Manifest{}, err
		}
		m.Files[FileRecordsCSV] = sum(x.recHash)
		if m.Files[FileBodies], err = x.copySpool(FileBodies, x.bodies); err != nil {
			return Manifest{}, err
		}
	} else {
		m.Files[FileRecords] = sum(x.recHash)
	}
	if m.Files[FileProofs], err = x.copySpool(FileProofs, x.proofs); err != nil {
		return Manifest{}, err
	}
	var cps bytes.Buffer
	if err := WriteCheckpoints(&cps, checkpoints); err != nil {
		return Manifest{}, err
	}
	pemKeys, err := EncodeKeys(keys)
	if err != nil {
		return Manifest{}, err
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{FileCheckpoints, cps.Bytes()}, {FileKeys, pemKeys}} {
		m.Files[f.name] = sha256.Sum256(f.b)
		if err := x.add(f.name, f.b); err != nil {
			return Manifest{}, err
		}
	}
	manifest, err := integrity.Body(m)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := integrity.Sign(x.key, manifest)
	if err != nil {
		return Manifest{}, err
	}
	if err := x.add(FileManifest, manifest); err != nil {
		return Manifest{}, err
	}
	if err := x.add(FileSignature, sig); err != nil {
		return Manifest{}, err
	}
	if err := x.zw.Close(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Close removes the temporary files.
func (x *ExportWriter) Close() {
	x.proofs.remove()
	x.bodies.remove()
}

func (x *ExportWriter) add(name string, b []byte) error {
	f, err := x.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: x.m.CreatedAt})
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

func (x *ExportWriter) copySpool(name string, s *spool) (integrity.Hash, error) {
	if err := s.w.Flush(); err != nil {
		return integrity.Hash{}, err
	}
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return integrity.Hash{}, err
	}
	f, err := x.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: x.m.CreatedAt})
	if err != nil {
		return integrity.Hash{}, err
	}
	if _, err := io.Copy(f, s.f); err != nil {
		return integrity.Hash{}, err
	}
	return sum(s.h), nil
}

func sum(h hash.Hash) integrity.Hash {
	var out integrity.Hash
	h.Sum(out[:0])
	return out
}

// spool is a temporary file of lines with their running SHA-256.
type spool struct {
	f *os.File
	w *bufio.Writer
	h hash.Hash
}

func newSpool(dir string) (*spool, error) {
	f, err := os.CreateTemp(dir, "fair-export-*")
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	h := sha256.New()
	return &spool{f: f, w: bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20), h: h}, nil
}

func (s *spool) line(b []byte) error {
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	return s.w.WriteByte('\n')
}

func (s *spool) remove() {
	if s == nil {
		return
	}
	name := s.f.Name()
	_ = s.f.Close()
	_ = os.Remove(name)
}

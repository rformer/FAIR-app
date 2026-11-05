package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/audit/integrity"
)

// ExportFormat names the export bundle format (design §6.6): a ZIP of
//
//	manifest.json      the Manifest, as a body (ADR-011)
//	manifest.sig       ECDSA P-256 over SHA-256(manifest.json), ASN.1,
//	                   by the checkpoint key named in the manifest
//	records.jsonl      the records' exact bodies, one per line, in sequence
//	                   order (record_format "jsonl"), or
//	records.csv and    a CSV view and the bodies (record_format "csv");
//	bodies.jsonl       only the bodies are verified
//	proofs.jsonl       per record, in the same order: {"seq", "segment",
//	                   "path"}, its Merkle inclusion path in its segment
//	checkpoints.jsonl  the consecutive checkpoints covering the records,
//	                   through the one closed for the export
//	keys.pem           the public keys that signed them
//
// The manifest lists every other file with its SHA-256; nothing else may be
// in the ZIP.
const ExportFormat = "fair-audit-export-v1"

// Bundle file names.
const (
	FileManifest    = "manifest.json"
	FileSignature   = "manifest.sig"
	FileRecords     = "records.jsonl"
	FileRecordsCSV  = "records.csv"
	FileBodies      = "bodies.jsonl"
	FileProofs      = "proofs.jsonl"
	FileCheckpoints = "checkpoints.jsonl"
	FileKeys        = "keys.pem"
)

// Manifest describes an export.
type Manifest struct {
	Format       string                    `json:"format"`
	Instance     string                    `json:"instance"`
	ExportID     string                    `json:"export_id"`
	CreatedAt    time.Time                 `json:"created_at"`
	RequestedBy  string                    `json:"requested_by"`
	Reason       string                    `json:"reason"`
	Filter       Filter                    `json:"filter"`
	BUScope      []string                  `json:"bu_scope"` // the BUs the requester could see (AC-33)
	RecordCount  uint64                    `json:"record_count"`
	RecordFormat string                    `json:"record_format"` // jsonl | csv
	Files        map[string]integrity.Hash `json:"files"`
	KeyID        string                    `json:"key_id"`
}

// Filter is the search an export ran, in words and as data (AC-33).
type Filter struct {
	Description string          `json:"description"`
	Data        json.RawMessage `json:"data"`
}

// Proof places one exported record in its segment.
type Proof struct {
	Seq     uint64           `json:"seq"`
	Segment uint64           `json:"segment"`
	Path    []integrity.Hash `json:"path"`
}

// ExportInput is what an export bundle is built from.
type ExportInput struct {
	Manifest    Manifest // Format, Files, RecordCount and KeyID are filled in
	Bodies      [][]byte
	CSV         []byte // with Manifest.RecordFormat "csv"
	Proofs      []Proof
	Checkpoints []integrity.Checkpoint
	Keys        Keys
}

// WriteExport writes an export bundle signed with key.
func WriteExport(w io.Writer, in ExportInput, key *ecdsa.PrivateKey) error {
	if len(in.Bodies) != len(in.Proofs) {
		return fmt.Errorf("evidence: %d bodies, %d proofs", len(in.Bodies), len(in.Proofs))
	}
	m := in.Manifest
	m.Format = ExportFormat
	m.RecordCount = uint64(len(in.Bodies))
	id, err := integrity.KeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	m.KeyID = id
	if m.RecordFormat == "" {
		m.RecordFormat = "jsonl"
	}
	if m.BUScope == nil {
		m.BUScope = []string{}
	}
	if len(m.Filter.Data) == 0 {
		m.Filter.Data = json.RawMessage("{}")
	}
	files := map[string][]byte{}
	var bodies bytes.Buffer
	for _, b := range in.Bodies {
		if bytes.ContainsAny(b, "\n\r") {
			return fmt.Errorf("evidence: a body is one line")
		}
		bodies.Write(b)
		bodies.WriteByte('\n')
	}
	switch m.RecordFormat {
	case "jsonl":
		files[FileRecords] = bodies.Bytes()
	case "csv":
		files[FileRecordsCSV] = in.CSV
		files[FileBodies] = bodies.Bytes()
	default:
		return fmt.Errorf("evidence: record format %q", m.RecordFormat)
	}
	var proofs bytes.Buffer
	enc := json.NewEncoder(&proofs)
	for _, p := range in.Proofs {
		if p.Path == nil {
			p.Path = []integrity.Hash{}
		}
		if err := enc.Encode(p); err != nil {
			return err
		}
	}
	files[FileProofs] = proofs.Bytes()
	var cps bytes.Buffer
	if err := WriteCheckpoints(&cps, in.Checkpoints); err != nil {
		return err
	}
	files[FileCheckpoints] = cps.Bytes()
	if files[FileKeys], err = EncodeKeys(in.Keys); err != nil {
		return err
	}
	m.Files = map[string]integrity.Hash{}
	for name, b := range files {
		m.Files[name] = sha256.Sum256(b)
	}
	manifest, err := integrity.Body(m)
	if err != nil {
		return err
	}
	sig, err := integrity.Sign(key, manifest)
	if err != nil {
		return err
	}
	files[FileManifest], files[FileSignature] = manifest, sig
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	zw := zip.NewWriter(w)
	for _, n := range names {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: m.CreatedAt})
		if err != nil {
			return err
		}
		if _, err := f.Write(files[n]); err != nil {
			return err
		}
	}
	return zw.Close()
}

// ExportResult summarizes a verified export.
type ExportResult struct {
	Manifest Manifest
	Records  int
	Segments int      // checkpoints in the bundle
	Pinned   bool     // verified against keys given by the caller
	KeyIDs   []string // the keys that signed the manifest and checkpoints
	Anchored bool     // the checkpoints reach back to segment 1
}

// MaxBundleFile bounds one file in a bundle when it is read.
const MaxBundleFile = 4 << 30

// VerifyExport checks an export bundle (design §11): the manifest signature,
// every file's digest (and nothing unlisted), the checkpoint chain, and each
// record's Merkle path to its checkpoint, records in strictly increasing
// sequence order. trusted are keys obtained separately; when nil, the
// bundle's own keys.pem is used and the result is not Pinned.
func VerifyExport(r io.ReaderAt, size int64, trusted Keys) (ExportResult, error) {
	var res ExportResult
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return res, invalid("bundle: %v", err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if _, dup := files[f.Name]; dup {
			return res, invalid("bundle: %s appears twice", f.Name)
		}
		if strings.ContainsAny(f.Name, `/\`) || f.FileInfo().IsDir() {
			return res, invalid("bundle: unexpected entry %s", f.Name)
		}
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f, ok := files[name]
		if !ok {
			return nil, invalid("bundle: %s is missing", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, invalid("bundle: %s: %v", name, err)
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(io.LimitReader(rc, MaxBundleFile+1))
		if err != nil {
			return nil, invalid("bundle: %s: %v", name, err)
		}
		if len(b) > MaxBundleFile {
			return nil, invalid("bundle: %s is too large", name)
		}
		return b, nil
	}
	manifest, err := read(FileManifest)
	if err != nil {
		return res, err
	}
	sig, err := read(FileSignature)
	if err != nil {
		return res, err
	}
	var m Manifest
	if err := strictJSON(manifest, &m); err != nil || m.Format != ExportFormat {
		return res, invalid("manifest: not a %s manifest", ExportFormat)
	}
	res.Manifest = m

	// The keys: the caller's (pinned) or the bundle's own.
	keys := trusted
	res.Pinned = trusted != nil
	if !res.Pinned {
		b, err := read(FileKeys)
		if err != nil {
			return res, err
		}
		if keys, err = ParseKeys(b); err != nil {
			return res, err
		}
	}
	pub, ok := keys[m.KeyID]
	if !ok {
		return res, invalid("manifest: signed by key %s, which is not trusted", m.KeyID)
	}
	if !integrity.VerifySignature(pub, manifest, sig) {
		return res, invalid("manifest: the signature does not verify")
	}

	// Every file is listed with its digest, and only listed files exist.
	need := []string{FileProofs, FileCheckpoints, FileKeys}
	switch m.RecordFormat {
	case "jsonl":
		need = append(need, FileRecords)
	case "csv":
		need = append(need, FileRecordsCSV, FileBodies)
	default:
		return res, invalid("manifest: record format %q", m.RecordFormat)
	}
	for _, n := range need {
		if _, ok := m.Files[n]; !ok {
			return res, invalid("manifest: %s is not listed", n)
		}
	}
	contents := map[string][]byte{}
	for name := range files {
		if name == FileManifest || name == FileSignature {
			continue
		}
		if _, ok := m.Files[name]; !ok {
			return res, invalid("bundle: %s is not in the manifest", name)
		}
	}
	var badDigest []string
	for _, name := range sortedKeys(m.Files) {
		b, err := read(name)
		if err != nil {
			return res, err
		}
		// A mismatch is reported after the records, so that a changed
		// record is reported at its position.
		if sha256.Sum256(b) != m.Files[name] {
			badDigest = append(badDigest, name)
		}
		contents[name] = b
	}

	// The checkpoints.
	cps, err := ReadCheckpoints(bytes.NewReader(contents[FileCheckpoints]))
	if err != nil {
		return res, err
	}
	chain, err := VerifyChain(cps, keys)
	if err != nil {
		return res, err
	}
	if chain.Instance() != m.Instance {
		return res, invalid("checkpoints belong to instance %q, the manifest names %q", chain.Instance(), m.Instance)
	}
	res.Segments, res.Anchored = len(chain.Statements), chain.Anchored
	used := map[string]bool{m.KeyID: true}
	for _, s := range chain.Statements {
		used[s.KeyID] = true
	}
	res.KeyIDs = sortedKeys(used)

	// The records and their proofs.
	bodiesFile := FileRecords
	if m.RecordFormat == "csv" {
		bodiesFile = FileBodies
	}
	var bodies [][]byte
	if err := lines(bytes.NewReader(contents[bodiesFile]), func(_ int, l []byte) error {
		bodies = append(bodies, bytes.Clone(l))
		return nil
	}); err != nil {
		return res, err
	}
	var proofs []Proof
	if err := lines(bytes.NewReader(contents[FileProofs]), func(n int, l []byte) error {
		var p Proof
		if err := strictJSON(l, &p); err != nil {
			return invalid("proofs line %d: %v", n, err)
		}
		proofs = append(proofs, p)
		return nil
	}); err != nil {
		return res, err
	}
	var last uint64
	for i, p := range proofs {
		if i >= len(bodies) {
			break
		}
		if i > 0 && p.Seq <= last {
			return res, &integrity.Failure{Seq: p.Seq, Reason: fmt.Sprintf("record line %d is out of order (after record %d)", i+1, last)}
		}
		last = p.Seq
		s, ok := chain.Segment(p.Segment)
		if !ok {
			return res, &integrity.Failure{Seq: p.Seq, Reason: fmt.Sprintf("record line %d: segment %d is not in the checkpoints", i+1, p.Segment)}
		}
		if p.Seq < s.SeqFrom || p.Seq > s.SeqTo {
			return res, &integrity.Failure{Seq: p.Seq, Reason: fmt.Sprintf("record line %d: not in segment %d", i+1, p.Segment)}
		}
		if !integrity.VerifyInclusion(integrity.Leaf(bodies[i]), p.Seq-s.SeqFrom, s.Count(), p.Path, s.MerkleRoot) {
			return res, &integrity.Failure{Seq: p.Seq, Reason: fmt.Sprintf("record line %d does not prove into segment %d", i+1, p.Segment)}
		}
	}
	if uint64(len(bodies)) != m.RecordCount || len(proofs) != len(bodies) {
		return res, invalid("bundle: %d records and %d proofs, the manifest says %d", len(bodies), len(proofs), m.RecordCount)
	}
	if len(badDigest) > 0 {
		return res, invalid("bundle: %s does not match its digest", strings.Join(badDigest, ", "))
	}
	res.Records = len(bodies)
	return res, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

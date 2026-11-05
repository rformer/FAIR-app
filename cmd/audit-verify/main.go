// Command audit-verify (released as fair-audit-verify) verifies audit trail
// evidence offline (F-002 T-10, AC-11; design §11; ADR-011). It needs no
// access to the platform and makes no network calls: it uses only the
// standard library and internal/audit/evidence, and it reads only the files
// it is given.
//
//	fair-audit-verify verify-export [-keys trusted.pem] bundle.zip
//	fair-audit-verify verify-archive -checkpoints checkpoints.jsonl -keys trusted.pem segment.jsonl.gz...
//	fair-audit-verify compare -platform checkpoints.jsonl -external <siem.jsonl | worm-dir> [-from N] [-to N]
//	fair-audit-verify version
//
// -keys names public keys obtained separately from the evidence (from the
// platform administrator, the release, or the write-once copies' operator).
// An export bundle carries its own keys.pem; without -keys verify-export uses
// those and says the result is not pinned.
//
// Exit codes: 0 intact, 1 failed (the first failing position is printed),
// 2 usage or unreadable input.
package main

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/integrity"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitIntact = 0
	exitFailed = 1
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `usage:
  fair-audit-verify verify-export [-keys trusted.pem] bundle.zip
  fair-audit-verify verify-archive -checkpoints checkpoints.jsonl -keys trusted.pem segment.jsonl.gz...
  fair-audit-verify compare -platform <file|dir> -external <file|dir> [-from N] [-to N]
  fair-audit-verify version
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "%s", usage)
		return exitUsage
	}
	switch args[0] {
	case "verify-export":
		return verifyExport(args[1:], stdout, stderr)
	case "verify-archive":
		return verifyArchive(args[1:], stdout, stderr)
	case "compare":
		return compare(args[1:], stdout, stderr)
	case "version":
		say(stdout, "fair-audit-verify %s (fair-audit-v%d, %s, %s; FIPS 140 module: %v)\n", version, integrity.Version, evidence.ExportFormat, evidence.SegmentFormat, fips140.Enabled())
		return exitIntact
	case "-h", "-help", "--help", "help":
		say(stdout, "%s", usage)
		return exitIntact
	}
	say(stderr, "unknown command %q\n%s", args[0], usage)
	return exitUsage
}

// say writes output; a failed write changes nothing, the exit code carries
// the result.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func sayln(w io.Writer, s string) { say(w, "%s\n", s) }

func flags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// result prints the outcome of a verification and returns the exit code.
func result(err error, ok string, stdout, stderr io.Writer) int {
	var f *integrity.Failure
	var d *evidence.Difference
	switch {
	case err == nil:
		sayln(stdout, "INTACT: "+ok)
		return exitIntact
	case errors.As(err, &f):
		pos := fmt.Sprintf("record %d", f.Seq)
		if f.Segment != 0 {
			pos = fmt.Sprintf("segment %d", f.Segment)
		}
		say(stdout, "FAILED at %s: %s\n", pos, f.Reason)
		return exitFailed
	case errors.As(err, &d):
		say(stdout, "DIFFERENT at segment %d: %s\n", d.Segment, d.Reason)
		return exitFailed
	case errors.Is(err, evidence.ErrInvalid):
		say(stdout, "FAILED: %v\n", err)
		return exitFailed
	}
	say(stderr, "error: %v\n", err)
	return exitUsage
}

func loadKeys(file string) (evidence.Keys, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(file) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, err
	}
	k, err := evidence.ParseKeys(b)
	if err != nil {
		return nil, fmt.Errorf("-keys: %w", err)
	}
	return k, nil
}

func verifyExport(args []string, stdout, stderr io.Writer) int {
	fs := flags("verify-export", stderr)
	keysFile := fs.String("keys", "", "trusted public keys (PEM), obtained separately from the bundle")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		say(stderr, "%s", usage)
		return exitUsage
	}
	trusted, err := loadKeys(*keysFile)
	if err != nil {
		say(stderr, "error: %v\n", err)
		return exitUsage
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		say(stderr, "error: %v\n", err)
		return exitUsage
	}
	res, err := evidence.VerifyExport(bytes.NewReader(b), int64(len(b)), trusted)
	if err == nil {
		m := res.Manifest
		say(stdout, "export %s of instance %s, created %s by %s\n", m.ExportID, m.Instance, m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), m.RequestedBy)
		say(stdout, "filter: %s\nBU scope: %s\nreason: %s\n", m.Filter.Description, strings.Join(m.BUScope, ", "), m.Reason)
		say(stdout, "signing keys: %s\n", strings.Join(res.KeyIDs, ", "))
		if !res.Pinned {
			sayln(stderr, "WARNING: keys not pinned: the bundle's own keys.pem was trusted. Compare the signing key ids above with keys obtained separately, or pass -keys.")
		}
		if !res.Anchored {
			sayln(stdout, "note: the checkpoints start after segment 1; the first is trusted on its signature")
		}
	}
	return result(err, fmt.Sprintf("%d records in %d checkpointed segments", res.Records, res.Segments), stdout, stderr)
}

func verifyArchive(args []string, stdout, stderr io.Writer) int {
	fs := flags("verify-archive", stderr)
	cpFile := fs.String("checkpoints", "", "the checkpoints covering the segments (JSON lines)")
	keysFile := fs.String("keys", "", "trusted public keys (PEM)")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 || *cpFile == "" || *keysFile == "" {
		say(stderr, "%s", usage)
		return exitUsage
	}
	keys, err := loadKeys(*keysFile)
	if err != nil {
		say(stderr, "error: %v\n", err)
		return exitUsage
	}
	f, err := os.Open(*cpFile)
	if err != nil {
		say(stderr, "error: %v\n", err)
		return exitUsage
	}
	cps, err := evidence.ReadCheckpoints(f)
	_ = f.Close()
	if err != nil {
		return result(err, "", stdout, stderr)
	}
	var archives []evidence.NamedArchive
	for _, name := range fs.Args() {
		if _, err := os.Stat(name); err != nil {
			say(stderr, "error: %v\n", err)
			return exitUsage
		}
		archives = append(archives, evidence.NamedArchive{Name: name, Open: func() (io.ReadCloser, error) { return os.Open(name) }}) // #nosec G304 -- the operator names the files
	}
	res, err := evidence.VerifyArchives(archives, cps, keys)
	if errors.Is(err, evidence.ErrInsufficient) {
		say(stderr, "error: %v\n", err)
		return exitUsage
	}
	if err == nil && !res.Anchored {
		sayln(stdout, "note: the checkpoints start after segment 1; the first is trusted on its signature")
	}
	return result(err, fmt.Sprintf("%d records in segments %v", res.Records, res.Segments), stdout, stderr)
}

func loadSet(p string) (evidence.CheckpointSet, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return evidence.ReadCheckpointDir(os.DirFS(p))
	}
	f, err := os.Open(p) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return evidence.ReadCheckpointStream(f, filepath.Base(p))
}

func compare(args []string, stdout, stderr io.Writer) int {
	fs := flags("compare", stderr)
	platform := fs.String("platform", "", "the platform's checkpoints (JSON lines, or a directory of copies)")
	external := fs.String("external", "", "the external copy: a SIEM export (JSON lines) or a directory of write-once copies")
	from := fs.Uint64("from", 0, "first segment to compare (default: the first either copy has)")
	to := fs.Uint64("to", 0, "last segment to compare (default: the last either copy has)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *platform == "" || *external == "" {
		say(stderr, "%s", usage)
		return exitUsage
	}
	sets := make([]evidence.CheckpointSet, 2)
	for i, p := range []string{*platform, *external} {
		s, err := loadSet(p)
		if err != nil {
			if errors.Is(err, evidence.ErrInvalid) || errors.As(err, new(*integrity.Failure)) {
				return result(err, "", stdout, stderr)
			}
			say(stderr, "error: %v\n", err)
			return exitUsage
		}
		sets[i] = s
	}
	if d := evidence.Compare(sets[0], sets[1], *from, *to); d != nil {
		return result(d, "", stdout, stderr)
	}
	segs := sets[0].Segments()
	return result(nil, fmt.Sprintf("the copies agree (%d checkpoints compared)", countIn(segs, *from, *to)), stdout, stderr)
}

func countIn(segs []uint64, from, to uint64) int {
	n := 0
	for _, s := range segs {
		if s >= from && (to == 0 || s <= to) {
			n++
		}
	}
	return n
}

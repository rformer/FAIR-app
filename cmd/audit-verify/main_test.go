package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/evidence/evidencetest"
)

// fixture writes a trail's evidence: an export bundle, its trusted keys,
// the checkpoints, segment archives, a SIEM export and write-once copies.
func fixture(t *testing.T) (string, *evidencetest.Trail) {
	t.Helper()
	dir := t.TempDir()
	tr := evidencetest.New(t, []int{3, 0, 4}, 2)
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	in := evidence.ExportInput{Manifest: evidence.Manifest{Instance: tr.Instance, ExportID: "exp-1", CreatedAt: time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC),
		RequestedBy: "auditor-1", Reason: "review", Filter: evidence.Filter{Description: "everything"}}, Checkpoints: tr.Checkpoints, Keys: tr.PublicKeys()}
	for _, seq := range []uint64{1, 5, 7} {
		seg, path := tr.Proof(t, seq)
		in.Bodies = append(in.Bodies, tr.Records[seq-1].Body)
		in.Proofs = append(in.Proofs, evidence.Proof{Seq: seq, Segment: seg, Path: path})
	}
	var buf bytes.Buffer
	if err := evidence.WriteExport(&buf, in, tr.Keys[1]); err != nil {
		t.Fatal(err)
	}
	write("bundle.zip", buf.Bytes())
	keys, err := evidence.EncodeKeys(tr.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}
	write("keys.pem", keys)
	buf.Reset()
	if err := evidence.WriteCheckpoints(&buf, tr.Checkpoints); err != nil {
		t.Fatal(err)
	}
	write("checkpoints.jsonl", buf.Bytes())
	var siem bytes.Buffer
	if err := os.Mkdir(filepath.Join(dir, "worm"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i, cp := range tr.Checkpoints {
		n := uint64(i + 1) // #nosec G115 -- test positions
		buf.Reset()
		if err := evidence.WriteSegment(&buf, evidence.Segment{Checkpoint: cp, Records: tr.SegmentRecords(n)}); err != nil {
			t.Fatal(err)
		}
		write(fmt.Sprintf("%d.jsonl.gz", n), buf.Bytes())
		ev, _ := json.Marshal(map[string]any{"type": "audit.checkpoint", "attributes": map[string]string{
			"statement": string(cp.Statement), "signature": base64.StdEncoding.EncodeToString(cp.Signature)}})
		siem.Write(append(ev, '\n'))
		c, _ := json.Marshal(cp)
		write(filepath.Join("worm", fmt.Sprintf("%d.json", n)), c)
	}
	write("siem.jsonl", siem.Bytes())
	return dir, tr
}

func runCmd(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestCommands(t *testing.T) {
	dir, _ := fixture(t)
	p := func(name string) string { return filepath.Join(dir, name) }
	cases := []struct {
		name         string
		args         []string
		code         int
		stdout, warn string
	}{
		{"export, pinned", []string{"verify-export", "-keys", p("keys.pem"), p("bundle.zip")}, 0, "INTACT: 3 records in 3 checkpointed segments", ""},
		{"export, unpinned", []string{"verify-export", p("bundle.zip")}, 0, "INTACT", "keys not pinned"},
		{"archives", []string{"verify-archive", "-checkpoints", p("checkpoints.jsonl"), "-keys", p("keys.pem"), p("1.jsonl.gz"), p("2.jsonl.gz"), p("3.jsonl.gz")}, 0, "INTACT: 7 records in segments [1 2 3]", ""},
		{"compare with the SIEM", []string{"compare", "-platform", p("checkpoints.jsonl"), "-external", p("siem.jsonl")}, 0, "the copies agree (3 checkpoints compared)", ""},
		{"compare with the write-once copies", []string{"compare", "-platform", p("checkpoints.jsonl"), "-external", p("worm")}, 0, "agree", ""},
		{"archives in any order", []string{"verify-archive", "-checkpoints", p("checkpoints.jsonl"), "-keys", p("keys.pem"), p("worm/../3.jsonl.gz"), p("1.jsonl.gz")}, 0, "INTACT", ""},
		{"no command", nil, 2, "", ""},
		{"unknown command", []string{"verify-everything"}, 2, "", ""},
		{"archive without keys", []string{"verify-archive", "-checkpoints", p("checkpoints.jsonl"), p("1.jsonl.gz")}, 2, "", ""},
		{"missing file", []string{"verify-export", p("nope.zip")}, 2, "", ""},
		{"not a checkpoints file", []string{"verify-archive", "-checkpoints", p("siem.jsonl"), "-keys", p("keys.pem"), p("1.jsonl.gz")}, 1, "FAILED", ""},
		{"version", []string{"version"}, 0, "fair-audit-v1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := runCmd(c.args...)
			if code != c.code || !strings.Contains(out, c.stdout) || !strings.Contains(errOut, c.warn) {
				t.Fatalf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, c.code, out, errOut)
			}
		})
	}

	// Tampering: exit 1 with the first failing position.
	b, _ := os.ReadFile(p("3.jsonl.gz"))                            // #nosec G304 -- test fixture
	if err := os.WriteFile(p("2.jsonl.gz"), b, 0o600); err != nil { // #nosec G703 -- a test temp dir
		t.Fatal(err)
	}
	code, out, _ := runCmd("verify-archive", "-checkpoints", p("checkpoints.jsonl"), "-keys", p("keys.pem"), p("2.jsonl.gz"))
	if code != 1 || !strings.Contains(out, "FAILED at segment 2") {
		t.Fatalf("swapped object: %d %s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(readFile(t, p("checkpoints.jsonl"))), "\n")
	if err := os.WriteFile(p("short.jsonl"), []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCmd("compare", "-platform", p("short.jsonl"), "-external", p("siem.jsonl"))
	if code != 1 || !strings.Contains(out, "DIFFERENT at segment 3: missing in the platform's checkpoints") {
		t.Fatalf("truncated platform: %d %s", code, out)
	}
	// Pinned to keys that did not sign: refused.
	other, _ := fixture(t)
	code, out, _ = runCmd("verify-export", "-keys", filepath.Join(other, "keys.pem"), p("bundle.zip"))
	if code != 1 || !strings.Contains(out, "not trusted") {
		t.Fatalf("other keys: %d %s", code, out)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func goTool(t *testing.T) string {
	t.Helper()
	g, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to inspect the build with")
	}
	return g
}

// T-10: the tool makes no network calls. It depends only on the standard
// library and the two evidence packages, none of the standard library's
// network clients or servers, and the linked binary contains no code that
// opens a socket.
func TestNoNetwork(t *testing.T) {
	g := goTool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, g, "list", "-deps", "-f", "{{if .Standard}}std {{end}}{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	allowed := map[string]bool{
		"github.com/rformer/fair-app/cmd/audit-verify":         true,
		"github.com/rformer/fair-app/internal/audit/evidence":  true,
		"github.com/rformer/fair-app/internal/audit/integrity": true,
	}
	forbidden := regexp.MustCompile(`^(net/http|net/rpc|net/smtp|net/mail|crypto/tls|os/exec|plugin|log/syslog)(/|$)`)
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pkg, ok := strings.CutPrefix(l, "std "); ok {
			if forbidden.MatchString(pkg) {
				t.Errorf("depends on %s", pkg)
			}
			continue
		}
		if !allowed[l] {
			t.Errorf("depends on %s, outside the standard library", l)
		}
	}

	bin := filepath.Join(t.TempDir(), "fair-audit-verify")
	build := exec.CommandContext(ctx, g, "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	syms, err := exec.CommandContext(ctx, g, "tool", "nm", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("nm: %v\n%s", err, syms)
	}
	// What opening a connection or a listener needs, on any platform.
	socket := regexp.MustCompile(`\b(net\.(Dial|\(\*Dialer\)|Listen|\(\*ListenConfig\)|\(\*sysDialer\)|socket|internetSocket|ResolveTCPAddr|LookupHost|\(\*Resolver\))|syscall\.(Socket|Connect|Bind|Listen|Sendto|Sendmsg|WSASocket|WSAConnect)|internal/poll\.\(\*FD\)\.(Connect|Accept|WSAIoctl)|crypto/tls\.)`)
	var found []string
	for _, l := range strings.Split(string(syms), "\n") {
		if m := socket.FindString(l); m != "" {
			found = append(found, strings.TrimSpace(l))
		}
	}
	if len(found) > 0 {
		t.Fatalf("the binary links network code:\n%s", strings.Join(found, "\n"))
	}
	// Sanity: the check sees symbols at all.
	if !bytes.Contains(syms, []byte("evidence.VerifyExport")) {
		t.Fatal("symbol table not read")
	}

	// The built binary verifies the fixture end to end.
	dir, _ := fixture(t)
	run := exec.CommandContext(ctx, bin, "verify-export", "-keys", filepath.Join(dir, "keys.pem"), filepath.Join(dir, "bundle.zip"))
	out, err = run.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	if run.ProcessState.ExitCode() != 0 || !bytes.Contains(out, []byte("INTACT")) {
		t.Fatalf("exit %d: %s", run.ProcessState.ExitCode(), out)
	}
}

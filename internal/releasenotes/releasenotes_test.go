package releasenotes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repo makes a git repository with a commit "v1" and a commit "v2".
func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(p, s string) {
		t.Helper()
		f := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(f), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rm := func(p string) {
		t.Helper()
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(p))); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	write("db/migrations/0001_init.sql", "-- F-000: the start.\nCREATE TABLE x ();\n")
	write("profiles/packages.yaml", "packages:\n  - id: a\n    version: \"1.0.0\"\n  - id: gone\n    version: \"1.0.0\"\n")
	write("bindings/s.one.yaml", "key: s.one\n")
	write("bindings/s.two.yaml", "key: s.two\n")
	write(catalogPath, `{"version": 1, "permissions": [{"key": "a.view", "privileged": false}, {"key": "a.old"}]}`)
	write(eventsPath, "events:\n  - type: a.done\n    description: \"A was done\"\n")
	write("specs/adr/ADR-001-x.md", "# ADR-001\n")
	run("add", "-A")
	run("commit", "-q", "-m", "v1")
	run("tag", "v1")
	write("db/migrations/0002_more.sql", "-- F-001 T-02 (AC-01): more tables,\n-- with a second line.\n\n-- not the header\nCREATE TABLE y ();\n")
	write("profiles/packages.yaml", "packages:\n  - id: a\n    version: \"1.1.0\"\n  - id: b\n    version: \"1.0.0\"\n")
	write("bindings/s.one.yaml", "key: s.one\nmax: 2\n")
	rm("bindings/s.two.yaml")
	write("bindings/s.three.yaml", "key: s.three\n")
	write(catalogPath, `{"version": 2, "permissions": [{"key": "a.view", "privileged": true}, {"key": "b.edit"}]}`)
	write(eventsPath, "events:\n  - type: a.done\n    description: \"A was done\"\n  - type: b.made\n    description: \"B was made\"\n")
	write("specs/adr/ADR-001-x.md", "# ADR-001 amended\n")
	write("specs/adr/ADR-002-y.md", "# ADR-002\n")
	run("add", "-A")
	run("commit", "-q", "-m", "v2")
	run("tag", "v2")
	return dir
}

// F-012 T-07 (F-012-AC-12; design §3.4): the notes list each kind of change
// between two releases.
func TestNotes(t *testing.T) {
	n, err := Build(Git{Dir: repo(t)}, "v1", "v2", []PR{{Number: 7, Title: "Fix a thing", URL: "https://example.invalid/7"}})
	if err != nil {
		t.Fatal(err)
	}
	md := string(n.Markdown())
	for _, want := range []string{
		"# FAIR v2", "Changes since v1.",
		"- #7 Fix a thing (https://example.invalid/7)",
		"- `0002_more.sql`: F-001 T-02 (AC-01): more tables, with a second line.",
		"- `a`: 1.0.0 → 1.1.0", "- `b`: 1.0.0 (new)", "- `gone`: removed",
		"- `s.one`: changed", "- `s.three`: added", "- `s.two`: removed",
		"Version 1 → 2.", "- `a.view`: changed", "- `b.edit`: added", "- `a.old`: retired",
		"- `b.made`: B was made",
		"- `ADR-001-x`: amended", "- `ADR-002-y`: added",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	if strings.Contains(md, "0001_init") || strings.Contains(md, "not the header") || strings.Contains(md, "a.done") {
		t.Errorf("notes list what did not change:\n%s", md)
	}
}

// From the first commit (the first release, D-OQ3), everything is new.
func TestNotesFromNothing(t *testing.T) {
	dir := repo(t)
	n, err := Build(Git{Dir: dir}, EmptyTree, "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	md := string(n.Markdown())
	for _, want := range []string{"- `0001_init.sql`: F-000: the start.", "- `a`: 1.0.0 (new)", "- `a.done`: A was done", "Security fixes\n\nNone.", "The first release", "Version 1."} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
}

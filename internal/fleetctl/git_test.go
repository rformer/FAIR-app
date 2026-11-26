package fleetctl

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo commits the fixture fleet into a new repository, with git's
// configuration isolated from the machine's.
func gitRepo(t *testing.T) (Git, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": empty, "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "Fleet Test", "GIT_AUTHOR_EMAIL": "fleet@example.test",
		"GIT_COMMITTER_NAME": "Fleet Test", "GIT_COMMITTER_EMAIL": "fleet@example.test",
	} {
		t.Setenv(k, v)
	}
	for n, f := range fixture(t) {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := Git{Dir: dir}
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"commit", "-q", "-m", "fleet"}} {
		if _, err := g.run(context.Background(), nil, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	head, err := g.Resolve(context.Background(), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return g, head
}

// TestGitBranches: a plan becomes one branch per instance over the base,
// each changing only its instance's files; the working tree, the index and
// main stay as they were, and an existing branch refuses the whole plan.
func TestGitBranches(t *testing.T) {
	ctx := context.Background()
	g, head := gitRepo(t)
	f, err := Load(g.Tree(ctx, head))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.Promote(ctx, newFake(), now, v02, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Branches(ctx, head, plan.Changes); err != nil {
		t.Fatal(err)
	}
	br := "fleet/promote/v0.2.0/vendor-1"
	diff, err := g.run(ctx, nil, nil, "diff", "--name-only", head, br)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Fields(diff)[0] != "instances/vendor-1/kustomization.yaml" || len(strings.Fields(diff)) != 2 {
		t.Errorf("branch changes %q", diff)
	}
	msg, _ := g.run(ctx, nil, nil, "log", "-1", "--format=%B", br)
	if !strings.HasPrefix(msg, "Promote vendor-1 to v0.2.0 (ring vendor)") {
		t.Errorf("message %q", msg)
	}
	if st, _ := g.run(ctx, nil, nil, "status", "--porcelain"); st != "" {
		t.Errorf("working tree changed: %q", st)
	}
	if m, _ := g.Resolve(ctx, "main"); m != head {
		t.Error("main moved")
	}
	tip, _ := g.Resolve(ctx, br)
	hf, err := Load(g.Tree(ctx, tip))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := hf.Instance("vendor-1"); v.Pin != v02 || v.Previous != v01 {
		t.Errorf("on the branch: %+v", v)
	}
	if _, err := MergeCheck(ctx, newFake(), now, f, hf); err != nil {
		t.Errorf("merge check of the branch: %v", err)
	}

	// Again: the branch exists, nothing is written.
	if err := g.Branches(ctx, head, plan.Changes); err == nil {
		t.Error("an existing branch was overwritten")
	}
	if err := g.Branches(ctx, head, []Change{{Branch: "-x", Files: map[string][]byte{}}}); err == nil {
		t.Error("an option as a branch name")
	}
	if _, err := g.Resolve(ctx, "--all"); err == nil {
		t.Error("an option as a revision")
	}
}

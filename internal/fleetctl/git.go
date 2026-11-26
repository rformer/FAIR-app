package fleetctl

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// FSTree reads a Tree from a file system (a checkout: os.DirFS).
type FSTree struct{ FS fs.FS }

// ReadFile implements Tree.
func (t FSTree) ReadFile(name string) ([]byte, error) { return fs.ReadFile(t.FS, name) }

// ReadDir implements Tree.
func (t FSTree) ReadDir(name string) ([]Entry, error) {
	es, err := fs.ReadDir(t.FS, name)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(es))
	for _, e := range es {
		out = append(out, Entry{Name: e.Name(), Dir: e.IsDir()})
	}
	return out, nil
}

// Git runs git in a fleet repository checkout. It reads revisions and
// creates branches; it never pushes, and never touches the working tree,
// the index or the checked-out branch.
type Git struct {
	Dir string
}

var branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func (g Git) run(ctx context.Context, env []string, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", g.Dir}, args...)...) // #nosec G204 -- fixed binary; arguments are revisions and paths checked by the caller
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Resolve returns rev's commit.
func (g Git) Resolve(ctx context.Context, rev string) (string, error) {
	if strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("revision %q", rev)
	}
	out, err := g.run(ctx, nil, nil, "rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Tree returns a Tree reading commit.
func (g Git) Tree(ctx context.Context, commit string) Tree {
	return gitTree{g: g, ctx: ctx, commit: commit}
}

type gitTree struct {
	g      Git
	ctx    context.Context
	commit string
}

func (t gitTree) ReadFile(name string) ([]byte, error) {
	out, err := t.g.run(t.ctx, nil, nil, "cat-file", "blob", t.commit+":"+path.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("%s at %.12s: %w", name, t.commit, err)
	}
	return []byte(out), nil
}

func (t gitTree) ReadDir(name string) ([]Entry, error) {
	out, err := t.g.run(t.ctx, nil, nil, "ls-tree", "-z", t.commit+":"+path.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("%s at %.12s: %w", name, t.commit, err)
	}
	var es []Entry
	for _, line := range strings.Split(out, "\x00") {
		meta, n, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta)
		es = append(es, Entry{Name: n, Dir: len(f) > 1 && f[1] == "tree"})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Name < es[j].Name })
	return es, nil
}

// Branches creates one branch per change, each a single commit over base,
// with the author and committer of the caller's git configuration. Every
// branch must be new; if any exists, none is created.
func (g Git) Branches(ctx context.Context, base string, changes []Change) error {
	for _, c := range changes {
		if !branchRE.MatchString(c.Branch) || strings.Contains(c.Branch, "..") {
			return fmt.Errorf("branch name %q", c.Branch)
		}
		if _, err := g.run(ctx, nil, nil, "rev-parse", "--verify", "--quiet", "refs/heads/"+c.Branch); err == nil {
			return fmt.Errorf("branch %s exists; delete it or merge it first", c.Branch)
		}
	}
	tmp, err := os.MkdirTemp("", "fleetctl-index-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for i, c := range changes {
		env := []string{"GIT_INDEX_FILE=" + filepath.Join(tmp, fmt.Sprintf("index-%d", i))}
		if _, err := g.run(ctx, env, nil, "read-tree", base); err != nil {
			return err
		}
		names := make([]string, 0, len(c.Files))
		for n := range c.Files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			blob, err := g.run(ctx, nil, c.Files[n], "hash-object", "-w", "--stdin")
			if err != nil {
				return err
			}
			if _, err := g.run(ctx, env, nil, "update-index", "--add", "--cacheinfo", "100644,"+strings.TrimSpace(blob)+","+n); err != nil {
				return err
			}
		}
		tree, err := g.run(ctx, env, nil, "write-tree")
		if err != nil {
			return err
		}
		commit, err := g.run(ctx, nil, []byte(c.Message), "commit-tree", strings.TrimSpace(tree), "-p", base, "-F", "-")
		if err != nil {
			return err
		}
		// The empty old value: create only, never move an existing branch.
		if _, err := g.run(ctx, nil, nil, "update-ref", "refs/heads/"+c.Branch, strings.TrimSpace(commit), ""); err != nil {
			return err
		}
	}
	return nil
}

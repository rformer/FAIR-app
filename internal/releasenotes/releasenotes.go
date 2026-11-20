// Package releasenotes writes a release's notes from the repository between
// two refs (F-012 T-07, F-012-AC-12; design §3.4): the migrations added with
// their header comments, the profile package versions and the setting
// bindings changed, the permission catalog's version and changes, the
// security event types added, the ADRs added or amended, and the security
// fixes (pull requests labelled security, passed in by the release job).
//
// It reads the repository through git (Git), so the notes depend only on
// the two refs.
package releasenotes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Repo reads files and changes between refs.
type Repo interface {
	// Changes lists "A", "M" or "D" with the path for every file under dir
	// that differs between from and to.
	Changes(from, to, dir string) ([][2]string, error)
	// Show is a file at ref, or nil when it does not exist there.
	Show(ref, path string) ([]byte, error)
}

// Git is a Repo over the git command in Dir.
type Git struct{ Dir string }

func (g Git) git(args ...string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...) // #nosec G204 -- fixed git subcommands; refs from the release job
	cmd.Dir = g.Dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Changes implements Repo.
func (g Git) Changes(from, to, dir string) ([][2]string, error) {
	out, err := g.git("diff", "--no-renames", "--name-status", from, to, "--", dir)
	if err != nil {
		return nil, err
	}
	var ch [][2]string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			ch = append(ch, [2]string{f[0][:1], f[1]})
		}
	}
	return ch, nil
}

// Show implements Repo.
func (g Git) Show(ref, path string) ([]byte, error) {
	if _, err := g.git("cat-file", "-e", ref+":"+path); err != nil {
		return nil, nil //nolint:nilerr // absent at ref
	}
	return g.git("show", ref+":"+path)
}

// EmptyTree is git's empty tree: the "from" of the first release, before
// which there was nothing (D-OQ3).
const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// PR is a pull request labelled security.
type PR struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	URL    string `json:"url"`
}

// Notes are a release's notes.
type Notes struct {
	From, To   string
	Migrations []Item // name, header
	Packages   []Item // id, "from → to"
	Settings   []Item // key, added/changed/removed
	Catalog    string // "6 → 7" or ""
	Permission []Item // key, added/removed/changed
	Events     []Item // type, description
	ADRs       []Item // file, added/amended
	Security   []PR
}

// Item is one line.
type Item struct{ Name, Detail string }

// Build reads the notes between from and to.
func Build(r Repo, from, to string, security []PR) (*Notes, error) {
	n := &Notes{From: from, To: to, Security: security}
	var err error
	if n.Migrations, err = migrations(r, from, to); err != nil {
		return nil, err
	}
	if n.Packages, err = packages(r, from, to); err != nil {
		return nil, err
	}
	if n.Settings, err = changed(r, from, to, "bindings", ".yaml"); err != nil {
		return nil, err
	}
	if n.Catalog, n.Permission, err = permissions(r, from, to); err != nil {
		return nil, err
	}
	if n.Events, err = events(r, from, to); err != nil {
		return nil, err
	}
	if n.ADRs, err = changed(r, from, to, "specs/adr", ".md"); err != nil {
		return nil, err
	}
	return n, nil
}

func base(p string) string { return p[strings.LastIndex(p, "/")+1:] }

var verbs = map[string]string{"A": "added", "M": "changed", "D": "removed"}

func migrations(r Repo, from, to string) ([]Item, error) {
	ch, err := r.Changes(from, to, "db/migrations")
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, c := range ch {
		if c[0] != "A" || !strings.HasSuffix(c[1], ".sql") {
			continue
		}
		b, err := r.Show(to, c[1])
		if err != nil {
			return nil, err
		}
		out = append(out, Item{base(c[1]), header(b)})
	}
	slices.SortFunc(out, func(a, b Item) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// header is a migration's leading comment, as one paragraph.
func header(b []byte) string {
	var parts []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "--") {
			break
		}
		if t := strings.TrimSpace(strings.TrimPrefix(l, "--")); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

func changed(r Repo, from, to, dir, ext string) ([]Item, error) {
	ch, err := r.Changes(from, to, dir)
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, c := range ch {
		if !strings.HasSuffix(c[1], ext) {
			continue
		}
		name := strings.TrimSuffix(base(c[1]), ext)
		v := verbs[c[0]]
		if dir == "specs/adr" {
			v = map[string]string{"A": "added", "M": "amended", "D": "removed"}[c[0]]
		}
		out = append(out, Item{name, v})
	}
	slices.SortFunc(out, func(a, b Item) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

type pkgFile struct {
	Packages []struct {
		ID      string `yaml:"id"`
		Version string `yaml:"version"`
	} `yaml:"packages"`
}

func packages(r Repo, from, to string) ([]Item, error) {
	read := func(ref string) (map[string]string, error) {
		b, err := r.Show(ref, "profiles/packages.yaml")
		if err != nil || b == nil {
			return map[string]string{}, err
		}
		var f pkgFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("profiles/packages.yaml at %s: %w", ref, err)
		}
		m := map[string]string{}
		for _, p := range f.Packages {
			m[p.ID] = p.Version
		}
		return m, nil
	}
	a, err := read(from)
	if err != nil {
		return nil, err
	}
	b, err := read(to)
	if err != nil {
		return nil, err
	}
	var out []Item
	for id, v := range b {
		switch {
		case a[id] == "":
			out = append(out, Item{id, v + " (new)"})
		case a[id] != v:
			out = append(out, Item{id, a[id] + " → " + v})
		}
	}
	for id := range a {
		if b[id] == "" {
			out = append(out, Item{id, "removed"})
		}
	}
	slices.SortFunc(out, func(x, y Item) int { return strings.Compare(x.Name, y.Name) })
	return out, nil
}

const catalogPath = "internal/access/catalog/release/catalog.json"

type catalog struct {
	Version     int               `json:"version"`
	Permissions []json.RawMessage `json:"permissions"`
}

func permissions(r Repo, from, to string) (string, []Item, error) {
	read := func(ref string) (int, map[string]string, error) {
		b, err := r.Show(ref, catalogPath)
		if err != nil || b == nil {
			return 0, map[string]string{}, err
		}
		var c catalog
		if err := json.Unmarshal(b, &c); err != nil {
			return 0, nil, fmt.Errorf("%s at %s: %w", catalogPath, ref, err)
		}
		m := map[string]string{}
		for _, p := range c.Permissions {
			var k struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(p, &k); err != nil {
				return 0, nil, err
			}
			m[k.Key] = string(p)
		}
		return c.Version, m, nil
	}
	va, a, err := read(from)
	if err != nil {
		return "", nil, err
	}
	vb, b, err := read(to)
	if err != nil {
		return "", nil, err
	}
	var out []Item
	for k, p := range b {
		switch q, ok := a[k]; {
		case !ok:
			out = append(out, Item{k, "added"})
		case q != p:
			out = append(out, Item{k, "changed"})
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, Item{k, "retired"})
		}
	}
	slices.SortFunc(out, func(x, y Item) int { return strings.Compare(x.Name, y.Name) })
	v := ""
	switch {
	case va == 0 && vb != 0:
		v = strconv.Itoa(vb)
	case va != vb:
		v = fmt.Sprintf("%d → %d", va, vb)
	}
	return v, out, nil
}

const eventsPath = "pkg/audit/catalog.yaml"

func events(r Repo, from, to string) ([]Item, error) {
	read := func(ref string) (map[string]string, error) {
		b, err := r.Show(ref, eventsPath)
		if err != nil || b == nil {
			return map[string]string{}, err
		}
		var c struct {
			Events []struct {
				Type        string `yaml:"type"`
				Description string `yaml:"description"`
			} `yaml:"events"`
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("%s at %s: %w", eventsPath, ref, err)
		}
		m := map[string]string{}
		for _, e := range c.Events {
			m[e.Type] = e.Description
		}
		return m, nil
	}
	a, err := read(from)
	if err != nil {
		return nil, err
	}
	b, err := read(to)
	if err != nil {
		return nil, err
	}
	var out []Item
	for t, d := range b {
		if _, ok := a[t]; !ok {
			out = append(out, Item{t, d})
		}
	}
	slices.SortFunc(out, func(x, y Item) int { return strings.Compare(x.Name, y.Name) })
	return out, nil
}

// Markdown renders the notes.
func (n *Notes) Markdown() []byte {
	var b strings.Builder
	if n.From == EmptyTree {
		fmt.Fprintf(&b, "# FAIR %s\n\nThe first release: everything below is new.\n", n.To)
	} else {
		fmt.Fprintf(&b, "# FAIR %s\n\nChanges since %s.\n", n.To, n.From)
	}
	section := func(title string, items []Item, empty string) {
		fmt.Fprintf(&b, "\n## %s\n\n", title)
		if len(items) == 0 {
			fmt.Fprintf(&b, "%s\n", empty)
			return
		}
		for _, it := range items {
			if it.Detail == "" {
				fmt.Fprintf(&b, "- `%s`\n", it.Name)
			} else {
				fmt.Fprintf(&b, "- `%s`: %s\n", it.Name, it.Detail)
			}
		}
	}
	fmt.Fprintf(&b, "\n## Security fixes\n\n")
	if len(n.Security) == 0 {
		b.WriteString("None.\n")
	}
	for _, p := range n.Security {
		fmt.Fprintf(&b, "- #%d %s (%s)\n", p.Number, p.Title, p.URL)
	}
	section("Database migrations", n.Migrations, "None.")
	section("Profile packages", n.Packages, "Unchanged.")
	section("Setting definitions", n.Settings, "Unchanged.")
	fmt.Fprintf(&b, "\n## Permission catalog\n\n")
	if n.Catalog != "" {
		fmt.Fprintf(&b, "Version %s.\n\n", n.Catalog)
	}
	if len(n.Permission) == 0 {
		b.WriteString("No permission changes.\n")
	}
	for _, it := range n.Permission {
		fmt.Fprintf(&b, "- `%s`: %s\n", it.Name, it.Detail)
	}
	section("Security events added", n.Events, "None.")
	section("Architecture decisions", n.ADRs, "None.")
	return []byte(b.String())
}

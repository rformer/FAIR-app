// Package pincheck finds build inputs that are not pinned (F-012 T-01,
// F-012-AC-03; design §3.1): GitHub Actions not referenced by a full commit
// (with a version comment), container images not referenced by digest, and
// dependencies without a lock file or hashes. Images built by the
// repository itself (names starting "fair-") and Dockerfile stage names are
// local and need no digest.
//
// What it reads:
//   - .github/workflows/*.yml: every "uses:", "image:" and image on a
//     docker run, pull or create line;
//   - every Dockerfile*: FROM, with ARG defaults resolved;
//   - scripts/**/*.sh and scripts/**/*.yaml: "image:", docker run, pull and
//     create lines, kubectl --image=, and *IMAGE*= assignments with their
//     ${VAR:-default};
//   - go.sum beside go.mod; engine/*.lock with a hash on every requirement;
//     a package-lock.json beside every package.json; no "npm install" in
//     workflows or scripts.
//
// Comment lines are skipped.
package pincheck

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Problem is one unpinned input, by file and line (line 0: the file).
type Problem struct {
	File    string
	Line    int
	Message string
}

func (p Problem) String() string {
	if p.Line == 0 {
		return fmt.Sprintf("%s: %s", p.File, p.Message)
	}
	return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Message)
}

// TaggedWorkflows are reusable workflows that must be referenced by a
// release tag rather than a commit (the SLSA generator verifies its own
// tag to produce Build Level 3 provenance).
var TaggedWorkflows = []string{"slsa-framework/slsa-github-generator/.github/workflows/"}

var (
	usesRE     = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*["']?([^\s"'#]+)["']?\s*(#.*)?$`)
	shaRE      = regexp.MustCompile(`@[0-9a-f]{40}$`)
	semverRE   = regexp.MustCompile(`@v\d+\.\d+\.\d+$`)
	versionCmt = regexp.MustCompile(`#\s*v?\d+(\.\d+)*`)
	imageKeyRE = regexp.MustCompile(`^\s*(?:-\s*)?image:\s*["']?([^\s"'#]+)`)
	fromRE     = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
	argRE      = regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)`)
	assignRE   = regexp.MustCompile(`\b[A-Z_]*IMAGE[A-Z_]*=["']?(?:\$\{[A-Z_]+:-([^}]+)\}|([^\s"'$]+))`)
	imageFlag  = regexp.MustCompile(`--image=["']?([^\s"']+)`)
	refRE      = regexp.MustCompile(`^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?/)?[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[0-9a-f]{64})?$`)
	digestRE   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	varRE      = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	hashLineRE = regexp.MustCompile(`--hash=sha256:[0-9a-f]{64}`)
	goLatestRE = regexp.MustCompile(`\bgo (run|install) (\S+)@latest\b`)
)

// Check walks root and answers every problem, sorted.
func Check(root string) ([]Problem, error) {
	var out []Problem
	add := func(file string, line int, format string, a ...any) {
		rel, _ := filepath.Rel(root, file)
		out = append(out, Problem{File: filepath.ToSlash(rel), Line: line, Message: fmt.Sprintf(format, a...)})
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == ".git" || name == "testdata" || name == "dist" || (strings.HasPrefix(name, ".") && name != ".github" && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		switch {
		case strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")):
			return scanText(path, true, add)
		case strings.HasPrefix(name, "Dockerfile"):
			return scanDockerfile(path, add)
		case strings.HasPrefix(rel, "scripts/") && (strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")):
			return scanText(path, false, add)
		case name == "go.mod":
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "go.sum")); err != nil {
				add(path, 0, "go.mod without go.sum")
			}
		case name == "package.json":
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "package-lock.json")); err != nil {
				add(path, 0, "package.json without package-lock.json")
			}
		case strings.HasPrefix(rel, "engine/") && strings.HasSuffix(name, ".lock"):
			return scanLock(path, add)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}

type adder func(file string, line int, format string, a ...any)

func lines(path string) ([]string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own files
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

func comment(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }

// image checks one image reference.
func image(ref string, add adder, path string, n int) {
	ref = strings.Trim(ref, `"'`)
	if ref == "" || strings.Contains(ref, "$") || !refRE.MatchString(ref) {
		return
	}
	name := repository(ref)
	if !strings.Contains(ref, ":") {
		return // no tag or digest: not an image reference (a local name or a word)
	}
	if strings.HasPrefix(name, "fair-") {
		return // built by the repository
	}
	if !digestRE.MatchString(ref) {
		add(path, n, "image %s is not pinned by digest (@sha256:...)", ref)
	}
}

// repository is ref without its tag and digest.
func repository(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

func scanText(path string, workflow bool, add adder) error {
	ls, err := lines(path)
	if err != nil {
		return err
	}
	for i, l := range ls {
		n := i + 1
		if comment(l) {
			continue
		}
		if workflow {
			if m := usesRE.FindStringSubmatch(l); m != nil {
				usesRef(m[1], m[2], add, path, n)
				continue
			}
			if strings.Contains(l, "npm install") || strings.Contains(l, "npm i ") {
				add(path, n, "npm install: use npm ci with the lock file")
			}
		}
		if m := goLatestRE.FindStringSubmatch(l); m != nil {
			add(path, n, "go %s of %s@latest: name a version", m[1], m[2])
		}
		if m := imageKeyRE.FindStringSubmatch(l); m != nil {
			image(m[1], add, path, n)
			continue
		}
		for _, m := range assignRE.FindAllStringSubmatch(l, -1) {
			image(m[1]+m[2], add, path, n)
		}
		for _, m := range imageFlag.FindAllStringSubmatch(l, -1) {
			image(m[1], add, path, n)
		}
		if strings.Contains(l, "docker run") || strings.Contains(l, "docker pull") || strings.Contains(l, "docker create") {
			for _, tok := range strings.Fields(l) {
				if strings.Contains(tok, ":") && !strings.HasPrefix(tok, "-") && !strings.Contains(tok, ":/") {
					image(tok, add, path, n)
				}
			}
		}
	}
	return nil
}

func usesRef(ref, cmt string, add adder, path string, n int) {
	switch {
	case strings.HasPrefix(ref, "./"):
		return
	case strings.HasPrefix(ref, "docker://"):
		if !digestRE.MatchString(ref) {
			add(path, n, "%s is not pinned by digest", ref)
		}
		return
	}
	for _, p := range TaggedWorkflows {
		if strings.HasPrefix(ref, p) {
			if !semverRE.MatchString(ref) {
				add(path, n, "%s must be referenced by a release tag (vX.Y.Z)", ref)
			}
			return
		}
	}
	if !shaRE.MatchString(ref) {
		add(path, n, "action %s is not pinned to a full commit", ref)
		return
	}
	if !versionCmt.MatchString(cmt) {
		add(path, n, "action %s has no version comment (# vX.Y.Z)", ref)
	}
}

func scanDockerfile(path string, add adder) error {
	ls, err := lines(path)
	if err != nil {
		return err
	}
	args := map[string]string{}
	stages := map[string]bool{}
	for i, l := range ls {
		n := i + 1
		if comment(l) {
			continue
		}
		if m := argRE.FindStringSubmatch(l); m != nil {
			args[m[1]] = strings.Trim(m[2], `"'`)
			continue
		}
		m := fromRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ref := varRE.ReplaceAllStringFunc(m[1], func(v string) string {
			if d, ok := args[varRE.FindStringSubmatch(v)[1]]; ok {
				return d
			}
			return v
		})
		if m[2] != "" {
			stages[strings.ToLower(m[2])] = true
		}
		switch {
		case stages[strings.ToLower(ref)] && !strings.EqualFold(ref, m[2]), ref == "scratch":
			continue
		case strings.Contains(ref, "$"):
			add(path, n, "FROM %s: the variable has no pinned default", m[1])
		case !digestRE.MatchString(ref):
			add(path, n, "FROM %s is not pinned by digest", ref)
		}
	}
	return nil
}

// scanLock requires a hash on every requirement of a pip-compile lock.
func scanLock(path string, add adder) error {
	f, err := os.Open(path) // #nosec G304 -- the repository's own file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var req string
	var reqLine int
	hashed := false
	flush := func() {
		if req != "" && !hashed {
			add(path, reqLine, "requirement %s has no --hash", req)
		}
	}
	n := 0
	for sc.Scan() {
		n++
		l := sc.Text()
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			flush()
			req, reqLine, hashed = strings.Fields(t)[0], n, false
		}
		if hashLineRE.MatchString(l) {
			hashed = true
		}
	}
	flush()
	return sc.Err()
}

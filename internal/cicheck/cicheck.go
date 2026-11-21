// Package cicheck checks the CI pipeline against the repository (F-012 T-03,
// design §3.1, §3.2): every image the Dockerfile builds is in the images
// matrix, and every pull-request job is a required check of the branch
// protection (infra/github), so a job added or renamed cannot fall out of the
// gates unnoticed.
package cicheck

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	fromRE = regexp.MustCompile(`(?i)^\s*FROM\s+\S+\s+AS\s+(\S+)`)
	copyRE = regexp.MustCompile(`(?i)--from=(\S+)`)
)

// ImageTargets is every Dockerfile stage that is an image: a named stage no
// other stage copies from (build stages are copied from).
func ImageTargets(dockerfile string) ([]string, error) {
	b, err := os.ReadFile(dockerfile) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, err
	}
	var stages []string
	sources := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := sc.Text()
		if m := fromRE.FindStringSubmatch(l); m != nil {
			stages = append(stages, strings.ToLower(m[1]))
		}
		for _, m := range copyRE.FindAllStringSubmatch(l, -1) {
			sources[strings.ToLower(m[1])] = true
		}
	}
	var out []string
	for _, s := range stages {
		if !sources[s] {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out, sc.Err()
}

// Workflow is what the checks read of a GitHub Actions workflow.
type Workflow struct {
	Jobs map[string]Job `yaml:"jobs"`
	path string
}

// Job is one job.
type Job struct {
	If       string `yaml:"if"`
	Uses     string `yaml:"uses"` // a reusable workflow
	Strategy struct {
		Matrix map[string]any `yaml:"matrix"`
	} `yaml:"strategy"`
}

// LoadWorkflow reads a workflow file.
func LoadWorkflow(path string) (*Workflow, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, err
	}
	w := Workflow{path: path}
	if err := yaml.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// MatrixValues is a job's matrix values for key (strings).
func (w *Workflow) MatrixValues(job, key string) []string {
	var out []string
	vals, _ := w.Jobs[job].Strategy.Matrix[key].([]any)
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// CheckNames is the check name of every job that runs on pull requests: the
// job's key, or "key (value)" for each value of a one-key matrix, or, for a
// job calling a reusable workflow of this repository, "key / inner" for each
// of its jobs. Jobs conditioned on pushes (bench) are left out.
func (w *Workflow) CheckNames() []string {
	var out []string
	for name, j := range w.Jobs {
		if strings.Contains(j.If, "github.event_name == 'push'") {
			continue
		}
		if strings.HasPrefix(j.Uses, "./") {
			inner, err := LoadWorkflow(filepath.Join(filepath.Dir(w.path), "..", "..", filepath.FromSlash(j.Uses)))
			if err != nil {
				out = append(out, name+" / ?") // fails the comparison, naming the job
				continue
			}
			for _, n := range inner.CheckNames() {
				out = append(out, name+" / "+n)
			}
			continue
		}
		m := j.Strategy.Matrix
		if len(m) == 1 {
			for k := range m {
				if vals := w.MatrixValues(name, k); len(vals) > 0 {
					for _, v := range vals {
						out = append(out, name+" ("+v+")")
					}
					continue
				}
				out = append(out, name)
			}
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

var checkRE = regexp.MustCompile(`^\s*"([^"]+)",\s*$`)

// RequiredChecks is the default list of required_checks in
// infra/github/variables.tf.
func RequiredChecks(variablesTF string) ([]string, error) {
	b, err := os.ReadFile(variablesTF) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, err
	}
	s := string(b)
	i := strings.Index(s, `variable "required_checks"`)
	if i < 0 {
		return nil, nil
	}
	s = s[i:]
	s = s[strings.Index(s, "default = [")+len("default = ["):]
	s = s[:strings.Index(s, "]")]
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if m := checkRE.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out, nil
}

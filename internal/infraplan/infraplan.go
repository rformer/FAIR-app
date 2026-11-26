// Package infraplan reads OpenTofu plans (tofu show -json) for the instance
// pipeline (F-012 T-14, F-012-AC-14, AC-16; design §3.5, §6 "T:
// infrastructure drifts from code"):
//   - Summary: what a plan would change, for the pull request's comment;
//   - Digest: a stable digest of a plan's changes, so the apply after
//     approval applies the changes the approved plan showed and nothing
//     else;
//   - CreateOnly: a new instance's first stack plan creates and never
//     changes or deletes;
//   - Drift: the daily drift job's verdict over every instance's plans
//     (exit codes of tofu plan -detailed-exitcode and the plans), and the
//     issue it opens.
//
// Standard library only.
package infraplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Plan is what the pipeline reads of tofu show -json.
type Plan struct {
	FormatVersion   string   `json:"format_version"`
	ResourceChanges []Change `json:"resource_changes"`
	ResourceDrift   []Change `json:"resource_drift"`
	Errored         bool     `json:"errored"`
}

// Change is one resource instance's planned (or detected) change.
type Change struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Change  struct {
		Actions []string `json:"actions"`
	} `json:"change"`
}

// Item is one change in a summary: the address and what happens to it.
type Item struct {
	Address string
	Action  string // create, update, delete, replace
}

// Load reads a plan file.
func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the pipeline's own plan file
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("%s: not a tofu show -json plan (no format_version)", path)
	}
	return &p, nil
}

// action names a change's actions; "" for no change (no-op, read).
func action(actions []string) string {
	switch strings.Join(actions, ",") {
	case "create":
		return "create"
	case "update":
		return "update"
	case "delete":
		return "delete"
	case "delete,create", "create,delete":
		return "replace"
	case "forget":
		return "forget"
	case "", "no-op", "read":
		return ""
	default:
		return strings.Join(actions, ",")
	}
}

func items(cs []Change) []Item {
	var out []Item
	for _, c := range cs {
		if c.Mode == "data" {
			continue
		}
		if a := action(c.Change.Actions); a != "" {
			out = append(out, Item{Address: c.Address, Action: a})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// Changes is what applying the plan would do, sorted by address.
func (p *Plan) Changes() []Item { return items(p.ResourceChanges) }

// Drifted is what changed outside OpenTofu since the last apply (the
// refresh found it), sorted by address.
func (p *Plan) Drifted() []Item { return items(p.ResourceDrift) }

// Digest is the SHA-256 of the plan's changes (address and action, one per
// line, sorted): equal digests mean the same changes.
func (p *Plan) Digest() string {
	h := sha256.New()
	for _, it := range p.Changes() {
		fmt.Fprintf(h, "%s %s\n", it.Action, it.Address)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CreateOnly fails when the plan would change or delete anything: a new
// instance's first plan only creates.
func (p *Plan) CreateOnly() error {
	var bad []string
	for _, it := range p.Changes() {
		if it.Action != "create" {
			bad = append(bad, it.Action+" "+it.Address)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("a first apply only creates; this plan would also %s", strings.Join(bad, "; "))
	}
	return nil
}

// Summary is a Markdown summary of the plan, for the pull request.
func (p *Plan) Summary(title string) string {
	var b strings.Builder
	counts := map[string]int{}
	cs := p.Changes()
	for _, it := range cs {
		counts[it.Action]++
	}
	fmt.Fprintf(&b, "### %s\n\n", title)
	if len(cs) == 0 {
		b.WriteString("No changes.\n")
	} else {
		fmt.Fprintf(&b, "%d to create, %d to update, %d to replace, %d to delete.\n\n", counts["create"], counts["update"], counts["replace"], counts["delete"])
		b.WriteString("| Action | Resource |\n|---|---|\n")
		for _, it := range cs {
			fmt.Fprintf(&b, "| %s | `%s` |\n", it.Action, it.Address)
		}
	}
	if d := p.Drifted(); len(d) > 0 {
		b.WriteString("\nChanged outside OpenTofu since the last apply:\n\n| Change | Resource |\n|---|---|\n")
		for _, it := range d {
			fmt.Fprintf(&b, "| %s | `%s` |\n", it.Action, it.Address)
		}
	}
	fmt.Fprintf(&b, "\nDigest of the changes: `%s`\n", p.Digest())
	return b.String()
}

// Verdict is one instance's (or root's) drift state.
type Verdict string

// The verdicts, worst last.
const (
	Clean Verdict = "clean"
	Drift Verdict = "drift"
	Error Verdict = "error"
)

func worse(a, b Verdict) Verdict {
	rank := map[Verdict]int{Clean: 0, Drift: 1, Error: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// RootResult is one root's plan of one instance.
type RootResult struct {
	Root     string // account, instance
	ExitCode int    // tofu plan -detailed-exitcode: 0 clean, 1 error, 2 changes
	Verdict  Verdict
	Changes  []Item
	Drifted  []Item
	Problem  string
}

// InstanceResult is one instance's verdict over its roots.
type InstanceResult struct {
	Instance string
	Verdict  Verdict
	Roots    []RootResult
}

// ReadDrift reads a drift job's results: DIR/<instance>/<root>.exitcode
// (tofu plan -detailed-exitcode) and, for exit 0 and 2, DIR/<instance>/<root>.json
// (tofu show -json). A root with exit 2 drifted; a root with exit 1, a
// missing or unreadable file, or an exit code the plan contradicts, could
// not be checked (an error, which alerts too).
func ReadDrift(dir string) ([]InstanceResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []InstanceResult
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		res := InstanceResult{Instance: e.Name(), Verdict: Clean}
		codes, _ := filepath.Glob(filepath.Join(dir, e.Name(), "*.exitcode"))
		sort.Strings(codes)
		if len(codes) == 0 {
			res.Verdict = Error
			res.Roots = append(res.Roots, RootResult{Root: "-", Verdict: Error, Problem: "no plan was recorded"})
		}
		for _, c := range codes {
			r := readRoot(c)
			res.Verdict = worse(res.Verdict, r.Verdict)
			res.Roots = append(res.Roots, r)
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, errors.New("no instance's plans in " + dir)
	}
	return out, nil
}

func readRoot(codeFile string) RootResult {
	root := strings.TrimSuffix(filepath.Base(codeFile), ".exitcode")
	r := RootResult{Root: root, ExitCode: -1, Verdict: Error}
	b, err := os.ReadFile(codeFile) // #nosec G304 -- the drift job's own file
	if err != nil {
		r.Problem = err.Error()
		return r
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		r.Problem = "unreadable exit code"
		return r
	}
	r.ExitCode = code
	if code != 0 && code != 2 {
		r.Problem = fmt.Sprintf("tofu plan failed (exit %d)", code)
		return r
	}
	p, err := Load(strings.TrimSuffix(codeFile, ".exitcode") + ".json")
	if err != nil {
		r.Problem = "the plan could not be read: " + err.Error()
		return r
	}
	if p.Errored {
		r.Problem = "the plan is marked errored"
		return r
	}
	r.Changes, r.Drifted = p.Changes(), p.Drifted()
	switch {
	case code == 0 && len(r.Changes) == 0:
		r.Verdict = Clean
		// Changed outside OpenTofu in attributes the configuration does not
		// set: reported with the drift, not alerted on its own.
		if len(r.Drifted) > 0 {
			r.Problem = "changes outside OpenTofu the configuration does not manage"
		}
	case code == 2 && len(r.Changes) > 0:
		r.Verdict = Drift
	default:
		r.Problem = fmt.Sprintf("exit %d but %d planned changes", code, len(r.Changes))
	}
	return r
}

// Overall is the worst verdict over the instances.
func Overall(rs []InstanceResult) Verdict {
	v := Clean
	for _, r := range rs {
		v = worse(v, r.Verdict)
	}
	return v
}

// IssueTitle is the drift issue's title (one open issue, commented on by
// later runs).
const IssueTitle = "Infrastructure drift: instances differ from their code"

// IssueBody is the drift issue's body for the instances that drifted or
// could not be checked; runURL links the run.
func IssueBody(rs []InstanceResult, runURL string) string {
	var b strings.Builder
	b.WriteString("The daily drift job (F-012-AC-16) found deployed infrastructure that differs from its code, or could not check it.\n")
	if runURL != "" {
		fmt.Fprintf(&b, "Run: %s\n", runURL)
	}
	b.WriteString("\nChanges are applied only from approved code: revert the change outside OpenTofu, or make it a reviewed change to `infra/` (docs/operations/onboarding.md, \"Drift\").\n")
	for _, r := range rs {
		if r.Verdict == Clean {
			continue
		}
		fmt.Fprintf(&b, "\n## %s: %s\n", r.Instance, r.Verdict)
		for _, root := range r.Roots {
			if root.Verdict == Clean && len(root.Drifted) == 0 {
				continue
			}
			fmt.Fprintf(&b, "\n### %s (%s)\n", root.Root, root.Verdict)
			if root.Problem != "" {
				fmt.Fprintf(&b, "\n%s.\n", strings.TrimSuffix(root.Problem, "."))
			}
			if len(root.Changes) > 0 {
				b.WriteString("\nThe plan would:\n\n")
				for _, it := range root.Changes {
					fmt.Fprintf(&b, "- %s `%s`\n", it.Action, it.Address)
				}
			}
			if len(root.Drifted) > 0 {
				b.WriteString("\nChanged outside OpenTofu:\n\n")
				for _, it := range root.Drifted {
					fmt.Fprintf(&b, "- %s `%s`\n", it.Action, it.Address)
				}
			}
		}
	}
	return b.String()
}

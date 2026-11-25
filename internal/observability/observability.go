// Package observability reads the operations configuration in
// deploy/observability (F-012 T-11; F-012-AC-24, AC-25; design §3.7): the
// Prometheus alert rules, their runbooks in docs/operations/runbooks and the
// OpenTelemetry Collector configurations, so tests can hold them together.
// promtool and the Collector validate the files themselves
// (scripts/observability-check.sh).
package observability

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// RunbookBase is the start of every alert's runbook_url; the rest is
// <alert>.md, a file in RunbookDir.
const RunbookBase = "https://github.com/rformer/FAIR-app/blob/main/docs/operations/runbooks/"

// Paths relative to the repository root.
const (
	AlertsDir  = "deploy/observability/alerts"
	RunbookDir = "docs/operations/runbooks"
)

// Severities an alert may carry: critical pages, warning opens a ticket.
var Severities = []string{"critical", "warning"}

// Rule is one rule of a Prometheus rule file (recording rules have Record).
type Rule struct {
	Alert       string            `yaml:"alert"`
	Record      string            `yaml:"record"`
	Expr        string            `yaml:"expr"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
	File        string            `yaml:"-"`
}

type ruleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []Rule `yaml:"rules"`
	} `yaml:"groups"`
}

// Alerts reads every alerting rule of the rule files (*.yaml) in dir.
func Alerts(dir string) ([]Rule, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files in %s", dir)
	}
	slices.Sort(files)
	var out []Rule
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the repository's own files
		if err != nil {
			return nil, err
		}
		var rf ruleFile
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, g := range rf.Groups {
			for _, r := range g.Rules {
				if r.Alert == "" {
					continue
				}
				r.File = filepath.Base(f)
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// Runbooks names the runbooks in dir: every *.md but README.md, by alert
// name (the file name without .md).
func Runbooks(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".md")
		if name != "README" {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Check returns every problem with the alerts and runbooks under root: an
// alert without a known severity, a summary, or a runbook_url naming its
// own runbook file; a runbook file missing; a runbook without an alert; an
// alert name used twice.
func Check(root string) ([]string, error) {
	alerts, err := Alerts(filepath.Join(root, AlertsDir))
	if err != nil {
		return nil, err
	}
	books, err := Runbooks(filepath.Join(root, RunbookDir))
	if err != nil {
		return nil, err
	}
	var problems []string
	seen := map[string]bool{}
	for _, a := range alerts {
		where := a.File + ": " + a.Alert
		if seen[a.Alert] {
			problems = append(problems, where+": alert name used twice")
		}
		seen[a.Alert] = true
		if !slices.Contains(Severities, a.Labels["severity"]) {
			problems = append(problems, fmt.Sprintf("%s: severity %q, want one of %v", where, a.Labels["severity"], Severities))
		}
		if strings.TrimSpace(a.Annotations["summary"]) == "" {
			problems = append(problems, where+": no summary annotation")
		}
		if want := RunbookBase + a.Alert + ".md"; a.Annotations["runbook_url"] != want {
			problems = append(problems, fmt.Sprintf("%s: runbook_url %q, want %q", where, a.Annotations["runbook_url"], want))
		}
		if !slices.Contains(books, a.Alert) {
			problems = append(problems, fmt.Sprintf("%s: no runbook %s/%s.md", where, RunbookDir, a.Alert))
		}
	}
	for _, b := range books {
		if !seen[b] {
			problems = append(problems, fmt.Sprintf("%s/%s.md: no alert of that name", RunbookDir, b))
		}
	}
	return problems, nil
}

// Collector is what the tests read of an OpenTelemetry Collector
// configuration.
type Collector struct {
	Receivers  map[string]any `yaml:"receivers"`
	Exporters  map[string]any `yaml:"exporters"`
	Connectors map[string]any `yaml:"connectors"`
	Service    struct {
		Pipelines map[string]struct {
			Receivers []string `yaml:"receivers"`
			Exporters []string `yaml:"exporters"`
		} `yaml:"pipelines"`
	} `yaml:"service"`
	raw map[string]any
}

// ReadCollector reads a Collector configuration file.
func ReadCollector(path string) (*Collector, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own files
	if err != nil {
		return nil, err
	}
	var c Collector
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &c.raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// TLSBlocks returns every `tls` block in the configuration by its path
// (e.g. receivers.otlp.protocols.grpc.tls).
func (c *Collector) TLSBlocks() map[string]map[string]any {
	out := map[string]map[string]any{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		for k, child := range m {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if cm, ok := child.(map[string]any); ok && k == "tls" {
				out[p] = cm
			}
			walk(p, child)
		}
	}
	walk("", c.raw)
	return out
}

// ExporterType is a component id's type: otlp_grpc/forward is otlp_grpc.
func ExporterType(id string) string {
	t, _, _ := strings.Cut(id, "/")
	return t
}

package observability

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const root = "../.."

// F-012 T-11 (F-012-AC-24; design §3.7): every alert has a severity, a
// summary and a runbook_url to its own runbook, which exists; every runbook
// has its alert.
func TestAlertsHaveRunbooks(t *testing.T) {
	alerts, err := Alerts(filepath.Join(root, AlertsDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) == 0 {
		t.Fatal("no alerts")
	}
	problems, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// The design's alert list (§3.7) is covered: availability, latency, failed
// jobs, audit forwarding and verification, certificate and key expiry,
// backups, drift.
func TestAlertsCoverDesign(t *testing.T) {
	alerts, err := Alerts(filepath.Join(root, AlertsDir))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range alerts {
		names = append(names, a.Alert)
	}
	for _, want := range []string{"ApiAvailabilityBudgetBurn", "ApiLatencyP95High", "JobFailureBudgetBurn", "AuditForwardingBacklogHigh",
		"AuditVerificationFailed", "CertificateExpiringSoon", "EngineCertificateExpiringSoon", "BackupJobFailed", "PostureDriftDetected"} {
		if !slices.Contains(names, want) {
			t.Errorf("no alert %s", want)
		}
	}
}

// Check finds each kind of problem.
func TestCheckFindsProblems(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, AlertsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, RunbookDir), 0o750); err != nil {
		t.Fatal(err)
	}
	rules := `groups:
  - name: g
    rules:
      - record: r:x
        expr: up
      - alert: Good
        expr: up == 0
        labels: { severity: critical }
        annotations: { summary: s, runbook_url: ` + RunbookBase + `Good.md }
      - alert: NoSeverity
        expr: up == 0
        annotations: { summary: s, runbook_url: ` + RunbookBase + `NoSeverity.md }
      - alert: WrongURL
        expr: up == 0
        labels: { severity: warning }
        annotations: { summary: s, runbook_url: https://example.test/WrongURL.md }
      - alert: NoBook
        expr: up == 0
        labels: { severity: warning }
        annotations: { summary: s, runbook_url: ` + RunbookBase + `NoBook.md }
      - alert: Good
        expr: up == 1
        labels: { severity: warning }
        annotations: { summary: s, runbook_url: ` + RunbookBase + `Good.md }
`
	if err := os.WriteFile(filepath.Join(dir, AlertsDir, "a.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"Good", "NoSeverity", "WrongURL", "Orphan", "README"} {
		if err := os.WriteFile(filepath.Join(dir, RunbookDir, b+".md"), []byte("# "+b+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	problems, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(problems, "\n")
	for _, want := range []string{"NoSeverity: severity", "WrongURL: runbook_url", "NoBook: no runbook", "Orphan.md: no alert", "Good: alert name used twice"} {
		if !strings.Contains(all, want) {
			t.Errorf("no problem %q in:\n%s", want, all)
		}
	}
	if len(problems) != 5 || strings.Contains(all, "README") {
		t.Errorf("%d problems:\n%s", len(problems), all)
	}
}

// F-012-AC-25: the self-hosted Collector exports only to the local
// Prometheus endpoint (and a nop sink); forwarding is the administrator's,
// to an endpoint they set, in the separate overlay.
func TestSelfHostedCollectorStaysInside(t *testing.T) {
	c, err := ReadCollector(filepath.Join(root, "deploy/observability/collector-selfhosted.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for id := range c.Exporters {
		if typ := ExporterType(id); typ != "prometheus" && typ != "nop" {
			t.Errorf("self-hosted exporter %s", id)
		}
	}
	f, err := ReadCollector(filepath.Join(root, "deploy/observability/collector-selfhosted-forward.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for id, v := range f.Exporters {
		m, _ := v.(map[string]any)
		ep, _ := m["endpoint"].(string)
		if !strings.HasPrefix(ep, "${env:") {
			t.Errorf("forwarding exporter %s endpoint %q: the administrator's, from the environment", id, ep)
		}
	}
}

// Every TLS block in every Collector configuration sets TLS 1.2 or later
// (ADR-006), and none disables verification.
func TestCollectorTLS(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(root, "deploy/observability/collector-*.yaml"))
	if err != nil || len(files) < 4 {
		t.Fatalf("%d collector configurations (%v)", len(files), err)
	}
	for _, f := range files {
		c, err := ReadCollector(f)
		if err != nil {
			t.Fatal(err)
		}
		blocks := c.TLSBlocks()
		if len(blocks) == 0 {
			t.Errorf("%s: no TLS", filepath.Base(f))
		}
		for path, tls := range blocks {
			if v := tls["min_version"]; v != "1.2" && v != "1.3" {
				t.Errorf("%s %s: min_version %v", filepath.Base(f), path, v)
			}
			if tls["insecure"] == true || tls["insecure_skip_verify"] == true {
				t.Errorf("%s %s: verification off", filepath.Base(f), path)
			}
		}
	}
}

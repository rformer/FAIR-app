package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/fleetctl"
)

var (
	d1  = "sha256:" + strings.Repeat("1", 64)
	d2  = "sha256:" + strings.Repeat("2", 64)
	now = time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC) // Saturday
)

// healthy is a fake health source: the named instances run their pin,
// ready and soaked; any other instance cannot be reached.
type healthy struct {
	on     map[string]fleetctl.Pin
	alerts []string
}

func (h healthy) Flux(_ context.Context, in fleetctl.Instance) (fleetctl.Flux, error) {
	p, ok := h.on[in.ID]
	if !ok {
		return fleetctl.Flux{}, errors.New("unreachable")
	}
	rev := p.Tag + "@" + p.Digest
	f := fleetctl.Flux{Source: fleetctl.Step{Name: "fair-release", Ready: true, Revision: rev}, Since: now.Add(-100 * time.Hour)}
	for _, n := range []string{"fair-addons", "fair-policy", "fair-addons-config", "fair-namespaces", "fair-secrets", "fair-migrate", "fair-platform", "fair-observability"} {
		f.Steps = append(f.Steps, fleetctl.Step{Name: n, Ready: true, Revision: rev})
	}
	return f, nil
}

func (h healthy) Ready(context.Context, fleetctl.Instance) error { return nil }

func (h healthy) Alerts(context.Context, fleetctl.Instance, time.Duration) ([]string, error) {
	return h.alerts, nil
}

// repo commits internal/fleetctl's fixture fleet into a new repository.
func repo(t *testing.T) string {
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
	src := os.DirFS(filepath.Join("..", "..", "internal", "fleetctl", "testdata", "fleet"))
	dst, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dst.Close() }()
	err = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}
		if err := dst.MkdirAll(path.Dir(p), 0o750); err != nil {
			return err
		}
		return dst.WriteFile(p, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"commit", "-q", "-m", "fleet"}} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

func fleetctlRun(t *testing.T, src fleetctl.Sources, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, env{stdout: &out, stderr: &errb, now: func() time.Time { return now },
		sources: func(fleetctl.Live) fleetctl.Sources { return src }})
	return code, out.String(), errb.String()
}

func TestCommands(t *testing.T) {
	dir := repo(t)
	v01 := fleetctl.Pin{Tag: "v0.1.0", Digest: d1}
	v02 := fleetctl.Pin{Tag: "v0.2.0", Digest: d2}
	fleetJSON := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(fleetJSON, []byte(`{"staging":"ghcr.io/o/staging/fair-manifests@`+d2+`","release":"ghcr.io/o/fair-manifests@`+d2+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	all := healthy{on: map[string]fleetctl.Pin{"vendor-1": v01, "canary-1": v01, "canary-2": v01, "general-1": v01, "general-2": v01}}

	code, out, _ := fleetctlRun(t, all, "status", "-repo", dir)
	if code != 0 || !strings.Contains(out, "INSTANCE") || strings.Count(out, "healthy") != 5 {
		t.Errorf("status %d:\n%s", code, out)
	}
	code, out, _ = fleetctlRun(t, all, "status", "-repo", dir, "-json")
	if code != 0 || strings.Count(out, `"healthy":true`) != 5 {
		t.Errorf("status -json %d:\n%s", code, out)
	}

	// The first ring: a branch for vendor-1, and none twice.
	code, out, errs := fleetctlRun(t, all, "promote", "-repo", dir, "-release", "v0.2.0", "-fleet-json", fleetJSON)
	if code != 0 || !strings.Contains(out, "vendor-1: branch fleet/promote/v0.2.0/vendor-1") {
		t.Fatalf("promote %d: %s %s", code, out, errs)
	}
	if code, _, _ = fleetctlRun(t, all, "promote", "-repo", dir, "-release", "v0.2.0", "-digest", d2); code != 1 {
		t.Errorf("promote over an existing branch: %d", code)
	}
	// The canary ring before vendor-1 runs v0.2.0: stopped by a gate (3).
	code, _, errs = fleetctlRun(t, all, "promote", "-repo", dir, "-release", "v0.2.0", "-digest", d2, "-ring", "canary")
	if code != 3 || !strings.Contains(errs, "rollout stopped at vendor-1: pin gate") {
		t.Errorf("canary too early %d: %s", code, errs)
	}
	if code, _, _ = fleetctlRun(t, all, "promote", "-repo", dir, "-release", "v0.2.0", "-digest", d1, "-fleet-json", fleetJSON); code != 1 {
		t.Error("-digest disagreeing with fleet.json accepted")
	}

	// The bot's check before merging vendor-1's branch (always open).
	code, out, errs = fleetctlRun(t, all, "merge-check", "-repo", dir, "-branch", "fleet/promote/v0.2.0/vendor-1")
	if code != 0 || !strings.Contains(out, "may merge now") {
		t.Errorf("merge-check %d: %s %s", code, out, errs)
	}

	// Merged: canary follows once vendor-1 is healthy on v0.2.0.
	git(t, dir, "merge", "-q", "--ff-only", "fleet/promote/v0.2.0/vendor-1")
	all.on["vendor-1"] = v02
	code, out, errs = fleetctlRun(t, all, "promote", "-repo", dir, "-release", "v0.2.0", "-digest", d2)
	if code != 0 || !strings.Contains(out, "gates passed: vendor-1") || !strings.Contains(out, "canary-2: branch") {
		t.Errorf("canary %d: %s %s", code, out, errs)
	}
	// An SLO alert on vendor-1 stops canary's merge.
	burning := healthy{on: all.on, alerts: []string{"ApiAvailabilityBudgetBurn (gateway)"}}
	code, _, errs = fleetctlRun(t, burning, "merge-check", "-repo", dir, "-branch", "fleet/promote/v0.2.0/canary-1")
	if code != 3 || !strings.Contains(errs, "slo gate") {
		t.Errorf("merge-check with an alert %d: %s", code, errs)
	}

	// vendor-1 fails: roll it back to v0.1.0.
	code, out, errs = fleetctlRun(t, all, "rollback", "-repo", dir, "-instance", "vendor-1")
	if code != 0 || !strings.Contains(out, "fleet/rollback/v0.2.0/vendor-1") {
		t.Fatalf("rollback %d: %s %s", code, out, errs)
	}
	show := git(t, dir, "show", "fleet/rollback/v0.2.0/vendor-1:instances/vendor-1/kustomization.yaml")
	if !strings.Contains(show, "tag: v0.1.0, digest: \""+d1+"\"") {
		t.Errorf("rollback pin:\n%s", show)
	}
	if code, _, _ = fleetctlRun(t, all, "rollback", "-repo", dir, "-ring", "general"); code != 1 {
		t.Error("general rolled back without previous releases")
	}

	for _, args := range [][]string{{}, {"nope"}, {"status"}, {"rollback", "-repo", dir}, {"merge-check", "-repo", dir}, {"status", "-repo", dir, "extra"}} {
		if code, _, _ := fleetctlRun(t, all, args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return string(out)
}

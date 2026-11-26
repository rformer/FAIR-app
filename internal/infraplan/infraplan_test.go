package infraplan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func plan(t *testing.T, js string) *Plan {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(p, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	pl, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

const twoChanges = `{"format_version":"1.2","resource_changes":[
 {"address":"b.x","mode":"managed","change":{"actions":["update"]}},
 {"address":"a.x","mode":"managed","change":{"actions":["create"]}},
 {"address":"c.x","mode":"managed","change":{"actions":["no-op"]}},
 {"address":"data.d.x","mode":"data","change":{"actions":["read"]}}]}`

// The digest names the changes, not their order or the unchanged.
func TestDigestIsTheChanges(t *testing.T) {
	a := plan(t, twoChanges)
	b := plan(t, `{"format_version":"1.2","resource_changes":[
 {"address":"a.x","mode":"managed","change":{"actions":["create"]}},
 {"address":"b.x","mode":"managed","change":{"actions":["update"]}}]}`)
	if a.Digest() != b.Digest() {
		t.Errorf("same changes, different digests: %s %s", a.Digest(), b.Digest())
	}
	c := plan(t, `{"format_version":"1.2","resource_changes":[
 {"address":"a.x","mode":"managed","change":{"actions":["create"]}},
 {"address":"b.x","mode":"managed","change":{"actions":["delete","create"]}}]}`)
	if a.Digest() == c.Digest() {
		t.Error("an update and a replace have the same digest")
	}
	if got := a.Changes(); len(got) != 2 || got[0].Address != "a.x" || got[1].Action != "update" {
		t.Errorf("changes %v", got)
	}
}

func TestCreateOnly(t *testing.T) {
	if err := plan(t, `{"format_version":"1.2","resource_changes":[{"address":"a.x","mode":"managed","change":{"actions":["create"]}}]}`).CreateOnly(); err != nil {
		t.Error(err)
	}
	err := plan(t, twoChanges).CreateOnly()
	if err == nil || !strings.Contains(err.Error(), "update b.x") {
		t.Errorf("an update in a first plan: %v", err)
	}
}

func TestSummary(t *testing.T) {
	s := plan(t, twoChanges).Summary("example: instance")
	for _, want := range []string{"### example: instance", "1 to create, 1 to update, 0 to replace, 0 to delete.", "| create | `a.x` |", "Digest of the changes: `"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "c.x") {
		t.Error("unchanged resources listed")
	}
}

func TestLoadRefusesOtherJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(p, []byte(`{"resource_changes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("a file without format_version read as a plan")
	}
}

// The drift job's decision over the recorded runs (the CI dry run).
func TestDryRun(t *testing.T) {
	var out bytes.Buffer
	if err := DryRun(filepath.Join("testdata", "drift"), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"== clean: clean", "== drifted: drift", "== errored: error", "== outside-only: clean", "== deletes-a-store: drift"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q", want)
		}
	}
}

// A wrong expectation fails the dry run (it checks, not just prints).
func TestDryRunFailsOnAWrongVerdict(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("testdata", "drift", "drifted")
	if err := os.CopyFS(filepath.Join(dir, "drifted"), os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "drifted", "expect"), []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DryRun(dir, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "verdict drift, want clean") {
		t.Errorf("a wrong verdict passed: %v", err)
	}
}

func TestOnlyTheDriftedInTheIssue(t *testing.T) {
	rs, err := ReadDrift(filepath.Join("testdata", "drift", "drifted", "plans"))
	if err != nil {
		t.Fatal(err)
	}
	body := IssueBody(rs, "")
	if strings.Contains(body, "## other") {
		t.Errorf("a clean instance in the issue:\n%s", body)
	}
	if Overall(rs) != Drift {
		t.Errorf("overall %s", Overall(rs))
	}
}

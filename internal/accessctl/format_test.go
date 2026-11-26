package accessctl

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var repoRoot = filepath.Join("..", "..")

func testDir(t *testing.T) *Dir {
	t.Helper()
	d, err := Load(filepath.Join("testdata", "access"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// copyDir copies the test access directory so a test can change one file.
func copyDir(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", "access")
	err := filepath.WalkDir(src, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- test files
		if err != nil {
			return err
		}
		// One form whatever the checkout's line endings.
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600) // #nosec G703 -- test files
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestLoad(t *testing.T) {
	d := testDir(t)
	if len(d.Requests) != 4 || len(d.Operators) != 3 || len(d.Instances) != 2 {
		t.Fatalf("loaded %d requests, %d operators, %d instances", len(d.Requests), len(d.Operators), len(d.Instances))
	}
	r := d.Requests["globex-check-0040"]
	s, e := r.Window()
	if !s.Equal(at("2026-11-25T08:00:00Z")) || !e.Equal(at("2026-11-25T09:30:00Z")) {
		t.Errorf("window %s to %s", s, e)
	}
	rv := d.Requests["globex-revoked-0041"]
	if !rv.Expires().Equal(at("2026-11-26T09:30:00Z")) || rv.ActiveAt(at("2026-11-26T09:30:00Z")) || !rv.ActiveAt(at("2026-11-26T09:29:59Z")) {
		t.Errorf("a revocation ends the window: %s", rv.Expires())
	}
	if got := d.Active(at("2026-11-26T11:30:00Z"), "acme", RoleOperator); len(got) != 2 {
		t.Errorf("active: %v", got)
	}
}

const valid = `format: fair.access-request.v1
operator: alice
approver: bob
instance: acme
role: operator
reason: Restart the risk service after the engine certificate rotation
ticket: OPS-42
start: 2026-11-26T10:00:00Z
duration: 4h
`

// F-012 T-18 (F-012-AC-27; design §3.9): every rule of a request: the
// schema, at most 8 hours, a second operator as approver, known names.
func TestRequestRules(t *testing.T) {
	for _, c := range []struct{ name, edit, want string }{
		{"valid", "", ""},
		{"too long", "duration: 4h=>duration: 9h", "duration"},
		{"too long in minutes", "duration: 4h=>duration: 481m", "at most 8h0m0s"},
		{"zero", "duration: 4h=>duration: 0m", "duration"},
		{"seconds", "duration: 4h=>duration: 30s", "duration"},
		{"self-approved", "approver: bob=>approver: alice", "a second operator"},
		{"unknown approver", "approver: bob=>approver: mallory", `approver "mallory" is not in operators.yaml`},
		{"unknown operator", "operator: alice=>operator: mallory", `operator "mallory" is not in operators.yaml`},
		{"unknown instance", "instance: acme=>instance: initech", `instance "initech" is not in instances.yaml`},
		{"admin role", "role: operator=>role: admin", "role"},
		{"no ticket", "ticket: OPS-42\n=>", "ticket"},
		{"bad ticket", "ticket: OPS-42=>ticket: whatever", "ticket"},
		{"short reason", "reason: Restart the risk service after the engine certificate rotation=>reason: because", "reason"},
		{"no approver", "approver: bob\n=>", "approver"},
		{"local time", "start: 2026-11-26T10:00:00Z=>start: 2026-11-26T05:00:00-05:00", "start"},
		{"extra field", "duration: 4h=>duration: 4h\npermissions: AdministratorAccess", "permissions"},
		{"wrong format", "format: fair.access-request.v1=>format: fair.access-request.v2", "format"},
		{"unknown revoker", "duration: 4h=>duration: 4h\nrevoked: {at: 2026-11-26T11:00:00Z, by: mallory, reason: Not needed any longer at all}", `revoked.by "mallory"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := copyDir(t)
			text := valid
			if c.edit != "" {
				from, to, _ := strings.Cut(c.edit, "=>")
				if !strings.Contains(text, from) {
					t.Fatalf("edit %q does not apply", from)
				}
				text = strings.Replace(text, from, to, 1)
			}
			if err := os.WriteFile(filepath.Join(dir, "requests", "acme-new-0050.yaml"), []byte(text), 0o600); err != nil { // #nosec G703 -- test files
				t.Fatal(err)
			}
			_, err := Load(dir)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want an error with %q", err, c.want)
			case c.want != "" && !strings.Contains(err.Error(), "acme-new-0050.yaml"):
				t.Errorf("the error names no file: %v", err)
			}
		})
	}
}

func TestDirectoryRules(t *testing.T) {
	for _, c := range []struct{ file, from, to, want string }{
		{"operators.yaml", "github: bob-ops", "github: Alice-Ops", "one person, one entry"},
		{"operators.yaml", "user_id: 9067a1b2c3-22222222-2222-2222-2222-222222222222", "user_id: 9067a1b2c3-11111111-1111-1111-1111-111111111111", "one person, one entry"},
		{"operators.yaml", "name: carol", "name: alice", "alice is listed twice"},
		{"instances.yaml", `account_id: "888888888888"`, `account_id: "777777777777"`, "one account per instance"},
		{"instances.yaml", "region: us-gov-west-1\n    cluster: fair-globex", "region: us-east-1\n    cluster: fair-globex", "not a GovCloud region"},
		{"controller.yaml", "partition: aws-us-gov", "partition: aws", "GovCloud"},
		{"controller.yaml", "name: FairOperator", "name: FairReadOnly", "used twice"},
		{"controller.yaml", "permissionSet/ssoins-7907a1b2c3d4e5f6/ps-8293", "permissionSet/ssoins-0000000000000000/ps-8293", "not a permission set of"},
	} {
		dir := copyDir(t)
		p := filepath.Join(dir, c.file)
		b, _ := os.ReadFile(p) // #nosec G304 -- test files
		if !bytes.Contains(b, []byte(c.from)) {
			t.Fatalf("%s: %q not found", c.file, c.from)
		}
		if err := os.WriteFile(p, bytes.Replace(b, []byte(c.from), []byte(c.to), 1), 0o600); err != nil { // #nosec G703 -- test files
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q: %v, want %q", c.file, c.to, err, c.want)
		}
	}
	dir := copyDir(t)
	if err := os.WriteFile(filepath.Join(dir, "requests", "x.yml"), []byte(valid), 0o600); err != nil { // #nosec G703 -- test files
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "requests are <id>.yaml") {
		t.Errorf("%v", err)
	}
}

// A merged request is a record: it stays, and only a revocation may be
// added to it.
func TestCheckChanges(t *testing.T) {
	base := testDir(t)
	edit := func(id, from, to string) error {
		t.Helper()
		dir := copyDir(t)
		p := filepath.Join(dir, "requests", id+".yaml")
		if from == "" {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		} else {
			b, _ := os.ReadFile(p) // #nosec G304 -- test files
			if !bytes.Contains(b, []byte(from)) {
				t.Fatalf("%q not in %s", from, id)
			}
			if err := os.WriteFile(p, bytes.Replace(b, []byte(from), []byte(to), 1), 0o600); err != nil { // #nosec G703 -- test files
				t.Fatal(err)
			}
		}
		head, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return CheckChanges(base, head)
	}
	if err := CheckChanges(base, testDir(t)); err != nil {
		t.Errorf("unchanged: %v", err)
	}
	if err := edit("acme-incident-0042", "duration: 4h", "duration: 4h\nrevoked: {at: 2026-11-26T12:00:00Z, by: bob, reason: The incident is closed early}"); err != nil {
		t.Errorf("adding a revocation: %v", err)
	}
	for _, c := range []struct{ id, from, to, want string }{
		{"acme-incident-0042", "", "", "stays"},
		{"acme-incident-0042", "duration: 4h", "duration: 8h", "may not change"},
		{"acme-incident-0042", "start: 2026-11-26T10:00:00Z", "start: 2026-11-26T12:00:00Z", "may not change"},
		{"acme-incident-0042", "approver: bob", "approver: carol", "may not change"},
		{"globex-revoked-0041", "at: 2026-11-26T09:30:00Z", "at: 2026-11-26T16:30:00Z", "revocation may not change"},
	} {
		if err := edit(c.id, c.from, c.to); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q -> %q: %v, want %q", c.id, c.from, c.to, err, c.want)
		}
	}
}

// The fleet template's access directory loads, and its schema is this
// package's.
func TestFleetTemplate(t *testing.T) {
	dir := filepath.Join(repoRoot, "deploy", "fleet", "access")
	b, err := os.ReadFile(filepath.Join(dir, "request.schema.json")) // #nosec G304 -- test files
	if err != nil {
		t.Fatal(err)
	}
	if crlf := []byte("\r\n"); !bytes.Equal(bytes.ReplaceAll(b, crlf, []byte("\n")), bytes.ReplaceAll(RequestSchema, crlf, []byte("\n"))) {
		t.Error("deploy/fleet/access/request.schema.json differs from internal/accessctl/request.schema.json: copy it")
	}
	d, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Requests) == 0 {
		t.Error("the template has no example request")
	}
	for _, r := range d.Requests {
		if r.ActiveAt(time.Now()) {
			t.Errorf("the template's example %s is active", r.ID)
		}
	}
}

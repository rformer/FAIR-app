package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "formats", name)) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validateAgainst(t *testing.T, s *jsonschema.Schema, name, doc string) map[string]any {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, doc)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("does not match %s: %v\n%s", name, err, doc)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(doc), &m)
	return m
}

// decisionsFile writes the documented example decisions file, changed by
// the replacer.
func decisionsFile(t *testing.T, r *strings.Replacer) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "formats", "fair-install-decisions-v1.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)## Example\\s*```yaml\\n(.*?)```").FindSubmatch(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	if m == nil {
		t.Fatal("no example decisions")
	}
	doc := string(m[1])
	if r != nil {
		doc = r.Replace(doc)
	}
	p := filepath.Join(t.TempDir(), "decisions.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil { // #nosec G703 -- a test file in t.TempDir()
		t.Fatal(err)
	}
	return p
}

// validArgs returns arguments a planned command accepts.
func validArgs(t *testing.T, c command, decisions string) []string {
	t.Helper()
	var args []string
	for _, f := range []string{"package", "registry", "to", "backup", "installation", "confirm"} {
		if strings.Contains(c.args, "-"+f+" ") && !strings.Contains(c.args, "["+"-"+f) {
			args = append(args, "-"+f, "id-1")
		}
	}
	if strings.Contains(c.args, "(-decisions FILE | -interactive)") {
		args = append(args, "-decisions", decisions)
	}
	words := strings.Fields(c.args)
	for i, w := range words {
		if (w == "FILE" || w == "ID") && (i == 0 || !strings.Contains(words[i-1], "-")) {
			args = append(args, "x")
		}
	}
	return args
}

// F-014 T-12 (AC-54; design §3.4): every command's output, successes and
// failures alike, is plain text with no escape sequence by default, colour
// only with -color and never with NO_COLOR, and with -output json exactly
// one document matching its schema; exit codes as documented.
func TestFairctlOutput(t *testing.T) {
	errSchema := compileSchema(t, "fairctl-error.schema.json")
	verSchema := compileSchema(t, "fairctl-version.schema.json")
	verifySchema := compileSchema(t, "fairctl-verify.schema.json")
	decisions := decisionsFile(t, nil)
	noColor := map[string]string{"NO_COLOR": "1"}

	errorDoc := func(t *testing.T, r result, code int, errCode string) map[string]any {
		t.Helper()
		noEscapes(t, r)
		if r.code != code || r.stderr != "" {
			t.Fatalf("exit %d (want %d), stderr %q", r.code, code, r.stderr)
		}
		m := validateAgainst(t, errSchema, "fairctl-error.schema.json", r.stdout)
		if got := m["error"].(map[string]any)["code"]; got != errCode || m["exit_code"] != float64(code) {
			t.Fatalf("error %v, exit_code %v; want %s, %d", got, m["exit_code"], errCode, code)
		}
		return m
	}

	for _, c := range commands {
		if c.name == "verify" || c.name == "version" || c.name == "preflight" { // their own tests
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			name := strings.Fields(c.name)
			valid := validArgs(t, c, decisions)
			with := func(flags ...string) []string { // flags before the positional arguments
				return append(append(append([]string{}, name...), flags...), valid...)
			}
			// Not in this build: says so, exit 2, never success.
			for _, vars := range []map[string]string{nil, noColor} {
				r := fairctl(t, vars, with("-color")...)
				noEscapes(t, r)
				if r.code != exitUsage || r.stdout != "" || r.stderr != "fairctl "+c.name+": "+c.name+" is not yet available in this build\n" {
					t.Fatalf("exit %d\nstdout %q\nstderr %q", r.code, r.stdout, r.stderr)
				}
			}
			m := errorDoc(t, fairctl(t, nil, with("-output", "json")...), exitUsage, "not_available")
			if m["command"] != c.name {
				t.Fatalf("command %v", m["command"])
			}
			// Usage errors, in text and JSON.
			r := fairctl(t, nil, with("-no-such-flag")...)
			noEscapes(t, r)
			if r.code != exitUsage || !strings.Contains(r.stderr, "flag provided but not defined") {
				t.Fatalf("unknown flag: %d %q", r.code, r.stderr)
			}
			errorDoc(t, fairctl(t, nil, with("-output=json", "-no-such-flag")...), exitUsage, "usage")
			errorDoc(t, fairctl(t, nil, append(with("-output", "json"), "extra", "arguments")...), exitUsage, "usage")
			if r := fairctl(t, nil, append(name, "-output", "yaml")...); r.code != exitUsage {
				t.Fatalf("-output yaml: %d", r.code)
			}
			if r := fairctl(t, nil, append(name, "-h")...); r.code != exitOK || !strings.Contains(r.stdout, "usage: fairctl "+c.name) {
				t.Fatalf("-h: %d %q", r.code, r.stdout)
			} else {
				noEscapes(t, r)
			}
		})
	}

	t.Run("required flags", func(t *testing.T) {
		for _, args := range [][]string{
			{"install", "-decisions", decisions},
			{"install", "-package", "p"},
			{"install", "-package", "p", "-decisions", decisions, "-interactive"},
			{"upgrade"},
			{"registry", "load", "-package", "p"},
			{"restore"},
			{"license", "install"},
			{"decommission", "destroy", "-installation", "a", "-confirm", "b"},
		} {
			r := fairctl(t, nil, args...)
			noEscapes(t, r)
			if r.code != exitUsage || strings.Contains(r.stderr, "not yet available") {
				t.Errorf("%v: %d %q", args, r.code, r.stderr)
			}
			errorDoc(t, fairctl(t, nil, append(args, "-output", "json")...), exitUsage, "usage")
		}
	})

	t.Run("decisions refused before anything runs", func(t *testing.T) {
		const secret = "hvs.CAESIJ2bW9ja3Rva2VuZm9ydGVzdHMx" // #nosec G101 -- a fake token, refused by the test
		bad := decisionsFile(t, strings.NewReplacer("token_file: secrets/openbao-admin-token", "token_file: "+secret))
		for _, cmd := range [][]string{{"install", "-package", "p", "-decisions", bad}, {"preflight", "-decisions", bad}} {
			r := fairctl(t, nil, cmd...)
			noEscapes(t, r)
			if r.code != exitUsage || !strings.Contains(r.stderr, "looks secret") || !strings.Contains(r.stderr, "key_store.token_file") ||
				strings.Contains(r.stdout+r.stderr, secret) || strings.Contains(r.stderr, "not yet available") {
				t.Fatalf("%v: %d\n%s%s", cmd, r.code, r.stdout, r.stderr)
			}
			m := errorDoc(t, fairctl(t, nil, append(cmd, "-output", "json")...), exitUsage, "invalid_decisions")
			if strings.Contains(fairctl(t, nil, append(cmd, "-output", "json")...).stdout, secret) || len(m["error"].(map[string]any)["problems"].([]any)) == 0 {
				t.Fatalf("%v", m)
			}
		}
		invalid := decisionsFile(t, strings.NewReplacer("mode: self-hosted", "mode: hybrid"))
		r := fairctl(t, nil, "preflight", "-decisions", invalid)
		if r.code != exitUsage || !strings.Contains(r.stderr, "mode: must be") {
			t.Fatalf("%d %q", r.code, r.stderr)
		}
		missing := filepath.Join(t.TempDir(), "none.yaml")
		errorDoc(t, fairctl(t, nil, "preflight", "-output", "json", "-decisions", missing), exitUsage, "invalid_decisions")
	})

	t.Run("unknown commands", func(t *testing.T) {
		for _, args := range [][]string{{"frobnicate"}, {"backup"}, {"backup", "everything"}, {"decommission"}, {"\x1b[31mred"}} {
			r := fairctl(t, nil, args...)
			noEscapes(t, r)
			if r.code != exitUsage {
				t.Errorf("%q: %d", args, r.code)
			}
			errorDoc(t, fairctl(t, nil, append(args, "-output", "json")...), exitUsage, "usage")
		}
		if r := fairctl(t, nil, "backup"); !strings.Contains(r.stderr, "backup run, backup schedule") {
			t.Errorf("%q", r.stderr)
		}
		if r := fairctl(t, nil); r.code != exitUsage || !strings.Contains(r.stderr, "exit codes:") {
			t.Errorf("no command: %d %q", r.code, r.stderr)
		}
	})

	t.Run("help lists every command", func(t *testing.T) {
		r := fairctl(t, nil, "help")
		noEscapes(t, r)
		for _, c := range commands {
			if !strings.Contains(r.stdout, "fairctl "+c.name) {
				t.Errorf("help lacks %s", c.name)
			}
		}
		for _, want := range []string{"registry load", "install remove", "license show", "backup keys", "restore verify", "decommission record", "4 environment unreachable"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("help lacks %q", want)
			}
		}
	})

	t.Run("version", func(t *testing.T) {
		r := fairctl(t, nil, "version", "-output", "json")
		noEscapes(t, r)
		if r.code != exitOK {
			t.Fatal(r.code)
		}
		if m := validateAgainst(t, verSchema, "fairctl-version.schema.json", r.stdout); m["version"] != "dev" {
			t.Fatalf("%v", m)
		}
		errorDoc(t, fairctl(t, nil, "version", "-output", "json", "x"), exitUsage, "usage")
	})

	t.Run("verify", func(t *testing.T) {
		dir, key := testPackage(t)
		for _, vars := range []map[string]string{nil, noColor} {
			args := []string{"verify", "-key", key, dir}
			if vars != nil {
				args = append([]string{"verify", "-color"}, args[1:]...)
			}
			r := fairctl(t, vars, args...)
			noEscapes(t, r)
			if r.code != exitOK {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
		}
		j := fairctl(t, nil, "verify", "-output", "json", "-key", key, dir)
		noEscapes(t, j)
		validateAgainst(t, verifySchema, "fairctl-verify.schema.json", j.stdout)
		// Names from outside (a path with an escape sequence) are printed
		// harmlessly, in text and JSON.
		odd := filepath.Join(t.TempDir(), "pkg\x1b[2J\r")
		r := fairctl(t, nil, "verify", "-key", key, odd)
		noEscapes(t, r)
		if r.code != exitUsage || !strings.Contains(r.stderr, `pkg\x1b[2J\x0d is not a package directory`) {
			t.Fatalf("%d %q", r.code, r.stderr)
		}
		errorDoc(t, fairctl(t, nil, "verify", "-output", "json", "-key", key, odd), exitUsage, "usage")
		errorDoc(t, fairctl(t, nil, "verify", "-output", "json", dir), exitUsage, "usage")
	})
}

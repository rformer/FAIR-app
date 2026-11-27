package installer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rformer/fair-app/pkg/audit"
)

var docs = filepath.Join("..", "..", "docs", "formats")

// exampleDecisions is the example in docs/formats/fair-install-decisions-v1.md.
func exampleDecisions(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docs, "fair-install-decisions-v1.md")) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)## Example\\s*```yaml\\n(.*?)```").FindSubmatch(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	if m == nil {
		t.Fatal("no example in fair-install-decisions-v1.md")
	}
	return string(m[1])
}

func TestDecisionsExample(t *testing.T) {
	doc := exampleDecisions(t)
	d, err := ParseDecisions([]byte(doc))
	if err != nil {
		t.Fatalf("the documented example is refused: %v", err)
	}
	if d.Mode != "self-hosted" || d.IDP.Kind != "oidc" || d.Dependencies.ObjectStore.AuditBucket != "fair-audit" || !d.Dependencies.NATS.Bundled {
		t.Fatalf("%+v", d)
	}
	p := filepath.Join(t.TempDir(), "decisions.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = LoadDecisions(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Path(d.IDP.ClientSecretFile); got != filepath.Join(filepath.Dir(p), "secrets", "oidc-client-secret") {
		t.Fatalf("relative path resolved to %s", got)
	}
}

// F-014 T-12 (AC-14; design §3.4, §7 "I: generated credentials leak"): a
// secret-looking value anywhere in the decisions file refuses the whole
// file before anything runs, naming the field and never the value.
func TestDecisionsRefuseSecrets(t *testing.T) {
	base := exampleDecisions(t)
	const jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlc2lnbmF0dXJl"
	cases := []struct {
		name, old, new, field string
	}{
		{"JWT as the client secret file", "client_secret_file: secrets/oidc-client-secret", "client_secret_file: " + jwt, "idp.client_secret_file"},
		{"inline client secret", "client_secret_file: secrets/oidc-client-secret", "client_secret: s3cr3t-value", "idp.client_secret"},
		{"password field", "admin_password_file: secrets/postgres-admin-password", "admin_password: hunter2hunter2", "dependencies.postgres.admin_password"},
		{"PEM private key", "ca_file: certs/postgres-ca.pem", "ca_file: \"-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEE\\n-----END EC PRIVATE KEY-----\"", "dependencies.postgres.ca_file"},
		{"PEM certificate inline", "ca_file: certs/openbao-ca.pem", "ca_file: |\n    -----BEGIN CERTIFICATE-----\n    MIIBszCCAVmgAwIBAgIU\n    -----END CERTIFICATE-----", "key_store.ca_file"},
		{"vault token", "token_file: secrets/openbao-admin-token", "token_file: hvs.CAESIJ2bW9ja3Rva2VuZm9ydGVzdHMx", "key_store.token_file"},
		{"AWS access key", "access_key_file: secrets/s3-access-key", "access_key_file: AKIAIOSFODNN7EXAMPLE", "dependencies.object_store.access_key_file"},
		{"random secret key", "secret_key_file: secrets/s3-secret-key", "secret_key_file: wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYzz9a8Bc7", "dependencies.object_store.secret_key_file"},
		{"password in a URL", "issuer: https://login.example.com/", "issuer: https://admin:Pa55word@login.example.com/", "idp.issuer"},
		{"bearer in a reason", "reason: The storage class uses KMS-encrypted volumes", "reason: \"use Bearer abcdefghijklmnopqrstuvwxyz012345\"", "attestations.storage_encryption[0].reason"},
		{"token in a list", "domains: [example.com]", "domains: [example.com, " + jwt + "]", "idp.domains[1]"},
		{"secret-looking key", "overrides: []", "overrides: []\n" + jwt + ": x", ""},
		{"GitHub token in the operator", "operator: Jane Admin", "operator: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "operator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(base, tc.old) {
				t.Fatalf("the example has no %q", tc.old)
			}
			doc := strings.Replace(base, tc.old, tc.new, 1)
			_, err := ParseDecisions([]byte(doc))
			var de *DecisionsError
			if !errors.As(err, &de) || !de.Secret {
				t.Fatalf("not refused as a secret: %v", err)
			}
			if tc.field != "" && !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the refusal does not name %s: %v", tc.field, err)
			}
			for _, w := range []string{jwt, "s3cr3t-value", "hunter2hunter2", "MHcCAQEE", "MIIBszCC", "hvs.CAES", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "Pa55word", "abcdefghijklmnopqrstuvwxyz012345", "ghp_"} {
				if strings.Contains(err.Error(), w) {
					t.Errorf("the refusal repeats the value: %v", err)
				}
			}
		})
	}
	// Words, digests, paths and identifiers are not secrets.
	for _, s := range []string{"secrets/oidc-client-secret", "3f5b9c8a6e0d1f2a4b7c9e0d1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2",
		"/etc/fair/keys/postgres-admin-password", "Restricted pod security is enforced cluster-wide", "00u1a2b3c4d5e6f7g8h9", "fedramp-moderate"} {
		if LooksSecret(s) {
			t.Errorf("%q looks secret", s)
		}
	}
}

// Strict decoding and field checks: every problem listed.
func TestDecisionsStrict(t *testing.T) {
	base := exampleDecisions(t)
	for name, tc := range map[string]struct{ old, new, want string }{
		"unknown field":      {"mode: self-hosted", "mode: self-hosted\nflavour: vanilla", "field flavour not found"},
		"format":             {"format: fair.install-decisions.v1", "format: fair.install-decisions.v0", "format"},
		"mode":               {"mode: self-hosted", "mode: hybrid", "mode"},
		"currency":           {"currency: USD", "currency: usd", "currency"},
		"scanner digest":     {"manifest_sha256: 3f5b", "manifest_sha256: zz5b", "scanner.manifest_sha256"},
		"bundled with host":  {"  nats:\n    bundled: true", "  nats:\n    bundled: true\n    url: tls://nats:4222", "dependencies.nats"},
		"brought, no file":   {"    admin_password_file: secrets/postgres-admin-password\n", "", "dependencies.postgres.admin_password_file"},
		"saas override":      {"mode: self-hosted", "mode: saas", ""}, // valid without overrides
		"cidr":               {"ingress_cidr: 10.20.0.0/16", "ingress_cidr: 10.0.0.0/4", "hosts.ingress_cidr"},
		"two documents":      {"overrides: []", "overrides: []\n---\nmode: saas", "more than one YAML document"},
		"alias":              {"profile: fedramp-moderate", "profile: &p fedramp-moderate\ncurrency2: *p", "aliases"},
		"break-glass reason": {"break_glass:\n  enabled: false", "break_glass:\n  enabled: true", "break_glass.reason"},
		"bad http issuer":    {"issuer: https://login.example.com/", "issuer: http://login.example.com/", "idp.issuer"},
	} {
		doc := strings.Replace(base, tc.old, tc.new, 1)
		if doc == base {
			t.Fatalf("%s: the example has no %q", name, tc.old)
		}
		_, err := ParseDecisions([]byte(doc))
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	doc := strings.Replace(base, "overrides: []", "overrides:\n  - check: node_fips\n    subject: node/a\n    reason: lab cluster", 1)
	if _, err := ParseDecisions([]byte(doc)); err != nil {
		t.Errorf("override: %v", err)
	}
	if _, err := ParseDecisions([]byte(strings.Replace(doc, "mode: self-hosted", "mode: saas", 1))); err == nil || !strings.Contains(err.Error(), "SaaS allows no override") {
		t.Errorf("SaaS override: %v", err)
	}
	// Several problems at once, sorted by field.
	_, err := ParseDecisions([]byte(strings.NewReplacer("mode: self-hosted", "mode: x", "currency: USD", "currency: x").Replace(base)))
	var de *DecisionsError
	if !errors.As(err, &de) || len(de.Problems) != 2 || de.Problems[0].Field != "currency" || de.Problems[1].Field != "mode" {
		t.Fatalf("%v", err)
	}
}

func TestProgress(t *testing.T) {
	p := NewProgress()
	if s, _ := p.Next(); s != StepVerify {
		t.Fatal(s)
	}
	if err := p.Set(StepDecisions, StateRunning); err == nil {
		t.Fatal("a step ran before the one before it was done")
	}
	for _, s := range []State{StateRunning, StateFailed, StateRunning, StateDone} {
		if err := p.Set(StepVerify, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Set(StepVerify, StateRunning); err == nil {
		t.Fatal("a done step ran again")
	}
	if err := p.Set(StepDecisions, StateDone); err == nil {
		t.Fatal("done without running")
	}
	if s, _ := p.Next(); s != StepDecisions {
		t.Fatal(s)
	}
	for _, s := range Steps()[1:] {
		if err := p.Set(s, StateRunning); err != nil {
			t.Fatal(err)
		}
		if err := p.Set(s, StateDone); err != nil {
			t.Fatal(err)
		}
	}
	if !p.Done() {
		t.Fatal("not done")
	}
	if err := p.Set("helm", StateRunning); err == nil {
		t.Fatal("unknown step")
	}
}

type fakeCluster struct {
	maps map[string]map[string]string
	fail error
}

func (f *fakeCluster) GetConfigMap(_ context.Context, ns, name string) (map[string]string, bool, error) {
	d, ok := f.maps[ns+"/"+name]
	return d, ok, nil
}

func (f *fakeCluster) ApplyConfigMap(_ context.Context, ns, name string, labels, data map[string]string) error {
	if f.fail != nil {
		return f.fail
	}
	if labels[ManagedByLabel] != ManagedByFairctl {
		return errors.New("unlabelled")
	}
	if f.maps == nil {
		f.maps = map[string]map[string]string{}
	}
	cp := map[string]string{}
	for k, v := range data {
		cp[k] = v
	}
	f.maps[ns+"/"+name] = cp
	return nil
}

func logSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docs, "fair-install-log-v1.schema.json")) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("fair-install-log-v1.schema.json", sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("fair-install-log-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fakeSubmitter struct {
	batches [][]audit.Event
	seen    map[string]bool
}

func (f *fakeSubmitter) SubmitEvents(_ context.Context, events []audit.Event) (int, error) {
	if len(events) > SubmitBatch {
		return 0, errors.New("PF035: events are an array of at most 1,000")
	}
	f.batches = append(f.batches, events)
	n := 0
	for _, e := range events {
		if !f.seen[e.ID] {
			f.seen[e.ID] = true
			n++
		}
	}
	return n, nil
}

// F-014 T-12 (design §3.4): the install log (JSON lines, no secrets,
// events as install.submit_events takes them) and the fair-install
// ConfigMap (step names and states only), through a fake cluster.
func TestInstallLogAndConfigMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), LogFile)
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	cl := &fakeCluster{}
	r := NewRecorder(l, cl, nil)
	ctx := context.Background()
	for _, st := range []State{StateRunning, StateDone} {
		if err := r.Set(ctx, StepVerify, st); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Set(ctx, StepDecisions, StateRunning); err != nil {
		t.Fatal(err)
	}
	actor, err := OperatorActor("Jane Admin")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := l.Event(audit.Event{Type: "install.decision_recorded", Severity: audit.SeverityHigh, Actor: actor, Target: "install:decision",
		Attributes: map[string]string{"key": "mode", "attested": "false"}})
	if err != nil || ev.ID == "" || ev.Time.IsZero() {
		t.Fatalf("%+v %v", ev, err)
	}
	refused := []audit.Event{
		{Type: "setting.changed", Severity: audit.SeverityHigh, Actor: actor},                                                                                                       // not an installer event
		{Type: "install.decision_recorded", Severity: audit.SeverityHigh, Actor: "system:fairctl", Target: "x"},                                                                     // not an operator
		{Type: "install.decision_recorded", Severity: audit.SeverityLow, Actor: actor, Target: "x"},                                                                                 // not in the catalog at low
		{Type: "install.decision_recorded", Severity: audit.SeverityHigh, Actor: actor, Target: "x", Attributes: map[string]string{"key": "Bearer abcdefghijklmnopqrstuvwxyz0123"}}, // secret
	}
	for i, e := range refused {
		if _, err := l.Event(e); err == nil {
			t.Errorf("event %d logged", i)
		}
	}
	if err := l.Step(StepDecisions, State("hunter2")); err == nil {
		t.Error("an unknown state was logged")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("log mode %v", st.Mode().Perm())
	}
	s := logSchema(t)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines:\n%s", len(lines), raw)
	}
	for _, line := range lines {
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(inst); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	// An interrupted write leaves a torn last line: ignored.
	torn := append(append([]byte{}, raw...), []byte(`{"format":"fair.install-log.v1","time":"2026-`)...)
	entries, err := ReadLog(bytes.NewReader(torn))
	if err != nil || len(entries) != 4 {
		t.Fatalf("%d %v", len(entries), err)
	}
	if _, err := ReadLog(strings.NewReader("{\"format\":\"other\"}\n" + string(raw))); err == nil {
		t.Fatal("a foreign line was read")
	}
	p := ProgressOf(entries)
	if p[StepVerify] != StateDone || p[StepDecisions] != StateRunning || p[StepPreflight] != StatePending {
		t.Fatalf("%v", p)
	}
	if next, _ := p.Next(); next != StepDecisions {
		t.Fatalf("resume at %s", next)
	}

	// The ConfigMap: every step and its state, nothing else.
	data := cl.maps[StepNamespace+"/"+StepConfigMap]
	if len(data) != len(Steps()) || data["verify"] != "done" || data["decisions"] != "running" || data["report"] != "pending" {
		t.Fatalf("ConfigMap %v", data)
	}
	got, err := ProgressFromConfigMap(data)
	if err != nil || got[StepDecisions] != StateRunning {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ProgressFromConfigMap(map[string]string{"verify": "done", "admin_password": "x"}); err == nil {
		t.Fatal("a ConfigMap holding a value was read")
	}
	if _, err := ProgressFromConfigMap(map[string]string{"verify": "hunter2"}); err == nil {
		t.Fatal("a ConfigMap holding a value was read")
	}
	// The cluster unreachable: the log still has the step.
	cl.fail = errors.New("connection refused")
	l2, _ := OpenLog(path)
	defer func() { _ = l2.Close() }()
	r2 := NewRecorder(l2, cl, p)
	if err := r2.Set(ctx, StepDecisions, StateDone); err == nil || !strings.Contains(err.Error(), StepConfigMap) {
		t.Fatalf("%v", err)
	}
	if again, _ := os.ReadFile(path); !strings.Contains(string(again), `"step":"decisions","state":"done"`) { // #nosec G304 -- a test file
		t.Fatal("the log was not written first")
	}

	// Replay: batches of at most 1,000, idempotent by id.
	events := EventsOf(entries)
	if len(events) != 1 || events[0].ID != ev.ID || !events[0].Time.Equal(ev.Time) {
		t.Fatalf("%+v", events)
	}
	var many []audit.Event
	for range 2500 {
		e, err := CheckEvent(audit.Event{Type: "install.decision_recorded", Severity: audit.SeverityHigh, Actor: actor, Target: "install:decision"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		many = append(many, e)
	}
	sub := &fakeSubmitter{seen: map[string]bool{}}
	if n, err := Replay(ctx, sub, many); err != nil || n != 2500 || len(sub.batches) != 3 || len(sub.batches[2]) != 500 {
		t.Fatalf("%d %v %d", n, err, len(sub.batches))
	}
	if n, err := Replay(ctx, sub, many); err != nil || n != 0 {
		t.Fatalf("replay again recorded %d: %v", n, err)
	}
	if _, err := Replay(ctx, sub, []audit.Event{{ID: "x", Time: time.Now(), Type: "install.decision_recorded", Actor: "u1"}}); err == nil {
		t.Fatal("a non-operator event replayed")
	}
}

func TestOutput(t *testing.T) {
	var out, errs bytes.Buffer
	o := &Output{Stdout: &out, Stderr: &errs}
	o.Fact("package", "fair\x1b[2J-v1\r\b")
	o.Result(true, "checked")
	if got := out.String(); got != "package: fair\\x1b[2J-v1\\x0d\\x08\nok: checked\n" {
		t.Fatalf("%q", got)
	}
	o.Color = true
	out.Reset()
	o.Result(false, "refused")
	if out.String() != "\x1b[31mFAIL\x1b[0m: refused\n" {
		t.Fatalf("%q", out.String())
	}
	in := bufio.NewReader(strings.NewReader("maybe\n\nyes\n"))
	errs.Reset()
	a, err := o.Prompt(in, "Proceed?", []string{"yes", "no"}, "")
	if err != nil || a != "yes" || !strings.Contains(errs.String(), "Proceed? [yes/no]: ") || !strings.Contains(errs.String(), "answer one of: yes, no") {
		t.Fatalf("%q %v %q", a, err, errs.String())
	}
	a, err = o.Prompt(bufio.NewReader(strings.NewReader("\n")), "Proceed?", []string{"yes", "no"}, "no")
	if err != nil || a != "no" {
		t.Fatalf("default: %q %v", a, err)
	}
	if _, err := o.Prompt(bufio.NewReader(strings.NewReader("")), "Proceed?", []string{"yes", "no"}, "no"); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("EOF: %v", err)
	}
}

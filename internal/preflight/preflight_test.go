package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

// fixtureManifest is the fixtures' release manifest: their images and the
// RBAC of deploy/k8s (verified already, as fairctl verifies the package).
func fixtureManifest(t *testing.T) *releasemanifest.Manifest {
	t.Helper()
	rbac, err := releasemanifest.RBACFromDir(filepath.Join(root, "deploy/k8s"))
	if err != nil {
		t.Fatal(err)
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "1.0.0", RBAC: rbac, Images: fixtureImages}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

var fixtureScope = scanner.Scope{Namespaces: []string{"fair-platform"}, ProbeNamespace: "fair-fips-probe"}

// key is a finding or observation as compared: every field, the detail
// normalized (keys sorted).
func key(check, severity, subject string, controls []string, detail, remediation string) string {
	var v any
	if err := json.Unmarshal([]byte(detail), &v); err != nil {
		return "bad detail " + detail
	}
	b, _ := json.Marshal(v)
	return strings.Join([]string{check, severity, subject, strings.Join(controls, ","), string(b), remediation}, " | ")
}

// drift is what the drift scanner reports over the cluster with the
// release applied: scanner.ScanOnce over the objects, the catalog of
// checks.Catalog.
func drift(t *testing.T, cluster *objreader.Set, cfg checks.Config) (findings, observations []string) {
	t.Helper()
	var got *posturev1.ScanReport
	s := &scanner.Scanner{Reader: cluster, Checks: checks.Catalog(cfg), Scope: fixtureScope, Instance: "test",
		Report: func(_ context.Context, r *posturev1.ScanReport) error { got = r; return nil }}
	if _, err := s.ScanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range got.CheckErrors {
		t.Errorf("drift: check error %s: %s", e.CheckId, e.Error)
	}
	for _, f := range got.Findings {
		findings = append(findings, key(f.CheckId, f.Severity, f.Subject, f.Controls, f.DetailJson, f.Remediation))
	}
	for _, o := range got.Observations {
		observations = append(observations, key(o.CheckId, o.Method, o.Subject, nil, o.DetailJson, ""))
	}
	slices.Sort(findings)
	slices.Sort(observations)
	return findings, observations
}

func reportKeys(r *Report) (findings, observations []string) {
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			findings = append(findings, key(c.ID, f.Severity, f.Subject, f.Controls, string(f.Detail), f.Remediation))
		}
		for _, o := range c.Observations {
			observations = append(observations, key(c.ID, o.Method, o.Subject, nil, string(o.Detail), ""))
		}
	}
	slices.Sort(findings)
	slices.Sort(observations)
	return findings, observations
}

// TestPreflightMatchesDrift (F-014 AC-18; design §3.7): over every
// distribution fixture, pass and fail, the preflight over a cluster
// without the platform plus the release's objects finds exactly what the
// drift scanner finds over the cluster with the release applied: the same
// checks, subjects, severities, controls, details and remediation, and the
// same observations. The cluster is read through the kube client from a
// recording API server, which sees only GET lists (AC-21).
func TestPreflightMatchesDrift(t *testing.T) {
	manifest := fixtureManifest(t)
	for _, d := range distributions {
		for _, variant := range []string{"pass", "fail"} {
			t.Run(d.name+"/"+variant, func(t *testing.T) {
				f := loadFixture(t, d.name, variant)
				applied, err := objreader.Applied(f.all)
				if err != nil {
					t.Fatal(err)
				}
				cfg := checks.Config{PSADefault: d.psaDefault, Manifest: manifest, Dial: routes(t, applied)}
				wantF, wantO := drift(t, set(t, applied, f.notServed), cfg)
				if variant == "pass" && len(wantF) != 0 {
					t.Fatalf("the pass fixture has drift findings: %v", wantF)
				}
				if variant == "fail" {
					seen := map[string]bool{}
					for _, k := range wantF {
						id, _, _ := strings.Cut(k, " | ")
						seen[id] = true
					}
					for _, m := range checks.Metas() {
						if !seen[m.ID] {
							t.Errorf("the fail fixture has no %s finding", m.ID)
						}
					}
				}

				var cluster, release []map[string]any
				for _, o := range f.all {
					if platform(o) {
						release = append(release, o)
					} else {
						cluster = append(cluster, o)
					}
				}
				if len(cluster) == 0 || len(release) == 0 {
					t.Fatalf("the split is empty: %d cluster, %d release objects", len(cluster), len(release))
				}
				for name, c := range map[string]struct{ live, release []map[string]any }{
					"cluster without the platform plus the release": {cluster, release},
					"empty cluster plus the fixture":                {nil, f.all},
					"installed (nothing to apply)":                  {applied, nil},
				} {
					t.Run(name, func(t *testing.T) {
						api := newAPIServer(t, set(t, c.live, f.notServed))
						rep, err := Run(context.Background(), Options{Live: api.client(t), Objects: c.release, Config: cfg, Scope: fixtureScope,
							Release: manifest.Release, Purpose: PurposeCheck, Mode: ModeSelfHosted, Profile: "enterprise-baseline"})
						if err != nil {
							t.Fatal(err)
						}
						gotF, gotO := reportKeys(rep)
						if !slices.Equal(gotF, wantF) {
							t.Errorf("findings differ\npreflight:\n  %s\ndrift:\n  %s", strings.Join(gotF, "\n  "), strings.Join(wantF, "\n  "))
						}
						if !slices.Equal(gotO, wantO) {
							t.Errorf("observations differ\npreflight: %v\ndrift: %v", gotO, wantO)
						}
						for _, ch := range rep.Checks {
							if ch.Result == ResultError {
								t.Errorf("%s could not run: %s", ch.ID, ch.Error)
							}
						}
						want := Passed
						if variant == "fail" {
							want = Refused
						}
						if rep.Result != want {
							t.Errorf("result %s, want %s", rep.Result, want)
						}
						api.readOnly(t)
					})
				}
			})
		}
	}
}

// A preflight run issues no write: through the kube client to a recording
// API server, every request is a GET list (AC-21), and Secrets are never
// asked for; a server refusing every read leaves checks failed, never
// passed.
func TestPreflightReadOnly(t *testing.T) {
	f := loadFixture(t, "kind", "fail")
	api := newAPIServer(t, set(t, nil, f.notServed))
	rep, err := Run(context.Background(), Options{Live: api.client(t), Objects: f.all, Scope: fixtureScope,
		Config:  checks.Config{Manifest: fixtureManifest(t), Dial: func(context.Context, string) (net.Conn, error) { return nil, errors.New("no route") }},
		Release: "1.0.0", Purpose: PurposeCheck, Mode: ModeSelfHosted, Profile: "fedramp-moderate"})
	if err != nil {
		t.Fatal(err)
	}
	api.readOnly(t)
	for _, r := range api.requests() {
		if !strings.Contains(r, "limit=500") {
			t.Errorf("not a list: %s", r)
		}
	}
	if rep.Result != Refused {
		t.Fatalf("result %s", rep.Result)
	}

	// Forbidden everywhere: every check reading the cluster is an error.
	deny := newAPIServer(t, set(t, nil, nil))
	deny.srv.Config.Handler = denyAll(deny)
	rep, err = Run(context.Background(), Options{Live: deny.client(t), Scope: fixtureScope, Config: checks.Config{Manifest: fixtureManifest(t)},
		Release: "1.0.0", Purpose: PurposeCheck, Mode: ModeSelfHosted})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result != Refused {
		t.Fatalf("a cluster refusing reads: %s", rep.Result)
	}
	errs := 0
	for _, c := range rep.Checks {
		if c.Result == ResultPassed && c.ID != "tls_endpoints" {
			t.Errorf("%s passed on a cluster refusing every read", c.ID)
		}
		if c.Result == ResultError {
			errs++
		}
	}
	if errs == 0 {
		t.Error("no check error on a cluster refusing every read")
	}
	deny.readOnly(t)
}

func denyAll(a *apiServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.reqs = append(a.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		a.mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}
}

// An unreachable cluster is not a failed check: Run says so (fairctl exits 4).
func TestPreflightUnreachable(t *testing.T) {
	api := newAPIServer(t, objreader.New())
	c := api.client(t)
	api.srv.Close()
	_, err := Run(context.Background(), Options{Live: c, Release: "1.0.0", Purpose: PurposeCheck, Mode: ModeSelfHosted, Scope: fixtureScope})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
}

// The registry is the drift catalog (same identifiers, titles, controls
// and remediation as checks.Metas) followed by the preflight-only checks;
// a preflight-only check runs over the overlay in the modes it names, and
// its findings follow its own hard-floor rule.
func TestRegistry(t *testing.T) {
	metas := checks.Metas()
	reg := Checks()
	if len(reg) < len(metas) {
		t.Fatalf("%d checks", len(reg))
	}
	for i, m := range metas {
		c := reg[i]
		if c.ID != m.ID || c.Title != m.Title || !slices.Equal(c.Controls, m.Controls) || c.Remediation != m.Remediation || c.Source != SourceDrift || c.Anchor == "" || !c.AppliesTo(ModeAirGapped) {
			t.Errorf("registry entry %d %+v, catalog %+v", i, c, m)
		}
	}
	saved := only
	t.Cleanup(func() { only = saved })
	register(Check{ID: "test_only", Title: "a test check", Controls: []string{"CM-6"}, Remediation: "fix it", Modes: []string{ModeAirGapped},
		floor: func(f Finding, _ Context) bool { return f.Subject == "x/floor" },
		run: func(ctx context.Context, in Input) (scanner.Result, error) {
			ns, _, err := in.Reader.List(ctx, kube.Namespaces, "")
			if err != nil {
				return scanner.Result{}, err
			}
			var out []scanner.Finding
			for _, n := range ns {
				out = append(out, scanner.Finding{CheckID: "test_only", Severity: "high", Controls: []string{"CM-6"}, Subject: "x/" + n.Metadata.Name,
					DetailJSON: `{"namespace":"` + n.Metadata.Name + `"}`, Remediation: "fix it"})
			}
			return scanner.Result{Findings: out}, nil
		}})
	for _, bad := range []Check{{ID: "tls_endpoints", run: func(context.Context, Input) (scanner.Result, error) { return scanner.Result{}, nil }}, {ID: "test_only", run: func(context.Context, Input) (scanner.Result, error) { return scanner.Result{}, nil }}, {ID: "no_body"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("register(%s) did not refuse", bad.ID)
				}
			}()
			register(bad)
		}()
	}
	if last := Checks()[len(Checks())-1]; last.ID != "test_only" || last.Source != SourcePreflight || last.AppliesTo(ModeSelfHosted) {
		t.Fatalf("%+v", last)
	}
	objs := []map[string]any{
		{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "floor"}},
		{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "other"}},
	}
	run := func(mode string, ov ...Override) *Report {
		r, err := Run(context.Background(), Options{Live: objreader.New(), Objects: objs, Scope: fixtureScope, Config: checks.Config{Manifest: fixtureManifest(t)},
			Release: "1.0.0", Purpose: PurposeCheck, Mode: mode, Overrides: ov})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, c := range run(ModeSelfHosted).Checks {
		if c.ID == "test_only" && c.Result != ResultNotApplicable {
			t.Errorf("ran outside its modes: %s", c.Result)
		}
	}
	r := run(ModeAirGapped, Override{Check: "test_only", Subject: "x/floor", Reason: "r"})
	for _, c := range r.Checks {
		if c.ID != "test_only" {
			continue
		}
		if len(c.Findings) != 2 || !c.Findings[0].HardFloor || c.Findings[1].HardFloor {
			t.Fatalf("%+v", c.Findings)
		}
	}
	if o := r.Overrides[0]; o.Applied || o.Refusal != "on the hard floor: no override" {
		t.Errorf("an override of a hard-floor finding: %+v", o)
	}
}

// Overrides (design §3.8): an override applies to its check's failed
// findings of its subject that are not on the hard floor; none in SaaS;
// one matching nothing is listed as such. Hard floor by finding (§3.7):
// plaintext or TLS below 1.2, node FIPS under a FedRAMP or CMMC profile,
// plaintext key material.
func TestOverridesAndHardFloor(t *testing.T) {
	f := loadFixture(t, "kind", "fail")
	applied, err := objreader.Applied(f.all)
	if err != nil {
		t.Fatal(err)
	}
	cfg := checks.Config{Manifest: fixtureManifest(t), Dial: routes(t, applied)}
	run := func(mode, profile string, ov []Override) *Report {
		r, err := Run(context.Background(), Options{Live: set(t, nil, f.notServed), Objects: f.all, Config: cfg, Scope: fixtureScope,
			Release: "1.0.0", Purpose: PurposeInstall, Mode: mode, Profile: profile, Overrides: ov})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	floors := map[string]bool{}
	var all []Override
	r := run(ModeSelfHosted, "fedramp-moderate", nil)
	for _, c := range r.Checks {
		for _, fd := range c.Findings {
			if fd.HardFloor {
				floors[c.ID+" "+fd.Subject] = true
			}
			all = append(all, Override{Check: c.ID, Subject: fd.Subject, Reason: "accepted for the test"})
		}
	}
	want := map[string]bool{
		"tls_endpoints endpoint/iam.fair-platform.svc:443":        true, // plaintext
		"tls_endpoints endpoint/posture.fair-platform.svc:9443":   true, // TLS 1.0
		"node_fips node/fair-control-plane":                       true, // FedRAMP profile
		"plaintext_secrets workload/fair-platform/Deployment/iam": true,
	}
	if fmt.Sprint(floors) != fmt.Sprint(want) {
		t.Errorf("hard floor %v, want %v", floors, want)
	}
	if r := run(ModeSelfHosted, "enterprise-baseline", nil); hardFloor(r, "node_fips") {
		t.Error("node FIPS on the floor under the enterprise baseline")
	}
	if r := run(ModeSelfHosted, "some-custom-profile", nil); !hardFloor(r, "node_fips") {
		t.Error("node FIPS off the floor under an unknown profile")
	}

	// Every finding overridden: the floor still refuses.
	r = run(ModeSelfHosted, "fedramp-moderate", append(all, Override{Check: "network_policy", Subject: "namespace/elsewhere", Reason: "r"}))
	if r.Result != Refused {
		t.Fatalf("result %s", r.Result)
	}
	for _, o := range r.Overrides {
		switch {
		case o.Subject == "namespace/elsewhere":
			if o.Applied || o.Refusal != "matches no failed finding" {
				t.Errorf("%+v", o)
			}
		case floors[o.Check+" "+o.Subject]:
			if o.Applied || o.Refusal != "on the hard floor: no override" {
				t.Errorf("%+v", o)
			}
		default:
			if !o.Applied {
				t.Errorf("not applied: %+v", o)
			}
		}
	}
	if got := len(r.Failures()); got != len(floors) {
		t.Errorf("failures %v, want the %d on the floor", r.Failures(), len(floors))
	}

	// Without the floor's failures (enterprise baseline, the floor's
	// subjects fixed by removing them), every other finding overridden
	// passes with overrides.
	var above []Override
	for _, o := range all {
		if !floors[o.Check+" "+o.Subject] {
			above = append(above, o)
		}
	}
	trimmed := fixture{notServed: f.notServed}
	for _, o := range f.all {
		n := str(o, "metadata", "name")
		if o["kind"] == "Service" || (o["kind"] == "Pod" && strings.HasPrefix(n, "iam-")) || o["kind"] == "Node" {
			continue
		}
		trimmed.all = append(trimmed.all, o)
	}
	rr, err := Run(context.Background(), Options{Live: set(t, nil, trimmed.notServed), Objects: trimmed.all, Config: cfg, Scope: fixtureScope,
		Release: "1.0.0", Purpose: PurposeInstall, Mode: ModeSelfHosted, Profile: "fedramp-moderate", Overrides: above})
	if err != nil {
		t.Fatal(err)
	}
	if rr.Result != PassedWithOverrides {
		t.Errorf("result %s, failures %v", rr.Result, rr.Failures())
	}
	if s := run(ModeSaaS, "fedramp-moderate", above); s.Result != Refused || s.Overrides[0].Applied || s.Overrides[0].Refusal != "SaaS allows no override" {
		t.Errorf("SaaS: %s %+v", s.Result, s.Overrides[0])
	}
}

func hardFloor(r *Report, check string) bool {
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if c.ID == check && f.HardFloor {
				return true
			}
		}
	}
	return false
}

func reportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const name = "fair-preflight-report-v1.schema.json"
	b, err := os.ReadFile(filepath.Join(root, "docs/formats", name)) // #nosec G304 -- a test file
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

// The report and its record (design §5, install.preflight): the documented
// schema, a digest of the stored form, run id, times; values that look
// secret redacted in details, and a report still holding one refused.
func TestReportRecord(t *testing.T) {
	f := loadFixture(t, "openshift", "fail")
	applied, err := objreader.Applied(f.all)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	r, err := Run(context.Background(), Options{Live: set(t, nil, f.notServed), Objects: f.all, Scope: fixtureScope,
		Config:  checks.Config{Manifest: fixtureManifest(t), Dial: routes(t, applied)},
		Release: "1.0.0", Purpose: PurposeUpgrade, Mode: ModeSelfHosted, Profile: "cmmc-l2-r2", Now: func() time.Time { return now },
		Overrides: []Override{{Check: "storage_encryption", Subject: "storageclass/gp2-csi", Reason: "encrypted by the array"}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.Record(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.RunID) != 36 || rec.RunID[14] != '4' || len(rec.Digest) != 64 || rec.Result != Refused || rec.Purpose != PurposeUpgrade || !rec.Started.Equal(now) {
		t.Fatalf("%+v", rec)
	}
	again, _ := r.Record(id)
	if again.Digest != rec.Digest {
		t.Error("the digest is not stable")
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(rec.Report))
	if err != nil {
		t.Fatal(err)
	}
	if err := reportSchema(t).Validate(inst); err != nil {
		t.Fatalf("the report does not match its schema: %v\n%s", err, rec.Report)
	}
	if !strings.Contains(string(rec.Report), `"applied":true`) {
		t.Errorf("the override is not reported applied: %s", rec.Report)
	}

	// A detail value that looks secret is redacted when the report is built.
	const token = "ghp_0123456789abcdefghijABCDEFGHIJ0123456789" // #nosec G101 -- a fake token, redacted by the test
	var cr CheckResult
	cr.fill(Check{ID: "x"}, scanner.Result{Findings: []scanner.Finding{{Subject: "s", Severity: "low", DetailJSON: `{"value":"` + token + `","n":3}`}}}, nil, Context{})
	if d := string(cr.Findings[0].Detail); strings.Contains(d, token) || !strings.Contains(d, Redacted) || !strings.Contains(d, `"n":3`) {
		t.Errorf("detail %s", d)
	}
	r.Checks[0].Findings = append(r.Checks[0].Findings, Finding{Subject: "s", Detail: json.RawMessage(`{"v":"` + token + `"}`)})
	if _, err := r.Record(id); !errors.Is(err, ErrSecret) {
		t.Errorf("a report with a secret was recorded: %v", err)
	}
}

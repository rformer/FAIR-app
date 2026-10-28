package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-015 T-33 (AC-45, AC-48): the Assessment Results export from a real
// posture: it validates against the pinned OSCAL schema, carries the
// effective settings, drift findings and Not assessed checks, and the same
// as_of gives the same bytes.
func TestAssessmentResultsExport(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t) // FedRAMP Moderate, Kubernetes access granted
	e := se.e

	// Application drift: a direct edit outside the bounds.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	se.scan(t)
	// Deployment drift and evidence: two checks run, the rest do not.
	fips := &staticCheck{id: posture.CheckNodeFIPS, observations: []scanner.Observation{
		{Subject: "node/a", Method: "verified", DetailJSON: `{"probe_pod":"fips-probe-x"}`},
		{Subject: "node/b", Method: "attested", DetailJSON: `{"label":"fair-platform.io/fips=attested"}`}}}
	hardening := &staticCheck{id: "pod_hardening", findings: []scanner.Finding{{CheckID: "pod_hardening", Severity: "high",
		Controls: []string{"CM-7"}, Subject: "deployment:fair/iam", DetailJSON: `{"container":"iam"}`, Remediation: "Run as non-root."}}}
	sc := &scanner.Scanner{Reader: fakeReader{}, Checks: []scanner.Check{fips, hardening}, Instance: "s-0", Report: se.report}
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}

	load := func() posture.ARSnapshot {
		t.Helper()
		s, err := posture.LoadARSnapshot(ctx, e.posturePool())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	export := func(s posture.ARSnapshot) ([]byte, *oscal.AssessmentResultsModel) {
		t.Helper()
		b, err := posture.ExportAssessmentResults(s)
		if err != nil {
			t.Fatal(err)
		}
		doc, kind, err := oscal.Parse(b)
		if err != nil || kind != oscal.AssessmentResults {
			t.Fatalf("not valid Assessment Results: %v %v", kind, err)
		}
		return b, doc.AssessmentResults
	}

	s1 := load()
	b1, ar := export(s1)
	r := ar.Results[0]
	props := func(ps *[]oscal.Property, name string) []string {
		var out []string
		if ps != nil {
			for _, p := range *ps {
				if p.Name == name {
					out = append(out, p.Value)
				}
			}
		}
		return out
	}

	// Observations: every setting (each of its parameters), with the effective value.
	var defs int
	if err := e.posturePool().QueryRow(ctx, "SELECT count(*) FROM posture.registry_view()").Scan(&defs); err != nil {
		t.Fatal(err)
	}
	observed := map[string]int{}
	var idle []oscal.Observation
	for _, o := range *r.Observations {
		for _, k := range props(o.Props, "fair-setting") {
			observed[k]++
			if k == "session.idle_timeout" {
				idle = append(idle, o)
			}
		}
	}
	if len(observed) != defs {
		t.Errorf("observed %d settings, the registry has %d", len(observed), defs)
	}
	if len(idle) == 0 {
		t.Fatal("no observation of session.idle_timeout")
	}
	for _, o := range idle {
		if v := props(o.Props, "fair-effective-value"); !slices.Equal(v, []string{"1h0m0s"}) || (*o.Types)[0] != "finding" {
			t.Errorf("session.idle_timeout observation: value %v type %v", v, *o.Types)
		}
	}

	// Findings: the drift findings (not-satisfied) and the checks that did not run (Not assessed).
	drift, notAssessed := map[string]bool{}, map[string]bool{}
	for _, f := range *r.Findings {
		if f.Target.Status.State != "not-satisfied" {
			t.Errorf("finding %q state %q", f.Title, f.Target.Status.State)
		}
		if slices.Equal(props(f.Props, "fair-assessment-status"), []string{"not-assessed"}) {
			notAssessed[props(f.Props, "fair-check")[0]] = true
		} else {
			drift[props(f.Props, "fair-check")[0]] = true
		}
	}
	for _, c := range []string{posture.CheckDeviation, posture.CheckRowMAC, "pod_hardening"} {
		if !drift[c] {
			t.Errorf("no finding for drift check %s; have %v", c, drift)
		}
	}
	if len(notAssessed) != 8 || notAssessed[posture.CheckNodeFIPS] || notAssessed["pod_hardening"] {
		t.Errorf("not assessed = %v, want the 8 checks that did not run", notAssessed)
	}
	var evidence []string
	for _, o := range *r.Observations {
		if props(o.Props, "fair-check") != nil && props(o.Props, "fair-subject") != nil {
			evidence = append(evidence, o.Description)
		}
	}
	if want := []string{"node_fips: deployment:node/a, verified.", "node_fips: deployment:node/b, attested, not verified."}; !slices.Equal(evidence, want) {
		t.Errorf("node evidence = %v", evidence)
	}
	if v := props(r.Props, "fair-profile"); len(v) != 1 || !strings.HasPrefix(v[0], "fedramp-moderate@") {
		t.Errorf("profile = %v", v)
	}
	if (*r.LocalDefinitions.Components)[0].UUID != posture.PlatformComponentUUID {
		t.Error("the platform component is not declared (AC-48)")
	}

	// Determinism: a second snapshot of the same posture at the same as_of
	// gives the same bytes, and so does the stored (JSON) snapshot.
	s2 := load()
	if !s2.AsOf.After(s1.AsOf) {
		t.Fatalf("as_of %v then %v", s1.AsOf, s2.AsOf)
	}
	s2.AsOf = s1.AsOf
	if b2, _ := export(s2); !bytes.Equal(b1, b2) {
		t.Error("the same posture and as_of gave a different document")
	}
	raw, _ := json.Marshal(s1)
	var stored posture.ARSnapshot
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if b3, _ := export(stored); !bytes.Equal(b1, b3) {
		t.Error("the stored snapshot does not reproduce the document")
	}

	// A different posture at the same as_of is a different document.
	if _, err := (posture.K8sAccess{DB: e.posturePool(), Audit: audit.NewMemory()}).Decide(ctx, posture.AccessRevoked, "customer revoked access", ""); err != nil {
		t.Fatal(err)
	}
	s3 := load()
	s3.AsOf = s1.AsOf
	b3, ar3 := export(s3)
	if bytes.Equal(b1, b3) {
		t.Fatal("revoking access did not change the export")
	}
	// Revoked: every deployment check is Not assessed.
	n := map[string]bool{}
	for _, f := range *ar3.Results[0].Findings {
		if slices.Equal(props(f.Props, "fair-assessment-status"), []string{"not-assessed"}) {
			n[props(f.Props, "fair-check")[0]] = true
			if !strings.Contains(f.Target.Status.Remarks, "revoked") {
				t.Errorf("not-assessed remarks %q", f.Target.Status.Remarks)
			}
		}
	}
	if len(n) != 10 {
		t.Errorf("with access revoked, %d checks not assessed, want 10", len(n))
	}
}

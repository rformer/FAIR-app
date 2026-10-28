package posture

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/oscal"
)

func arFixture() ARSnapshot {
	asOf := time.Date(2026, 10, 28, 12, 0, 0, 123456000, time.UTC)
	expires := asOf.Add(10 * 24 * time.Hour)
	report := asOf.Add(-5 * time.Minute)
	return ARSnapshot{
		AsOf:           asOf,
		Profile:        ARProfile{ID: "enterprise-baseline", Version: "1.0.0", Name: "Enterprise Baseline", Family: "enterprise"},
		DeploymentMode: "self-hosted",
		K8sAccess:      AccessGranted,
		ScannerReport:  &report,
		Settings: []ARSetting{
			{Key: "tls.min_version", Params: []string{"sc-8_odp", "sc-13_odp"}, Value: json.RawMessage(`"1.1"`), Source: "change",
				Default: json.RawMessage(`"1.2"`), Bound: json.RawMessage(`"1.2"`), Deviation: "below_floor"},
			{Key: "auth.lockout_threshold", Params: []string{"ac-7_odp.01"}, Value: json.RawMessage(`10`), Source: "exception",
				Default: json.RawMessage(`5`), Bound: json.RawMessage(`5`), Deviation: "exception",
				ExceptionID: "6b1d1f9e-6c43-4c33-9d8e-6f1a6b7f2a10", ExceptionExpires: &expires},
			{Key: "audit.export_format", Value: json.RawMessage(`{"kind": "ocsf",  "v": 1}`), Source: "profile",
				Default: json.RawMessage(`{"kind":"ocsf","v":1}`), Bound: json.RawMessage(`null`), Deviation: "in_bounds"},
		},
		Findings: []ARFinding{
			{ID: "11111111-1111-4111-8111-111111111111", Kind: "app", CheckID: CheckHardFloor, Severity: "critical",
				Controls: []string{"CM-6", "SC-8"}, Subject: "tls.min_version", Detail: json.RawMessage(`{"value":"1.1"}`),
				Remediation: "Restore TLS 1.2.", Status: "open", FirstSeen: asOf.Add(-time.Hour), LastSeen: asOf},
			{ID: "22222222-2222-4222-8222-222222222222", Kind: "deployment", CheckID: "pod_hardening", Severity: "high",
				Controls: []string{"CM-7"}, Subject: "fair/iam", Detail: json.RawMessage(`{}`),
				Remediation: "Run as non-root.", Status: "acknowledged", FirstSeen: asOf.Add(-2 * time.Hour), LastSeen: asOf},
		},
		Checks: []ARCheck{
			{ID: "pod_hardening", Title: "Platform pods run non-root with a read-only root filesystem", Controls: []string{"CM-7", "AC-6(10)"}, Assessed: true},
			{ID: "storage_encryption", Title: "Platform volumes use encrypted storage classes", Controls: []string{"SC-28", "SC-28(1)"},
				Reason: "the check failed: storage classes unreadable"},
		},
		Observations: []ARObservation{
			{CheckID: "node_fips", Subject: "node-b", Method: "attested", Detail: json.RawMessage(`{"label":"attested"}`), ObservedAt: report},
			{CheckID: "node_fips", Subject: "node-a", Method: "verified", Detail: json.RawMessage(`{"probe":"ready"}`), ObservedAt: report},
		},
	}
}

func exportAR(t *testing.T, s ARSnapshot) ([]byte, *oscal.AssessmentResultsModel) {
	t.Helper()
	b, err := ExportAssessmentResults(s)
	if err != nil {
		t.Fatal(err)
	}
	kind, err := oscal.Validate(b)
	if err != nil || kind != oscal.AssessmentResults {
		t.Fatalf("Validate: %v %v", kind, err)
	}
	doc, _, err := oscal.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, doc.AssessmentResults
}

func propValue(ps *[]oscal.Property, name string) []string {
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

// AC-45, AC-48: the document validates against the pinned OSCAL schema and
// holds observations per parameter, drift findings, Not assessed items and
// the component-definition reference.
func TestAssessmentResultsContent(t *testing.T) {
	_, ar := exportAR(t, arFixture())
	r := ar.Results[0]

	obs := map[string]oscal.Observation{}
	for _, o := range *r.Observations {
		obs[o.Title] = o
		if o.Subjects == nil || (*o.Subjects)[0].SubjectUuid != PlatformComponentUUID {
			t.Errorf("observation %q does not reference the platform component", o.Title)
		}
		if !slices.Equal(o.Methods, []string{"TEST"}) {
			t.Errorf("observation %q methods = %v", o.Title, o.Methods)
		}
	}
	// One observation per parameter, with the effective value.
	for _, title := range []string{"tls.min_version (sc-13_odp)", "tls.min_version (sc-8_odp)"} {
		o, ok := obs[title]
		if !ok {
			t.Fatalf("no observation %q; have %v", title, keys(obs))
		}
		if v := propValue(o.Props, "fair-effective-value"); !slices.Equal(v, []string{"1.1"}) {
			t.Errorf("%s effective value = %v", title, v)
		}
		if (*o.Types)[0] != "finding" {
			t.Errorf("%s type = %v, want finding (below the floor)", title, *o.Types)
		}
	}
	if c := propValue(obs["tls.min_version (sc-13_odp)"].Props, "fair-control"); !slices.Equal(c, []string{"sc-13"}) {
		t.Errorf("sc-13_odp controls = %v", c)
	}
	lock := obs["auth.lockout_threshold (ac-7_odp.01)"]
	if (*lock.Types)[0] != "finding" || len(propValue(lock.Props, "fair-exception-expires")) != 1 {
		t.Errorf("exception observation = %+v", lock)
	}
	// A setting without an OSCAL parameter is still observed; compact JSON values.
	fmtObs, ok := obs["audit.export_format"]
	if !ok || (*fmtObs.Types)[0] != "control-objective" {
		t.Fatalf("audit.export_format observation = %+v", fmtObs)
	}
	if v := propValue(fmtObs.Props, "fair-effective-value"); !slices.Equal(v, []string{`{"kind":"ocsf","v":1}`}) {
		t.Errorf("compact value = %v", v)
	}
	if len(propValue(fmtObs.Props, "fair-bound")) != 0 {
		t.Error("a null bound must be omitted, not exported as a value")
	}
	// Deployment evidence: attested is marked "attested, not verified".
	if o := obs["node_fips: node-b"]; !strings.Contains(o.Description, "attested, not verified") {
		t.Errorf("attested node = %q", o.Description)
	}
	if o := obs["node_fips: node-a"]; strings.Contains(o.Description, "attested") {
		t.Errorf("verified node = %q", o.Description)
	}
	if _, ok := obs["Platform pods run non-root with a read-only root filesystem"]; !ok {
		t.Error("no observation for the assessed check")
	}
	if _, ok := obs["Platform volumes use encrypted storage classes"]; ok {
		t.Error("a check that is not assessed must not be reported as observed")
	}

	// Findings: one per drift finding and control, not-satisfied; Not assessed per control.
	type fk struct{ title, target, state, reason string }
	var got []fk
	for _, f := range *r.Findings {
		got = append(got, fk{f.Title, f.Target.TargetId, f.Target.Status.State, f.Target.Status.Reason})
	}
	want := []fk{
		{"hard_floor_violation: tls.min_version", "cm-6", "not-satisfied", "fail"},
		{"hard_floor_violation: tls.min_version", "sc-8", "not-satisfied", "fail"},
		{"pod_hardening: fair/iam", "cm-7", "not-satisfied", "fail"},
		{"Not assessed: Platform volumes use encrypted storage classes", "sc-28", "not-satisfied", "other"},
		{"Not assessed: Platform volumes use encrypted storage classes", "sc-28.1", "not-satisfied", "other"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
	for _, f := range (*r.Findings)[3:] {
		if v := propValue(f.Props, "fair-assessment-status"); !slices.Equal(v, []string{"not-assessed"}) {
			t.Errorf("not-assessed prop = %v", v)
		}
		if !strings.Contains(f.Target.Status.Remarks, "storage classes unreadable") {
			t.Errorf("not-assessed remarks = %q", f.Target.Status.Remarks)
		}
	}
	tls := (*r.Findings)[0]
	if tls.RelatedObservations == nil || len(*tls.RelatedObservations) != 2 {
		t.Errorf("the TLS finding should relate both TLS observations: %+v", tls.RelatedObservations)
	}
	if ph := (*r.Findings)[2]; ph.RelatedObservations == nil || len(*ph.RelatedObservations) != 1 {
		t.Errorf("the pod_hardening finding should relate its check's observation: %+v", ph.RelatedObservations)
	}

	// Reviewed controls: every control touched, in catalog order.
	var ids []string
	for _, c := range *r.ReviewedControls.ControlSelections[0].IncludeControls {
		ids = append(ids, c.ControlId)
	}
	if want := []string{"ac-6.10", "ac-7", "cm-6", "cm-7", "sc-8", "sc-13", "sc-28", "sc-28.1"}; !slices.Equal(ids, want) {
		t.Errorf("reviewed controls = %v, want %v", ids, want)
	}

	// AC-48: the platform component is declared and linked to the component
	// definition; import-ap resolves to the generated plan.
	comp := (*r.LocalDefinitions.Components)[0]
	if comp.UUID != PlatformComponentUUID || comp.Links == nil {
		t.Fatalf("component = %+v", comp)
	}
	res := map[string]oscal.Resource{}
	for _, x := range *ar.BackMatter.Resources {
		res["#"+x.UUID] = x
	}
	if x, ok := res[(*comp.Links)[0].Href]; !ok || !strings.Contains(x.Title, "component definition") {
		t.Errorf("component-definition link %q does not resolve", (*comp.Links)[0].Href)
	}
	if x, ok := res[ar.ImportAp.Href]; !ok || !strings.Contains(x.Title, "assessment plan") {
		t.Errorf("import-ap %q does not resolve", ar.ImportAp.Href)
	}
	if v := propValue(r.Props, "fair-k8s-access"); !slices.Equal(v, []string{"granted"}) {
		t.Errorf("result k8s access = %v", v)
	}
}

// Deterministic output: the same snapshot gives the same bytes, whatever
// the order of its rows and after a JSON round trip (what T-35 stores).
func TestAssessmentResultsDeterministic(t *testing.T) {
	a, _ := exportAR(t, arFixture())

	s := arFixture()
	slices.Reverse(s.Settings)
	slices.Reverse(s.Findings)
	slices.Reverse(s.Checks)
	slices.Reverse(s.Observations)
	slices.Reverse(s.Settings[2].Params)
	s.Findings[1].Controls = []string{"SC-8", "CM-6"} // the TLS finding, reversed
	b, _ := exportAR(t, s)
	if !bytes.Equal(a, b) {
		t.Error("row order changed the document")
	}

	raw, err := json.Marshal(arFixture())
	if err != nil {
		t.Fatal(err)
	}
	var rt ARSnapshot
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatal(err)
	}
	c, _ := exportAR(t, rt)
	if !bytes.Equal(a, c) {
		t.Error("a stored snapshot does not reproduce the document")
	}

	later := arFixture()
	later.AsOf = later.AsOf.Add(time.Second)
	_, d := exportAR(t, later)
	_, e := exportAR(t, arFixture())
	if d.UUID == e.UUID || d.Results[0].UUID == e.Results[0].UUID {
		t.Error("a different as_of must give a different document")
	}
	if (*d.Results[0].Findings)[0].UUID != (*e.Results[0].Findings)[0].UUID {
		t.Error("a finding keeps its UUID across exports (OSCAL: per subject)")
	}
}

// Without Kubernetes access every deployment check is Not assessed, and an
// empty posture still yields a valid document.
func TestAssessmentResultsNoAccess(t *testing.T) {
	s := arFixture()
	s.K8sAccess, s.ScannerReport, s.Observations, s.Findings = AccessDeclined, nil, nil, nil
	for i := range s.Checks {
		s.Checks[i].Assessed, s.Checks[i].Reason = false, "Kubernetes access declined"
	}
	_, ar := exportAR(t, s)
	n := 0
	for _, f := range *ar.Results[0].Findings {
		if !strings.HasPrefix(f.Title, "Not assessed: ") {
			t.Errorf("unexpected finding %q", f.Title)
		}
		n++
	}
	if n != 4 {
		t.Errorf("not-assessed findings = %d, want one per control (4)", n)
	}

	exportAR(t, ARSnapshot{AsOf: s.AsOf})
}

func TestOSCALControlID(t *testing.T) {
	for in, want := range map[string]string{"AC-2": "ac-2", "AC-2(3)": "ac-2.3", "ac-2.3": "ac-2.3", "SC-08": "sc-8", "SC-28(01)": "sc-28.1"} {
		if got, ok := oscalControlID(in); !ok || got != want {
			t.Errorf("oscalControlID(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "AC", "AC-2(3", "control"} {
		if _, ok := oscalControlID(bad); ok {
			t.Errorf("oscalControlID(%q) accepted", bad)
		}
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

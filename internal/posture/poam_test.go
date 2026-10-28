package posture

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/oscal"
)

func poamFixture() ExportSnapshot {
	s := arFixture()
	at := s.AsOf
	s.Exceptions = []SnapshotException{
		{ID: "6b1d1f9e-6c43-4c33-9d8e-6f1a6b7f2a10", Key: "auth.lockout_threshold", Value: json.RawMessage(`10`),
			BoundAtCreation: json.RawMessage(`5`), Justification: "legacy kiosk accounts until the Q1 replacement",
			OwnerID: "0d6c7c0e-0000-4000-8000-000000000001", ApprovedBy: "0d6c7c0e-0000-4000-8000-000000000002",
			CreatedAt: at.Add(-20 * 24 * time.Hour), ExpiresAt: at.Add(10 * 24 * time.Hour), State: "active"},
		{ID: "7c2e2fa0-0000-4000-8000-000000000003", Key: "session.idle_timeout", BUID: "9a000000-0000-4000-8000-0000000000b1",
			Value: json.RawMessage(`"45m0s"`), BoundAtCreation: json.RawMessage(`"30m0s"`), Justification: "trading floor shifts",
			OwnerID: "0d6c7c0e-0000-4000-8000-000000000001", ApprovedBy: "0d6c7c0e-0000-4000-8000-000000000002",
			CreatedAt: at.Add(-2 * 24 * time.Hour), ExpiresAt: at.Add(5 * 24 * time.Hour), State: "active",
			RenewedFrom: "7c2e2fa0-0000-4000-8000-000000000004"},
		{ID: "8d3f3fb1-0000-4000-8000-000000000005", Key: "token.max_lifetime", Overlay: true,
			Value: json.RawMessage(`"2h0m0s"`), BoundAtCreation: json.RawMessage(`"1h0m0s"`), Justification: "batch export window",
			OwnerID: "0d6c7c0e-0000-4000-8000-000000000001", ApprovedBy: "0d6c7c0e-0000-4000-8000-000000000002",
			CreatedAt: at.Add(-7 * 24 * time.Hour), ExpiresAt: at.Add(-time.Hour), State: "revert_failed"},
	}
	s.Findings = append(s.Findings, SnapshotFinding{ID: "33333333-3333-4333-8333-333333333333", Kind: "app", CheckID: "revert_failed",
		Severity: "critical", Controls: []string{"CA-5", "CM-6"}, Subject: "exception:8d3f3fb1-0000-4000-8000-000000000005",
		Detail: json.RawMessage(`{}`), Remediation: "Revert by hand.", Status: "open", FirstSeen: at, LastSeen: at})
	return s
}

func exportPOAM(t *testing.T, s ExportSnapshot) ([]byte, *oscal.POAMModel) {
	t.Helper()
	b, err := ExportPOAM(s)
	if err != nil {
		t.Fatal(err)
	}
	doc, kind, err := oscal.Parse(b)
	if err != nil || kind != oscal.POAM {
		t.Fatalf("not a valid POA&M: %v %v", kind, err)
	}
	return b, doc.PlanOfActionAndMilestones
}

// AC-46: one item per open exception or deviation, with its justification,
// approver and expiry, related to the Assessment Results' observations and
// findings by UUID.
func TestPOAMContent(t *testing.T) {
	s := poamFixture()
	_, p := exportPOAM(t, s)

	var titles []string
	for _, it := range p.PoamItems {
		titles = append(titles, it.Title)
	}
	want := []string{
		"Exception: token.max_lifetime (Restricted BU overlay)",
		"Exception: session.idle_timeout (BU 9a000000-0000-4000-8000-0000000000b1)",
		"Exception: auth.lockout_threshold",
		"Deviation: tls.min_version",
	}
	if !slices.Equal(titles, want) {
		t.Fatalf("items:\n got %q\nwant %q", titles, want)
	}

	lock := p.PoamItems[2]
	for name, want := range map[string]string{
		"fair-justification": "legacy kiosk accounts until the Q1 replacement",
		"fair-approved-by":   "0d6c7c0e-0000-4000-8000-000000000002",
		"fair-owner":         "0d6c7c0e-0000-4000-8000-000000000001",
		"fair-expires":       s.AsOf.Add(10 * 24 * time.Hour).Format(time.RFC3339Nano),
		"fair-value":         "10",
		"fair-control":       "ac-7",
	} {
		if v := propValue(lock.Props, name); !slices.Equal(v, []string{want}) {
			t.Errorf("lockout item %s = %v, want %q", name, v, want)
		}
	}
	if !strings.Contains(lock.Description, "legacy kiosk accounts") || !strings.Contains(lock.Description, "expires") {
		t.Errorf("lockout description = %q", lock.Description)
	}

	// The same observation UUIDs as the Assessment Results at the same as_of.
	_, ar := exportAR(t, s)
	arObs := map[string]string{}
	for _, o := range *ar.Results[0].Observations {
		arObs[o.UUID] = o.Title
	}
	arFindings := map[string]string{}
	for _, f := range *ar.Results[0].Findings {
		arFindings[f.UUID] = f.Title
	}
	if lock.RelatedObservations == nil || arObs[(*lock.RelatedObservations)[0].ObservationUuid] != "auth.lockout_threshold (ac-7_odp.01)" {
		t.Errorf("lockout related observations = %+v", lock.RelatedObservations)
	}
	if bu := p.PoamItems[1]; bu.RelatedObservations != nil || len(propValue(bu.Props, "fair-renewed-from")) != 1 {
		t.Errorf("a BU exception relates no instance-wide observation and records its renewal: %+v", bu)
	}
	if ov := p.PoamItems[0]; !strings.Contains(ov.Remarks, "revert failed") || ov.RelatedFindings == nil || len(*ov.RelatedFindings) != 2 {
		t.Errorf("revert_failed item: remarks %q, related findings %+v", ov.Remarks, ov.RelatedFindings)
	}
	dev := p.PoamItems[3]
	if dev.RelatedFindings == nil || len(*dev.RelatedFindings) != 2 || dev.RelatedObservations == nil || len(*dev.RelatedObservations) != 2 {
		t.Fatalf("deviation relations = %+v %+v", dev.RelatedFindings, dev.RelatedObservations)
	}
	if v := propValue(dev.Props, "fair-deviation"); !slices.Equal(v, []string{"below_floor"}) {
		t.Errorf("deviation = %v", v)
	}

	// Every reference resolves inside the POA&M, to what the AR holds.
	have := map[string]bool{}
	for _, o := range *p.Observations {
		have[o.UUID] = true
		if _, ok := arObs[o.UUID]; !ok {
			t.Errorf("observation %s is not the AR's", o.Title)
		}
	}
	for _, f := range *p.Findings {
		have[f.UUID] = true
		if _, ok := arFindings[f.UUID]; !ok {
			t.Errorf("finding %s is not the AR's", f.Title)
		}
	}
	for _, it := range p.PoamItems {
		if it.RelatedObservations != nil {
			for _, r := range *it.RelatedObservations {
				if !have[r.ObservationUuid] {
					t.Errorf("%s: observation %s not in the document", it.Title, r.ObservationUuid)
				}
			}
		}
		if it.RelatedFindings != nil {
			for _, r := range *it.RelatedFindings {
				if !have[r.FindingUuid] {
					t.Errorf("%s: finding %s not in the document", it.Title, r.FindingUuid)
				}
			}
		}
	}
	if len(*p.Observations) != 3 || len(*p.Findings) != 4 {
		t.Errorf("only the related observations and findings are included: %d, %d", len(*p.Observations), len(*p.Findings))
	}
	if (*p.LocalDefinitions.Components)[0].UUID != PlatformComponentUUID || (*p.BackMatter.Resources)[0].UUID != componentDefinitionUUID {
		t.Error("the platform component and its component definition are not referenced (AC-48)")
	}
}

func TestPOAMDeterministic(t *testing.T) {
	a, pa := exportPOAM(t, poamFixture())
	s := poamFixture()
	slices.Reverse(s.Exceptions)
	slices.Reverse(s.Settings)
	slices.Reverse(s.Findings)
	b, _ := exportPOAM(t, s)
	if !bytes.Equal(a, b) {
		t.Error("row order changed the POA&M")
	}
	raw, _ := json.Marshal(poamFixture())
	var rt ExportSnapshot
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatal(err)
	}
	if c, _ := exportPOAM(t, rt); !bytes.Equal(a, c) {
		t.Error("a stored snapshot does not reproduce the POA&M")
	}
	later := poamFixture()
	later.AsOf = later.AsOf.Add(time.Hour)
	_, pl := exportPOAM(t, later)
	if pl.UUID == pa.UUID || pl.PoamItems[0].UUID != pa.PoamItems[0].UUID {
		t.Error("a later export is a new document whose items keep their UUIDs")
	}
}

func TestPOAMNothingOpen(t *testing.T) {
	s := arFixture()
	s.Settings = s.Settings[2:] // only the in-bounds setting
	if _, err := ExportPOAM(s); !errors.Is(err, ErrNoPOAMItems) {
		t.Fatalf("empty POA&M: %v", err)
	}
}

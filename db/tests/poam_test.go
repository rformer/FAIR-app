package tests

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-015 T-34 (AC-46): the POA&M export from a real posture validates
// against the pinned OSCAL schema and its items match the database: each
// open exception with its justification, approver and expiry, and each
// deviation without one.
func TestPOAMExport(t *testing.T) {
	ctx := context.Background()
	e, ev, _, _ := evaluatorFixture(t)
	load := func() posture.ExportSnapshot {
		t.Helper()
		s, err := posture.LoadExportSnapshot(ctx, e.posturePool())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Nothing open yet: no POA&M (OSCAL needs at least one item).
	if _, err := posture.ExportPOAM(load()); !errors.Is(err, posture.ErrNoPOAMItems) {
		t.Fatalf("POA&M with nothing open: %v", err)
	}

	x := approvedException(t, e, ev, 30*24*time.Hour)
	// A deviation with no exception, found by the drift engine.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1.0"' WHERE key = 'tls.min_version' AND bu_id IS NULL`)
	if _, err := (posture.Drift{DB: e.posturePool(), Audit: audit.NewMemory()}).Scan(ctx); err != nil {
		t.Fatal(err)
	}

	s := load()
	b, err := posture.ExportPOAM(s)
	if err != nil {
		t.Fatal(err)
	}
	doc, kind, err := oscal.Parse(b)
	if err != nil || kind != oscal.POAM {
		t.Fatalf("not a valid POA&M: %v %v", kind, err)
	}
	p := doc.PlanOfActionAndMilestones
	props := func(ps *[]oscal.Property, name string) string {
		if ps != nil {
			for _, p := range *ps {
				if p.Name == name {
					return p.Value
				}
			}
		}
		return ""
	}

	var exc, dev []oscal.POAMItem
	for _, it := range p.PoamItems {
		switch props(it.Props, "fair-item-kind") {
		case "exception":
			exc = append(exc, it)
		case "deviation":
			dev = append(dev, it)
		}
	}
	if len(exc) != 1 || len(dev) != 1 || len(p.PoamItems) != 2 {
		t.Fatalf("items: %d exceptions, %d deviations, %d in all", len(exc), len(dev), len(p.PoamItems))
	}

	// The exception item matches the database row.
	row := strings.Split(e.adminQuery(`SELECT id, key, justification, owner_id, approved_by,
		to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), state
		FROM posture.exception WHERE id = '`+x.ID+`'`), "|")
	it := exc[0]
	for name, want := range map[string]string{
		"fair-exception": row[0], "fair-setting": row[1], "fair-justification": row[2], "fair-owner": row[3],
		"fair-approved-by": row[4], "fair-state": row[6], "fair-value": "8760h0m0s",
	} {
		if got := props(it.Props, name); got != want {
			t.Errorf("exception item %s = %q, database %q", name, got, want)
		}
	}
	if exp, _ := time.Parse(time.RFC3339Nano, props(it.Props, "fair-expires")); !exp.Equal(mustTime(t, row[5])) {
		t.Errorf("expiry %q, database %q", props(it.Props, "fair-expires"), row[5])
	}
	if it.RelatedObservations == nil {
		t.Error("the instance-wide exception relates no observation")
	}

	// The deviation item: TLS below the floor, related to its drift finding.
	if d := dev[0]; props(d.Props, "fair-setting") != "tls.min_version" || props(d.Props, "fair-deviation") != "below_floor" ||
		d.RelatedFindings == nil {
		t.Errorf("deviation item = %+v", d)
	}

	// Cross-reference: the POA&M's observations and findings are the AR's.
	ar, err := posture.ExportAssessmentResults(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range *p.Observations {
		if !bytes.Contains(ar, []byte(`"uuid": "`+o.UUID+`"`)) {
			t.Errorf("observation %s is not in the Assessment Results", o.Title)
		}
	}
	for _, f := range *p.Findings {
		if !bytes.Contains(ar, []byte(`"uuid": "`+f.UUID+`"`)) {
			t.Errorf("finding %s is not in the Assessment Results", f.Title)
		}
	}

	// Deterministic for the same as_of.
	s2 := load()
	s2.AsOf = s.AsOf
	if b2, err := posture.ExportPOAM(s2); err != nil || !bytes.Equal(b, b2) {
		t.Errorf("the same posture and as_of gave a different POA&M (%v)", err)
	}
	if slices.ContainsFunc(p.PoamItems, func(i oscal.POAMItem) bool { return i.UUID == "" }) {
		t.Error("every item has a UUID")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

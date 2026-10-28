package posture

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/oscal"
)

// OSCAL POA&M export (F-015 T-34; AC-46, AC-48; design §6.9), built from
// the same ExportSnapshot as the Assessment Results. The observations and
// findings an item relates to are included with the UUIDs they have in the
// Assessment Results at the same as_of, so the two documents cross-reference.

// ErrNoPOAMItems is returned when no exception or deviation is open: nothing to
// put in a POA&M, and OSCAL requires at least one item. A placeholder item
// would be counted as an open item by the tools that read POA&Ms, so the
// export is refused instead and the caller reports that nothing is open.
var ErrNoPOAMItems = errors.New("posture: no open exceptions or deviations; a POA&M needs at least one item")

// ExportPOAM builds the POA&M and validates it against the pinned OSCAL
// schema; an invalid document is never returned (AC-47).
func ExportPOAM(s ExportSnapshot) ([]byte, error) {
	doc := BuildPOAM(s)
	if len(doc.PlanOfActionAndMilestones.PoamItems) == 0 {
		return nil, ErrNoPOAMItems
	}
	return oscal.Marshal(doc)
}

// BuildPOAM is the POA&M document for s:
//   - an item per open exception (active, or revert_failed: expired and not
//     yet reverted), instance-wide, for a BU or a Restricted BU overlay, with
//     its justification, owner, approver, creation and expiry, value and the
//     bound when it was created;
//   - an item per instance-wide deviation without an exception (below the
//     hard floor, or out of bounds);
//   - each item names its controls and relates the observations of its
//     setting (instance-wide items) and the drift findings about it.
//
// Item UUIDs depend only on the exception or setting, so an item keeps its
// identity across exports, as POA&M tracking expects.
func BuildPOAM(s ExportSnapshot) *oscal.Document {
	asOf := s.AsOf.UTC()
	stamp := asOf.Format(time.RFC3339Nano)
	a := assess(s)
	params := map[string][]string{}
	for _, st := range s.Settings {
		params[st.Key] = st.Params
	}
	usedObs, usedFindings := map[string]bool{}, map[string]bool{}
	relate := func(item *oscal.POAMItem, key string, instance bool, subjects ...string) {
		if instance {
			var ro []oscal.RelatedObservation
			for _, id := range a.settingObs[key] {
				ro = append(ro, oscal.RelatedObservation{ObservationUuid: id})
				usedObs[id] = true
			}
			if len(ro) > 0 {
				item.RelatedObservations = &ro
			}
		}
		var rf []oscal.RelatedFinding
		for _, sub := range subjects {
			for _, id := range a.driftFinding[sub] {
				rf = append(rf, oscal.RelatedFinding{FindingUuid: id})
				usedFindings[id] = true
			}
		}
		if len(rf) > 0 {
			item.RelatedFindings = &rf
		}
	}
	controlProps := func(key string) []oscal.Property {
		var out []oscal.Property
		for _, c := range oscalControlIDs(ControlsForParams(params[key])) {
			out = append(out, prop("fair-control", c)...)
		}
		return out
	}

	exceptions := slices.Clone(s.Exceptions)
	slices.SortFunc(exceptions, func(x, y SnapshotException) int {
		return cmp.Or(x.ExpiresAt.Compare(y.ExpiresAt), strings.Compare(x.Key, y.Key), strings.Compare(x.ID, y.ID))
	})
	var items []oscal.POAMItem
	for _, x := range exceptions {
		scope, title := "instance-wide", "Exception: "+x.Key
		switch {
		case x.Overlay:
			scope, title = "Restricted BU overlay", title+" (Restricted BU overlay)"
		case x.BUID != "":
			scope, title = "business unit "+x.BUID, title+" (BU "+x.BUID+")"
		}
		expiry := x.ExpiresAt.UTC().Format(time.RFC3339)
		desc := fmt.Sprintf("%s (%s) is %s, outside the bound %s the active profile set when the exception was created. "+
			"Approved by user %s, owned by user %s, expires %s. Justification: %s",
			x.Key, scope, describeValue(x.Value), describeValue(x.BoundAtCreation), x.ApprovedBy, x.OwnerID, expiry, strings.TrimSpace(x.Justification))
		remarks := "The value reverts to the profile automatically at expiry unless the exception is renewed with dual approval."
		if x.State == "revert_failed" {
			remarks = "The exception expired at " + expiry + " but its automatic revert failed; the value is still in force (critical finding revert_failed)."
		}
		ps := props("fair-item-kind", "exception", "fair-exception", x.ID, "fair-setting", x.Key, "fair-bu", x.BUID,
			"fair-value", oscalJSON(x.Value), "fair-bound-at-creation", oscalJSON(x.BoundAtCreation),
			"fair-justification", x.Justification, "fair-owner", x.OwnerID, "fair-approved-by", x.ApprovedBy,
			"fair-created", x.CreatedAt.UTC().Format(time.RFC3339Nano), "fair-expires", x.ExpiresAt.UTC().Format(time.RFC3339Nano),
			"fair-renewed-from", x.RenewedFrom, "fair-state", x.State)
		if x.Overlay {
			ps = append(ps, prop("fair-overlay", "true")...)
		}
		ps = append(ps, controlProps(x.Key)...)
		item := oscal.POAMItem{UUID: uuidV5("poam-item/exception/" + x.ID), Title: title, Description: desc, Props: &ps, Remarks: remarks}
		relate(&item, x.Key, x.BUID == "" && !x.Overlay, driftSubject(x.Key, x.BUID, x.Overlay), "exception:"+x.ID)
		items = append(items, item)
	}

	settings := slices.Clone(s.Settings)
	slices.SortFunc(settings, func(x, y SnapshotSetting) int { return strings.Compare(x.Key, y.Key) })
	for _, st := range settings {
		if st.Deviation != "below_floor" && st.Deviation != "out_of_bounds" {
			continue
		}
		desc := fmt.Sprintf("%s is %s instance-wide, %s (bound %s), with no approved exception. "+
			"Restore a value within the profile's bounds, or request an exception.", st.Key, describeValue(st.Value),
			deviationText(st.Deviation), describeValue(st.Bound))
		ps := props("fair-item-kind", "deviation", "fair-setting", st.Key, "fair-value", oscalJSON(st.Value),
			"fair-bound", oscalJSON(st.Bound), "fair-deviation", st.Deviation, "fair-source", st.Source)
		ps = append(ps, controlProps(st.Key)...)
		item := oscal.POAMItem{UUID: uuidV5("poam-item/deviation/" + st.Key), Title: "Deviation: " + st.Key, Description: desc, Props: &ps}
		relate(&item, st.Key, true, driftSubject(st.Key, "", false))
		items = append(items, item)
	}

	profile := s.Profile.ID + "@" + s.Profile.Version
	name := s.Profile.Name
	if name == "" {
		name = profile
	}
	poam := &oscal.POAMModel{
		UUID: uuidV5("poam/" + stamp),
		Metadata: oscal.Metadata{
			Title:        "FAIR Risk Platform plan of action and milestones: " + name,
			LastModified: asOf,
			Version:      stamp,
			OscalVersion: oscal.Version,
			Props:        ptr(props("fair-profile", profile, "fair-deployment-mode", s.DeploymentMode)),
		},
		LocalDefinitions: &oscal.POAMLocalDefs{Components: &[]oscal.SystemComponent{platformComponent()}},
		PoamItems:        items,
		BackMatter:       &oscal.BackMatter{Resources: &[]oscal.Resource{componentDefinitionResource()}},
	}
	var obs []oscal.Observation
	for _, o := range a.observations {
		if usedObs[o.UUID] {
			obs = append(obs, o)
		}
	}
	if len(obs) > 0 {
		poam.Observations = &obs
	}
	var fs []oscal.Finding
	for _, f := range a.findings {
		if usedFindings[f.UUID] {
			fs = append(fs, f)
		}
	}
	if len(fs) > 0 {
		poam.Findings = &fs
	}
	return &oscal.Document{PlanOfActionAndMilestones: poam}
}

package posture

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/oscal"
)

// OSCAL Assessment Results export (F-015 T-33; AC-45, AC-48; design §6.9).
// The export is a pure function of an ARSnapshot: LoadARSnapshot reads the
// posture in one read-only repeatable-read transaction, stamped with that
// transaction's time (as_of), and BuildAssessmentResults turns it into the
// document. Identifiers are UUIDv5 names and every list is sorted, so the
// same snapshot always gives the same bytes; T-35 stores the snapshot with
// the export record so an export can be regenerated and its digest checked.

// Reader is what the posture reads need: a pool or a transaction.
type Reader interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PlatformComponentUUID identifies the platform in OSCAL. F-014 publishes
// the platform's component definition with this component UUID (AC-48), so
// every export's subjects resolve to it.
var PlatformComponentUUID = uuidV5("component/fair-platform")

// ARSnapshot is everything an Assessment Results export is built from. Its
// JSON form is what T-35 records to reproduce an export.
type ARSnapshot struct {
	AsOf           time.Time       `json:"as_of"`
	Profile        ARProfile       `json:"profile"`
	DeploymentMode string          `json:"deployment_mode"`
	K8sAccess      string          `json:"k8s_access"`
	ScannerReport  *time.Time      `json:"scanner_report,omitempty"` // the latest report received
	Settings       []ARSetting     `json:"settings"`
	Findings       []ARFinding     `json:"findings"` // unresolved (open or acknowledged)
	Checks         []ARCheck       `json:"checks"`
	Observations   []ARObservation `json:"observations"` // deployment observations (node FIPS evidence)
}

// ARProfile is the active profile.
type ARProfile struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Name    string `json:"name"`
	Family  string `json:"family"`
}

// ARSetting is a setting's instance-wide effective value (registry_view).
type ARSetting struct {
	Key              string          `json:"key"`
	Params           []string        `json:"params"`
	Value            json.RawMessage `json:"value"`
	Source           string          `json:"source"`
	Default          json.RawMessage `json:"profile_default"`
	Bound            json.RawMessage `json:"bound"`
	Deviation        string          `json:"deviation"`
	ExceptionID      string          `json:"exception_id,omitempty"`
	ExceptionExpires *time.Time      `json:"exception_expires,omitempty"`
}

// ARFinding is an unresolved drift finding.
type ARFinding struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	CheckID     string          `json:"check_id"`
	Severity    string          `json:"severity"`
	Controls    []string        `json:"controls"`
	Subject     string          `json:"subject"`
	Detail      json.RawMessage `json:"detail"`
	Remediation string          `json:"remediation"`
	Status      string          `json:"status"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
}

// ARCheck is a deployment check, assessed or not (K8sAccess.Assessment).
type ARCheck struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Controls []string `json:"controls"`
	Assessed bool     `json:"assessed"`
	Reason   string   `json:"reason,omitempty"`
}

// ARObservation is a deployment observation (T-29), e.g. a node's FIPS
// mode verified by fips-probe or only attested by the installer.
type ARObservation struct {
	CheckID    string          `json:"check_id"`
	Subject    string          `json:"subject"`
	Method     string          `json:"method"` // verified or attested
	Detail     json.RawMessage `json:"detail"`
	ObservedAt time.Time       `json:"observed_at"`
}

// LoadARSnapshot reads the posture in one read-only repeatable-read
// transaction (design §6.9: a consistent snapshot); as_of is the
// transaction's time. Connect as app_posture.
func LoadARSnapshot(ctx context.Context, db *pgxpool.Pool) (ARSnapshot, error) {
	var s ARSnapshot
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return s, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&s.AsOf); err != nil {
		return s, err
	}
	s.AsOf = s.AsOf.UTC()

	err = tx.QueryRow(ctx, "SELECT profile_id, version, name, family FROM posture.profiles_view() WHERE active").
		Scan(&s.Profile.ID, &s.Profile.Version, &s.Profile.Name, &s.Profile.Family)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return s, mapErr(err)
	}

	rows, err := tx.Query(ctx, `SELECT key, params, value, source, profile_default, bound, deviation,
		coalesce(exception_id::text, ''), exception_expires FROM posture.registry_view()`)
	if err != nil {
		return s, mapErr(err)
	}
	s.Settings, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ARSetting, error) {
		var v ARSetting
		err := r.Scan(&v.Key, &v.Params, &v.Value, &v.Source, &v.Default, &v.Bound, &v.Deviation, &v.ExceptionID, &v.ExceptionExpires)
		v.ExceptionExpires = utcPtr(v.ExceptionExpires)
		return v, err
	})
	if err != nil {
		return s, mapErr(err)
	}

	fs, err := Findings(ctx, tx, time.Time{})
	if err != nil {
		return s, err
	}
	for _, f := range fs {
		if f.Status == "resolved" {
			continue
		}
		s.Findings = append(s.Findings, ARFinding{f.ID, f.Kind, f.CheckID, f.Severity, f.Controls, f.Subject, f.Detail,
			f.Remediation, f.Status, f.FirstSeen.UTC(), f.LastSeen.UTC()})
	}

	st, err := accessStatus(ctx, tx)
	if err != nil {
		return s, err
	}
	s.DeploymentMode, s.K8sAccess = st.DeploymentMode, st.State
	as, report, err := assessment(ctx, tx, s.AsOf, 0)
	if err != nil {
		return s, err
	}
	if !report.IsZero() {
		r := report.UTC()
		s.ScannerReport = &r
	}
	for _, a := range as {
		s.Checks = append(s.Checks, ARCheck{a.CheckID, a.Title, a.Controls, a.Assessed, a.Reason})
	}
	os, err := Observations(ctx, tx)
	if err != nil {
		return s, err
	}
	for _, o := range os {
		s.Observations = append(s.Observations, ARObservation{o.CheckID, o.Subject, o.Method, o.Detail, o.ObservedAt.UTC()})
	}
	return s, tx.Commit(ctx)
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ExportAssessmentResults builds the document and validates it against the
// pinned OSCAL schema; an invalid document is never returned (AC-47).
func ExportAssessmentResults(s ARSnapshot) ([]byte, error) {
	return oscal.Marshal(BuildAssessmentResults(s))
}

// BuildAssessmentResults is the Assessment Results document for s:
//   - an observation for each setting and OSCAL parameter (method TEST, type
//     finding when the setting deviates, control-objective otherwise), with
//     the effective value;
//   - an observation for each assessed deployment check, and for each
//     deployment observation (attested node FIPS evidence is marked
//     "attested, not verified");
//   - a finding for each unresolved drift finding and control, with target
//     status not-satisfied;
//   - a finding for each control of a deployment check that is not assessed,
//     not-satisfied with reason "other" and the prop
//     fair-assessment-status=not-assessed (OSCAL's objective status has no
//     not-assessed state);
//   - subjects referencing the platform component (PlatformComponentUUID),
//     declared in the result and linked to its component definition in
//     back-matter (AC-48); import-ap references the generated assessment
//     plan in back-matter.
func BuildAssessmentResults(s ARSnapshot) *oscal.Document {
	asOf := s.AsOf.UTC()
	stamp := asOf.Format(time.RFC3339Nano)
	platform := []oscal.SubjectReference{{SubjectUuid: PlatformComponentUUID, Type: "component", Title: "FAIR Risk Platform"}}
	controls := map[string]bool{}

	settings := slices.Clone(s.Settings)
	slices.SortFunc(settings, func(a, b ARSetting) int { return strings.Compare(a.Key, b.Key) })
	settingObs := map[string][]string{} // setting key -> observation UUIDs
	var observations []oscal.Observation
	for _, st := range settings {
		params := slices.Clone(st.Params)
		slices.Sort(params)
		if len(params) == 0 {
			params = []string{""} // still observed, with no parameter
		}
		deviates := st.Deviation == "below_floor" || st.Deviation == "out_of_bounds" || st.Deviation == "exception"
		typ := "control-objective"
		if deviates {
			typ = "finding"
		}
		for _, p := range params {
			id := uuidV5("assessment-results/" + stamp + "/setting/" + st.Key + "/" + p)
			settingObs[st.Key] = append(settingObs[st.Key], id)
			props := props(
				"fair-setting", st.Key,
				"fair-parameter", p,
				"fair-effective-value", oscalJSON(st.Value),
				"fair-profile-default", oscalJSON(st.Default),
				"fair-bound", oscalJSON(st.Bound),
				"fair-source", st.Source,
				"fair-deviation", st.Deviation,
				"fair-exception", st.ExceptionID,
			)
			if st.ExceptionExpires != nil {
				props = append(props, prop("fair-exception-expires", st.ExceptionExpires.UTC().Format(time.RFC3339Nano))...)
			}
			for _, c := range ControlsForParams([]string{p}) {
				if cid, ok := oscalControlID(c); ok {
					controls[cid] = true
					props = append(props, prop("fair-control", cid)...)
				}
			}
			title := st.Key
			if p != "" {
				title += " (" + p + ")"
			}
			observations = append(observations, oscal.Observation{
				UUID:        id,
				Title:       title,
				Description: fmt.Sprintf("The effective instance-wide value of %s is %s (%s).", st.Key, describeValue(st.Value), deviationText(st.Deviation)),
				Methods:     []string{"TEST"},
				Types:       &[]string{typ},
				Props:       &props,
				Subjects:    &platform,
				Collected:   asOf,
			})
		}
	}

	checks := slices.Clone(s.Checks)
	slices.SortFunc(checks, func(a, b ARCheck) int { return strings.Compare(a.ID, b.ID) })
	checkObs := map[string]string{}
	var notAssessed []oscal.Finding
	for _, c := range checks {
		cids := oscalControlIDs(c.Controls)
		for _, cid := range cids {
			controls[cid] = true
		}
		if !c.Assessed {
			for _, cid := range cids {
				notAssessed = append(notAssessed, oscal.Finding{
					UUID:        uuidV5("finding/not-assessed/" + c.ID + "/" + cid),
					Title:       "Not assessed: " + c.Title,
					Description: fmt.Sprintf("The deployment check %s (%s) is not assessed: %s.", c.ID, c.Title, c.Reason),
					Props:       ptr(props("fair-assessment-status", "not-assessed", "fair-check", c.ID, "fair-reason", c.Reason)),
					Target: oscal.FindingTarget{
						Type: "objective-id", TargetId: cid,
						Status: oscal.ObjectiveStatus{State: "not-satisfied", Reason: "other", Remarks: "Not assessed: " + c.Reason + "."},
					},
				})
			}
			continue
		}
		id := uuidV5("assessment-results/" + stamp + "/check/" + c.ID)
		checkObs[c.ID] = id
		collected := asOf
		if s.ScannerReport != nil {
			collected = s.ScannerReport.UTC()
		}
		ps := props("fair-check", c.ID)
		for _, cid := range cids {
			ps = append(ps, prop("fair-control", cid)...)
		}
		observations = append(observations, oscal.Observation{
			UUID:        id,
			Title:       c.Title,
			Description: fmt.Sprintf("The deployment check %s ran in the scanner's latest report.", c.ID),
			Methods:     []string{"TEST"},
			Types:       &[]string{"control-objective"},
			Props:       &ps,
			Subjects:    &platform,
			Collected:   collected,
		})
	}

	dobs := slices.Clone(s.Observations)
	slices.SortFunc(dobs, func(a, b ARObservation) int {
		return cmp.Or(strings.Compare(a.CheckID, b.CheckID), strings.Compare(a.Subject, b.Subject))
	})
	for _, o := range dobs {
		desc := fmt.Sprintf("%s: %s, verified.", o.CheckID, o.Subject)
		remarks := ""
		if o.Method == "attested" {
			desc = fmt.Sprintf("%s: %s, attested, not verified.", o.CheckID, o.Subject)
			remarks = "Attested by the installer, not verified by fips-probe."
		}
		ps := props("fair-check", o.CheckID, "fair-subject", o.Subject, "fair-method", o.Method, "fair-detail", oscalJSON(o.Detail))
		observations = append(observations, oscal.Observation{
			UUID:        uuidV5("assessment-results/" + stamp + "/observation/" + o.CheckID + "/" + o.Subject),
			Title:       o.CheckID + ": " + o.Subject,
			Description: desc,
			Methods:     []string{"TEST"},
			Types:       &[]string{"control-objective"},
			Props:       &ps,
			Subjects:    &[]oscal.SubjectReference{{SubjectUuid: PlatformComponentUUID, Type: "component", Title: o.Subject}},
			Collected:   o.ObservedAt.UTC(),
			Remarks:     remarks,
		})
	}

	drift := slices.Clone(s.Findings)
	slices.SortFunc(drift, func(a, b ARFinding) int {
		return cmp.Or(cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)), strings.Compare(a.CheckID, b.CheckID),
			strings.Compare(a.Subject, b.Subject), strings.Compare(a.ID, b.ID))
	})
	var findings []oscal.Finding
	for _, f := range drift {
		cids := oscalControlIDs(f.Controls)
		if len(cids) == 0 {
			cids = []string{"cm-6"} // drift from configured settings (CM-6) when a check names no control
		}
		var related []oscal.RelatedObservation
		for _, id := range settingObs[f.Subject] {
			related = append(related, oscal.RelatedObservation{ObservationUuid: id})
		}
		if id, ok := checkObs[f.CheckID]; ok {
			related = append(related, oscal.RelatedObservation{ObservationUuid: id})
		}
		for _, cid := range cids {
			controls[cid] = true
			of := oscal.Finding{
				UUID:  uuidV5("finding/drift/" + f.ID + "/" + cid),
				Title: f.CheckID + ": " + f.Subject,
				Description: fmt.Sprintf("Open %s drift finding (%s severity, %s since %s). Remediation: %s", f.Kind, f.Severity, f.Status,
					f.FirstSeen.UTC().Format(time.RFC3339), strings.TrimSpace(f.Remediation)),
				Props: ptr(props("fair-finding", f.ID, "fair-check", f.CheckID, "fair-kind", f.Kind, "fair-severity", f.Severity,
					"fair-status", f.Status, "fair-subject", f.Subject, "fair-detail", oscalJSON(f.Detail))),
				Target: oscal.FindingTarget{
					Type: "objective-id", TargetId: cid,
					Status: oscal.ObjectiveStatus{State: "not-satisfied", Reason: "fail"},
				},
			}
			if len(related) > 0 {
				of.RelatedObservations = &related
			}
			findings = append(findings, of)
		}
	}
	findings = append(findings, notAssessed...)

	var include []oscal.ControlByID
	for cid := range controls {
		include = append(include, oscal.ControlByID{ControlId: cid})
	}
	slices.SortFunc(include, func(a, b oscal.ControlByID) int { return compareControlIDs(a.ControlId, b.ControlId) })
	selection := oscal.AssessedControls{Description: "The controls the active profile's settings and the deployment checks implement or assess."}
	if len(include) > 0 {
		selection.IncludeControls = &include
	} else {
		selection.IncludeAll = &oscal.IncludeAll{}
	}

	profile := s.Profile.ID + "@" + s.Profile.Version
	planUUID := uuidV5("assessment-plan/" + profile)
	compDefUUID := uuidV5("component-definition/fair-platform")
	resultProps := props("fair-profile", profile, "fair-profile-family", s.Profile.Family,
		"fair-deployment-mode", s.DeploymentMode, "fair-k8s-access", s.K8sAccess)
	result := oscal.Result{
		UUID:  uuidV5("assessment-results/" + stamp + "/result"),
		Title: "Security posture as of " + stamp,
		Description: "The platform's security posture at " + stamp + ": the effective value of every posture setting, " +
			"the unresolved drift findings, and the deployment checks, assessed or not assessed.",
		Start:            asOf,
		End:              &asOf,
		Props:            &resultProps,
		ReviewedControls: oscal.ReviewedControls{ControlSelections: []oscal.AssessedControls{selection}},
		LocalDefinitions: &oscal.ResultLocalDefinitions{Components: &[]oscal.SystemComponent{{
			UUID: PlatformComponentUUID, Type: "software", Title: "FAIR Risk Platform",
			Description: "The FAIR Risk Platform, as described by its OSCAL component definition.",
			Status:      oscal.ComponentStatus{State: "operational"},
			Links:       &[]oscal.Link{{Href: "#" + compDefUUID, Rel: "component-definition"}},
		}}},
	}
	if len(observations) > 0 {
		result.Observations = &observations
	}
	if len(findings) > 0 {
		result.Findings = &findings
	}

	name := s.Profile.Name
	if name == "" {
		name = profile
	}
	metaProps := props("fair-profile", profile)
	return &oscal.Document{AssessmentResults: &oscal.AssessmentResultsModel{
		UUID: uuidV5("assessment-results/" + stamp),
		Metadata: oscal.Metadata{
			Title:        "FAIR Risk Platform security posture: " + name,
			LastModified: asOf,
			Version:      stamp,
			OscalVersion: oscal.Version,
			Props:        &metaProps,
		},
		ImportAp: oscal.ImportAp{Href: "#" + planUUID},
		Results:  []oscal.Result{result},
		BackMatter: &oscal.BackMatter{Resources: &[]oscal.Resource{
			{
				UUID:  planUUID,
				Title: "FAIR continuous posture assessment plan (" + profile + ")",
				Description: "Generated assessment plan: posture tests each setting's effective value against the active profile's " +
					"bounds and hard floors continuously (application drift), and the posture-scanner runs the deployment checks " +
					"every 15 minutes when Kubernetes access is granted (deployment drift).",
				Props: ptr(props("fair-profile", profile)),
			},
			{
				UUID:        compDefUUID,
				Title:       "FAIR Risk Platform component definition",
				Description: "The platform's OSCAL component definition (F-014), defining component " + PlatformComponentUUID + ".",
			},
		}},
	}}
}

// props builds name/value pairs into properties in the FAIR namespace,
// skipping empty values (OSCAL strings may not be empty).
func props(nv ...string) []oscal.Property {
	var out []oscal.Property
	for i := 0; i+1 < len(nv); i += 2 {
		out = append(out, prop(nv[i], nv[i+1])...)
	}
	return out
}

var spaceRun = regexp.MustCompile(`\s+`)

func prop(name, value string) []oscal.Property {
	value = strings.TrimSpace(spaceRun.ReplaceAllString(value, " "))
	if value == "" {
		return nil
	}
	return []oscal.Property{{Name: name, Ns: oscalNS, Value: value}}
}

func ptr[T any](v T) *T { return &v }

// oscalJSON is a JSON value as an OSCAL string: strings unquoted, other
// values compact; null and absent values are empty.
func oscalJSON(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) == nil {
		raw = buf.Bytes()
	}
	return oscalValue(raw)
}

func describeValue(raw json.RawMessage) string {
	if v := oscalJSON(raw); v != "" {
		return v
	}
	return "unset"
}

func deviationText(d string) string {
	switch d {
	case "in_bounds":
		return "within the profile's bounds"
	case "exception":
		return "outside the profile's bounds under an approved exception"
	case "out_of_bounds":
		return "outside the profile's bounds without an exception"
	case "below_floor":
		return "below the hard floor"
	case "unbound":
		return "not bound by the active profile"
	}
	return d
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	}
	return 3
}

// controlIDRE matches "AC-2(3)", "ac-2.3" and "AC-02".
var controlIDRE = regexp.MustCompile(`^([A-Za-z]{2})-0*(\d+)(?:(?:\(0*(\d+)\))|(?:\.0*(\d+)))?$`)

// oscalControlID is the 800-53r5 catalog id of a control ("AC-2(3)" ->
// "ac-2.3").
func oscalControlID(c string) (string, bool) {
	m := controlIDRE.FindStringSubmatch(strings.TrimSpace(c))
	if m == nil {
		return "", false
	}
	id := strings.ToLower(m[1]) + "-" + m[2]
	if e := cmp.Or(m[3], m[4]); e != "" {
		id += "." + e
	}
	return id, true
}

func oscalControlIDs(cs []string) []string {
	var out []string
	for _, c := range cs {
		if id, ok := oscalControlID(c); ok && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, compareControlIDs)
	return out
}

// compareControlIDs orders "ac-2" < "ac-2.3" < "ac-11" < "cm-6".
func compareControlIDs(a, b string) int {
	key := func(id string) (string, int, int) {
		fam, rest, _ := strings.Cut(id, "-")
		n, e, _ := strings.Cut(rest, ".")
		ni, _ := strconv.Atoi(n)
		ei, _ := strconv.Atoi(e)
		return fam, ni, ei
	}
	af, an, ae := key(a)
	bf, bn, be := key(b)
	return cmp.Or(strings.Compare(af, bf), cmp.Compare(an, bn), cmp.Compare(ae, be))
}

package frameworkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-08 (F-013-AC-12 to AC-15, AC-20; design §3.5, §3.7): coverage of
// a framework version, or of one of its baselines, for a business unit's
// subtree, read under the caller's row-level security by
// framework.coverage; restricted units only as their roll-up mode allows.
// Exports (CSV, JSON) apply export.reason_required to the subtree and are
// recorded as framework.coverage_exported in the transaction that read
// them: no record, no file (503).

// CoverageFormat names the JSON export.
const CoverageFormat = "fair.coverage.v1"

var (
	errReasonRequired = errors.New("frameworkapi: a reason is required")
	errAudit          = errors.New("frameworkapi: the export could not be recorded")
)

// coverageQuery reads ?bu= (required), ?baseline= and ?as_of= (a date,
// meaning the end of that day in UTC, or an RFC 3339 time).
type coverageQuery struct {
	version, bu string
	baseline    any
	asOf        any
	asOfText    string
}

func readCoverageQuery(w http.ResponseWriter, r *http.Request) (coverageQuery, bool) {
	v, ok := id(w, r)
	if !ok {
		return coverageQuery{}, false
	}
	q := r.URL.Query()
	c := coverageQuery{version: v, bu: q.Get("bu")}
	if !uuidRE.MatchString(c.bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is the business unit whose subtree's coverage is read")
		return c, false
	}
	if b := q.Get("baseline"); b != "" {
		if !uuidRE.MatchString(b) {
			problem(w, http.StatusBadRequest, "invalid_value", "baseline is a baseline's id")
			return c, false
		}
		c.baseline = b
	}
	if s := q.Get("as_of"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			d, derr := time.Parse(time.DateOnly, s)
			if derr != nil {
				problem(w, http.StatusBadRequest, "invalid_value", "as_of is a date (YYYY-MM-DD, the end of that day in UTC) or an RFC 3339 time")
				return c, false
			}
			t = d.Add(24*time.Hour - time.Microsecond)
		}
		c.asOf, c.asOfText = t.UTC(), s
	}
	return c, true
}

func (c coverageQuery) read(ctx context.Context, tx pgx.Tx) (json.RawMessage, error) {
	var raw json.RawMessage
	err := tx.QueryRow(ctx, "SELECT framework.coverage($1, $2::uuid, $3, $4::timestamptz)", c.version, c.baseline, c.bu, c.asOf).Scan(&raw)
	return raw, err
}

func (a *API) getCoverage(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	c, ok := readCoverageQuery(w, r)
	if !ok {
		return
	}
	var raw json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		raw, err = c.read(r.Context(), tx)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

func (a *API) exportCoverageCSV(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.exportCoverage(w, r, p, "csv")
}

func (a *API) exportCoverageJSON(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.exportCoverage(w, r, p, "json")
}

// Coverage is what framework.coverage answers (what the exports read).
type Coverage struct {
	Version struct {
		ID          string `json:"id"`
		Family      string `json:"family"`
		FamilyTitle string `json:"family_title"`
		Label       string `json:"label"`
		Title       string `json:"title"`
	} `json:"version"`
	Baseline *struct {
		ID    string `json:"id"`
		Key   string `json:"key"`
		Title string `json:"title"`
	} `json:"baseline"`
	BUID         string         `json:"bu_id"`
	Requirements []CoverageItem `json:"requirements"`
	Counts       map[string]int `json:"counts"`
	Restricted   *struct {
		Units  int            `json:"units"`
		Counts map[string]int `json:"counts"`
	} `json:"restricted"`
	LeftOut int `json:"left_out"`
}

// CoverageItem is one requirement's coverage.
type CoverageItem struct {
	Identifier string      `json:"identifier"`
	Label      *string     `json:"label"`
	Title      string      `json:"title"`
	State      string      `json:"state"`
	Direct     []CoveredBy `json:"direct"`
	Derived    []CoveredBy `json:"derived"`
}

// CoveredBy is a control that covers a requirement, directly or through a
// crosswalk.
type CoveredBy struct {
	Name           string  `json:"name"`
	Strength       string  `json:"strength"`
	Implementation *string `json:"implementation"`
	Via            string  `json:"via,omitempty"`
	Crosswalk      string  `json:"crosswalk,omitempty"`
	Relationship   string  `json:"relationship,omitempty"`
	Reach          string  `json:"reach,omitempty"`
}

var coverageStates = []string{"in_place", "not_in_place", "partial", "not_covered"}

func (a *API) exportCoverage(w http.ResponseWriter, r *http.Request, p authz.Principal, format string) {
	c, ok := readCoverageQuery(w, r)
	if !ok {
		return
	}
	why, err := reason.FromRequest(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_value", reason.Header+" is percent-encoded text of at most 500 characters")
		return
	}
	now := time.Now().UTC()
	var raw json.RawMessage
	var cov Coverage
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		if raw, err = c.read(r.Context(), tx); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &cov); err != nil {
			return err
		}
		// F-010's rule (OQ7): a reason where export.reason_required is in
		// force anywhere in the subtree.
		if a.Audit == nil {
			return errAudit
		}
		need, err := reason.InSubtree(r.Context(), tx, a.Reasons, c.bu)
		if err != nil {
			return fmt.Errorf("%w: %w", errAudit, err)
		}
		if need && why == "" {
			return errReasonRequired
		}
		baseline := ""
		if cov.Baseline != nil {
			baseline = cov.Baseline.Key
		}
		if err := a.Audit.Emit(audit.WithTx(r.Context(), tx), audit.Event{Type: "framework.coverage_exported", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "framework_version:" + c.version, BUID: c.bu, Reason: why, Attributes: map[string]string{
				"format": format, "framework": cov.Version.Family, "version": cov.Version.Label, "baseline": baseline, "as_of": c.asOfText,
				"requirements": fmt.Sprint(len(cov.Requirements))}}); err != nil {
			return fmt.Errorf("%w: %w", errAudit, err)
		}
		return nil
	})
	switch {
	case errors.Is(err, errReasonRequired):
		problem(w, http.StatusBadRequest, "reason_required", "export.reason_required is in force in this business unit's subtree: give a reason in "+reason.Header)
		return
	case errors.Is(err, errAudit):
		problem(w, http.StatusServiceUnavailable, "unavailable", "the export could not be recorded in the audit trail")
		return
	case err != nil:
		fail(w, err)
		return
	}
	name := fmt.Sprintf("coverage-%s-%s-%s", safeName(cov.Version.Family), safeName(cov.Version.Label), now.Format("20060102T150405Z"))
	var body []byte
	if format == "json" {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			fail(w, err)
			return
		}
		m["format"], m["exported_at"] = CoverageFormat, now.Format(time.RFC3339)
		body, _ = json.Marshal(m)
		w.Header().Set("Content-Type", "application/json")
		name += ".json"
	} else {
		var b bytes.Buffer
		if err := coverageTable(cov, c.asOfText, now).Write(&b); err != nil {
			fail(w, err)
			return
		}
		body = b.Bytes()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		name += ".csv"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// coverageTable is the CSV: metadata, then one row per requirement.
func coverageTable(c Coverage, asOf string, now time.Time) analysis.Table {
	meta := [][2]string{
		{"format", CoverageFormat},
		{"framework", c.Version.FamilyTitle},
		{"version", c.Version.Label},
		{"business_unit", c.BUID},
		{"as_of", asOf},
		{"exported_at", now.Format(time.RFC3339)},
	}
	if c.Baseline != nil {
		meta = append(meta, [2]string{"baseline", c.Baseline.Title})
	}
	for _, s := range coverageStates {
		meta = append(meta, [2]string{"count_" + s, fmt.Sprint(c.Counts[s])})
	}
	if c.Restricted != nil {
		meta = append(meta, [2]string{"restricted_units", fmt.Sprint(c.Restricted.Units)})
		for _, s := range coverageStates {
			meta = append(meta, [2]string{"restricted_count_" + s, fmt.Sprint(c.Restricted.Counts[s])})
		}
	}
	meta = append(meta, [2]string{"business_units_left_out", fmt.Sprint(c.LeftOut)})
	t := analysis.Table{Meta: meta, Header: []string{"requirement", "label", "title", "state", "direct", "through_crosswalks"}}
	for _, q := range c.Requirements {
		label := ""
		if q.Label != nil {
			label = *q.Label
		}
		t.Rows = append(t.Rows, []analysis.Cell{analysis.Text(q.Identifier), analysis.Text(label), analysis.Text(q.Title), analysis.Text(q.State),
			analysis.Text(coveredBy(q.Direct)), analysis.Text(coveredBy(q.Derived))})
	}
	return t
}

func coveredBy(cs []CoveredBy) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		impl := "unknown"
		if c.Implementation != nil {
			impl = *c.Implementation
		}
		s := fmt.Sprintf("%s (%s, %s)", c.Name, c.Strength, impl)
		if c.Via != "" {
			s += fmt.Sprintf(" via %s (%s: %s, %s)", c.Via, c.Crosswalk, c.Relationship, c.Reach)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// safeName keeps letters, digits, dots and hyphens of a file name part.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, s)
}

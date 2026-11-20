package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/internal/risk/canon"
)

// F-010 T-10 (design §3.4): what the readers share. Every reader runs in
// the requester's delegated read-only snapshot, so RLS decides what it
// sees; it reads no calibration table.

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// strictParams decodes raw into v, refusing unknown fields and trailing
// data, and returns v's canonical JSON (keys sorted).
func strictParams(raw json.RawMessage, v any) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("parameters: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parameters: one JSON object")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	m, err := canon.Parse(b)
	if err != nil {
		return nil, err
	}
	return canon.Marshal(m)
}

// num is v as a canonical decimal (a document's number cell); "" for NaN
// or infinities.
func num(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return ""
	}
	s, err := canon.Decimal(strconv.FormatFloat(v, 'f', -1, 64))
	if err != nil {
		return ""
	}
	return s
}

// numPtr is num for a nullable value.
func numPtr(v *float64) string {
	if v == nil {
		return ""
	}
	return num(*v)
}

func date(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// names are the display names report.people gives for ids (the people who
// read the register where the requester does); others stay unnamed.
func names(ctx context.Context, tx pgx.Tx, ids []string) (map[string]string, error) {
	out := map[string]string{}
	var uniq []string
	for _, id := range ids {
		if id != "" && uuidRE.MatchString(id) && !slices.Contains(uniq, id) {
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, "SELECT user_id::text, name FROM report.people($1::uuid[])", uniq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// nameOf is a person's name, or a placeholder for one the requester may
// not name.
func nameOf(names map[string]string, id string) string {
	if id == "" {
		return ""
	}
	if n, ok := names[id]; ok {
		return n
	}
	return "(not shown)"
}

// Coverage is how the requester's scope covers a BU subtree for a resource
// type (authz.rollup_coverage): BUs they read, BUs they see only in
// aggregate (restricted, Aggregate only) and BUs left out entirely.
type Coverage struct {
	Full, Aggregate, Excluded int
}

func coverage(ctx context.Context, tx pgx.Tx, resource, bu string) (Coverage, error) {
	var c Coverage
	err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE mode = 'full'), count(*) FILTER (WHERE mode = 'aggregate'),
		count(*) FILTER (WHERE mode = 'excluded') FROM authz.rollup_coverage($1, $2::uuid)`, resource, bu).Scan(&c.Full, &c.Aggregate, &c.Excluded)
	return c, err
}

// leftOutUnits adds the units a reader could not read to left and notes:
// AC-11's "not visible" and "restricted by roll-up mode", by business unit.
func (c Coverage) leftOutUnits(left map[string]int, notes *[]string) {
	if c.Excluded > 0 {
		left["units_not_visible"] = c.Excluded
		*notes = append(*notes, fmt.Sprintf("%d business units in the scope are not visible to the requester (or are restricted and excluded from roll-ups); their records are left out.", c.Excluded))
	}
	if c.Aggregate > 0 {
		left["units_aggregate_only"] = c.Aggregate
		*notes = append(*notes, fmt.Sprintf("%d restricted business units in the scope appear in roll-ups as totals only; their records are left out.", c.Aggregate))
	}
}

// runRefs are the analysis runs pinned by the given risks (as the requester
// sees them), for the metadata (AC-10).
func runRefs(ctx context.Context, tx pgx.Tx, risks []string) ([]doc.RunRef, error) {
	out := []doc.RunRef{}
	if len(risks) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (a.id) a.id::text, coalesce(s.name, ''), coalesce(a.engine_version, ''), a.seed::text, a.bundle_digest
		FROM register.risk_scenario l JOIN analysis.run a ON a.id = l.run_id LEFT JOIN risk.scenario s ON s.id = a.scenario_id
		WHERE l.risk_id = ANY ($1::uuid[]) ORDER BY a.id`, risks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r doc.RunRef
		if err := rows.Scan(&r.ID, &r.Scenario, &r.EngineVersion, &r.Seed, &r.InputDigest); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// para is a paragraph block.
func para(s string) doc.Block { return doc.Block{Kind: doc.KindParagraph, Text: s} }

func pairs(ps ...doc.Pair) doc.Block { return doc.Block{Kind: doc.KindPairs, Pairs: ps} }

func table(t *doc.Table) doc.Block {
	if t.Rows == nil {
		t.Rows = [][]string{}
	}
	return doc.Block{Kind: doc.KindTable, Table: t}
}

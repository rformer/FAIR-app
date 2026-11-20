package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-11 (F-010-AC-09 to AC-11; design §3.4): the risk report. One
// register risk the requester sees, inside the report's BU subtree: its
// description, owner and category; each linked scenario with its pinned
// run's results (F-006's views: summary by control set, the loss
// exceedance curve, the distribution, the breakdown, the drivers); the
// inputs' provenance (estimates, their sources, the estimate requests
// they came from; never a calibration record or an answer's weight); the
// treatment plan and its actions; the acceptance history.

// RiskParams name the risk.
type RiskParams struct {
	Risk string `json:"risk"`
}

// RiskKind is the risk report.
var RiskKind = Kind{Name: "risk", Title: "Risk",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p RiskParams
		out, err := strictParams(raw, &p)
		if err != nil {
			return nil, err
		}
		if !uuidRE.MatchString(p.Risk) {
			return nil, errors.New("risk is a register risk's id")
		}
		return out, nil
	},
	Read: readRisk}

// Refuse is a reader's failure that another attempt would repeat (the run
// fails at once with code).
func Refuse(code, detail string) error { return errFinal{code, detail} }

// FailNotFound means the report's subject is not visible to the requester in
// the report's scope.
const FailNotFound = "not_found"

type link struct {
	scenario, name, run, set string
	pinnedVersion            *int
}

func readRisk(ctx context.Context, tx pgx.Tx, r Run) (Built, error) {
	var p RiskParams
	if err := json.Unmarshal(r.Params, &p); err != nil {
		return Built{}, err
	}
	var title, owner, category, status, decision *string
	var body []byte
	var mean, p10, p90 *float64
	err := tx.QueryRow(ctx, `SELECT r.title, r.owner::text, c.name, `+register.StatusSQL+`, `+register.ExposureSQL("{ale,mean}")+`, `+
		register.ExposureSQL("{ale,percentiles,p10}")+`, `+register.ExposureSQL("{ale,percentiles,p90}")+`,
		CASE WHEN r.bu_id = ANY ((SELECT authz.visible_bus('treatment', 'read'))::uuid[]) THEN coalesce((SELECT t.decision FROM register.treatment t WHERE t.risk_id = r.id), 'none') END,
		(SELECT v.document FROM register.risk_version v WHERE v.risk_id = r.id AND v.version = r.current_version)
		FROM register.risk r LEFT JOIN register.category c ON c.id = r.category_id`+register.LinkStats+`
		WHERE r.id = $1 AND r.bu_id IN (SELECT register.subtree($2::uuid))`, p.Risk, r.BU.ID).
		Scan(&title, &owner, &category, &status, &mean, &p10, &p90, &decision, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return Built{}, Refuse(FailNotFound, "the risk is not visible to the requester in the report's business unit")
	}
	if err != nil {
		return Built{}, err
	}
	var rd register.Risk
	if body != nil {
		if err := json.Unmarshal(body, &rd); err != nil {
			return Built{}, err
		}
	}
	who, err := names(ctx, tx, []string{str(owner)})
	if err != nil {
		return Built{}, err
	}
	about := []doc.Pair{{Label: "Risk", Value: str(title)}, {Label: "Owner", Value: nameOf(who, str(owner))}, {Label: "Category", Value: str(category)},
		{Label: "Exposure status", Value: str(status)}, {Label: "Mean annualized loss", Value: Display(doc.ColAmount, numPtr(mean))},
		{Label: "10th percentile", Value: Display(doc.ColAmount, numPtr(p10))}, {Label: "90th percentile", Value: Display(doc.ColAmount, numPtr(p90))},
		{Label: "Treatment decision", Value: str(decision)}}
	sections := []doc.Section{{Heading: "The risk", Level: 1, Blocks: []doc.Block{pairs(about...)}}}
	if s := strings.TrimSpace(rd.Description); s != "" {
		sections[0].Blocks = append(sections[0].Blocks, para(s))
	}

	// The linked scenarios and their pinned runs.
	rows, err := tx.Query(ctx, `SELECT l.scenario_id::text, coalesce(s.name, ''), coalesce(l.run_id::text, ''), coalesce(l.control_set, ''), l.run_scenario_version
		FROM register.risk_scenario l LEFT JOIN risk.scenario s ON s.id = l.scenario_id WHERE l.risk_id = $1 ORDER BY s.name, l.scenario_id`, p.Risk)
	if err != nil {
		return Built{}, err
	}
	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.scenario, &l.name, &l.run, &l.set, &l.pinnedVersion); err != nil {
			rows.Close()
			return Built{}, err
		}
		links = append(links, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Built{}, err
	}
	runs, err := runRefs(ctx, tx, []string{p.Risk})
	if err != nil {
		return Built{}, err
	}
	notes := []string{"Estimate provenance lists sources and requests; calibration records and answer weights are never included."}
	left := map[string]int{}
	if len(links) == 0 {
		left["unquantified"] = 1
		sections = append(sections, doc.Section{Heading: "Scenarios", Level: 1, Blocks: []doc.Block{para("The risk has no linked scenario: it is unquantified.")}})
	}
	for i, l := range links {
		sec, err := scenarioSection(ctx, tx, i+1, l)
		if err != nil {
			return Built{}, err
		}
		sections = append(sections, sec...)
	}
	tsec, err := treatmentSection(ctx, tx, p.Risk)
	if err != nil {
		return Built{}, err
	}
	asec, err := acceptanceSection(ctx, tx, p.Risk)
	if err != nil {
		return Built{}, err
	}
	sections = append(sections, tsec, asec)
	d := doc.Document{Metadata: doc.Metadata{Title: "Risk: " + str(title), Filters: map[string]string{"risk": p.Risk}, Runs: runs, LeftOut: left, Notes: notes},
		Sections: sections}
	return Built{Doc: d, Risks: 1}, nil
}

// scenarioSection is one linked scenario: its pin, the run's views and the
// provenance of the version the run simulated.
func scenarioSection(ctx context.Context, tx pgx.Tx, n int, l link) ([]doc.Section, error) {
	head := doc.Section{Heading: "Scenario: " + l.name, Level: 1}
	if l.run == "" {
		head.Blocks = append(head.Blocks, para("No analysis run is pinned: the scenario does not count towards the exposure."))
		prov, err := provenanceSections(ctx, tx, n, l.scenario, nil)
		return append([]doc.Section{head}, prov...), err
	}
	var state string
	var sets []string
	var engine, seed, bundle, result *string
	var iterations int
	var version int
	err := tx.QueryRow(ctx, `SELECT state, control_sets, engine_version, seed::text, bundle_digest, result_digest, iterations, scenario_version
		FROM analysis.run WHERE id = $1`, l.run).Scan(&state, &sets, &engine, &seed, &bundle, &result, &iterations, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		head.Blocks = append(head.Blocks, para("The pinned run is not visible to the requester."))
		return []doc.Section{head}, nil
	}
	if err != nil {
		return nil, err
	}
	head.Blocks = append(head.Blocks, pairs(doc.Pair{Label: "Pinned run", Value: l.run}, doc.Pair{Label: "Control set", Value: l.set},
		doc.Pair{Label: "Scenario version", Value: strconv.Itoa(version)}, doc.Pair{Label: "Iterations", Value: Display(doc.ColNumber, strconv.Itoa(iterations))},
		doc.Pair{Label: "Engine version", Value: str(engine)}, doc.Pair{Label: "Seed", Value: str(seed)},
		doc.Pair{Label: "Input digest", Value: str(bundle)}, doc.Pair{Label: "Results digest", Value: str(result)}))
	out := []doc.Section{head}
	if state != "succeeded" {
		head.Blocks = append(head.Blocks, para("The pinned run has not succeeded ("+state+")."))
		out[0] = head
	} else {
		views, err := runViews(ctx, tx, n, l, sets, iterations)
		if err != nil {
			return nil, err
		}
		out = append(out, views...)
	}
	prov, err := provenanceSections(ctx, tx, n, l.scenario, &version)
	return append(out, prov...), err
}

func runViews(ctx context.Context, tx pgx.Tx, n int, l link, sets []string, iterations int) ([]doc.Section, error) {
	rows, err := tx.Query(ctx, `SELECT control_set, summary FROM analysis.result WHERE run_id = $1 ORDER BY array_position($2::text[], control_set)`, l.run, sets)
	if err != nil {
		return nil, err
	}
	var results []analysis.Set
	for rows.Next() {
		var s analysis.Set
		var raw []byte
		if err := rows.Scan(&s.Name, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &s.Summary); err != nil {
			rows.Close()
			return nil, err
		}
		results = append(results, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	id := func(s string) string { return fmt.Sprintf("s%d-%s", n, s) }
	summary := summaryTable(id("summary"), "Annualized loss by control set", "Control set")
	var pinned analysis.Set
	for _, s := range results {
		summary.Rows = append(summary.Rows, aleRow(s.Name, s.Summary))
		if s.Name == l.set {
			pinned = s
		}
	}
	blocks := []doc.Block{table(summary)}
	if b, ok := curveBlock(id("curve"), "Loss exceedance curve: "+l.name, l.set, pinned.Summary); ok {
		blocks = append(blocks, b)
	}
	var series []byte
	if err := tx.QueryRow(ctx, "SELECT ale FROM analysis.series WHERE run_id = $1 AND control_set = $2", l.run, l.set).Scan(&series); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if b, ok := histBlock(id("histogram"), "Distribution of annual loss: "+l.name, series, iterations); ok {
		blocks = append(blocks, b)
	}
	out := []doc.Section{{Heading: "Results", Level: 2, Blocks: blocks}}
	// Breakdown and drivers of the pinned set.
	if pinned.Summary != nil {
		_, b := analysis.BreakdownTable([]analysis.Set{pinned})
		bd := &doc.Table{ID: id("breakdown"), Caption: "Mean annual loss by part, " + l.set, Columns: []doc.Column{
			{Key: "part", Title: "Part", Type: doc.ColText}, {Key: "name", Title: "Name", Type: doc.ColText, Width: 2},
			{Key: "mean", Title: "Mean annual loss", Type: doc.ColAmount}, {Key: "share", Title: "Share", Type: doc.ColPercent}}}
		for _, r := range b {
			bd.Rows = append(bd.Rows, []string{r[1].String(), strings.ReplaceAll(r[2].String(), "_", " "), cellNum(r[3]), cellNum(r[4])})
		}
		_, sv := analysis.SensitivityTable(pinned)
		dr := &doc.Table{ID: id("drivers"), Caption: "Drivers: the inputs that move the mean most, " + l.set, Columns: []doc.Column{
			{Key: "input", Title: "Input", Type: doc.ColText, Width: 2.5}, {Key: "low", Title: "Mean at low", Type: doc.ColAmount},
			{Key: "high", Title: "Mean at high", Type: doc.ColAmount}, {Key: "swing", Title: "Swing", Type: doc.ColAmount},
			{Key: "spearman", Title: "Rank correlation", Type: doc.ColNumber}}}
		for i, r := range sv {
			if i == 10 {
				break
			}
			dr.Rows = append(dr.Rows, []string{r[1].String(), cellNum(r[7]), cellNum(r[10]), cellNum(r[12]), cellNum(r[13])})
		}
		out = append(out, doc.Section{Heading: "Breakdown and drivers", Level: 2, Blocks: []doc.Block{table(bd), table(dr)}})
	}
	return out, nil
}

// summaryTable is a table of annualized loss statistics, one row per
// subject (aleRow).
func summaryTable(id, caption, subject string) *doc.Table {
	return &doc.Table{ID: id, Caption: caption, Columns: []doc.Column{
		{Key: "subject", Title: subject, Type: doc.ColText, Width: 2}, {Key: "mean", Title: "Mean", Type: doc.ColAmount},
		{Key: "p10", Title: "10th", Type: doc.ColAmount}, {Key: "p50", Title: "50th", Type: doc.ColAmount},
		{Key: "p90", Title: "90th", Type: doc.ColAmount}, {Key: "p99", Title: "99th", Type: doc.ColAmount}}}
}

// aleRow is a summary's annualized loss: mean and percentiles.
func aleRow(name string, summary map[string]any) []string {
	ale, _ := summary["ale"].(map[string]any)
	ps, _ := ale["percentiles"].(map[string]any)
	row := []string{name, anyNum(ale["mean"])}
	for _, k := range []string{"p10", "p50", "p90", "p99"} {
		row = append(row, anyNum(ps[k]))
	}
	return row
}

// curveBlock charts a summary's loss exceedance curve (log axis), with its
// data table; false when it has none.
func curveBlock(id, title, label string, summary map[string]any) (doc.Block, bool) {
	curve := &doc.Table{ID: id, Caption: "Loss exceedance, " + label, Columns: []doc.Column{
		{Key: "loss", Title: "Annual loss", Type: doc.ColAmount}, {Key: "p", Title: "Probability of exceeding", Type: doc.ColPercent}}}
	if c, ok := summary["curve"].(map[string]any); ok {
		for _, pt := range asList(c["points"]) {
			xy, _ := pt.([]any)
			if len(xy) == 2 {
				curve.Rows = append(curve.Rows, []string{anyNum(xy[0]), anyNum(xy[1])})
			}
		}
	}
	if len(curve.Rows) == 0 {
		return doc.Block{}, false
	}
	return doc.Block{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartExceedance, Title: title,
		Alt: fmt.Sprintf("The chance that annual loss exceeds each amount, for %s; %s.", label, curveAlt(curve)), Log: true, Data: curve, XKey: "loss",
		Series: []doc.Ref{{ID: "p", Name: label}}}}, true
}

// histBlock charts the distribution of a stored series of n annual losses
// (linear bins), with its data table; false when there is nothing to bin.
func histBlock(id, title string, series []byte, n int) (doc.Block, bool) {
	v, err := analysis.Floats(series, n)
	if err != nil || len(v) == 0 {
		return doc.Block{}, false
	}
	h := analysis.LossHistogram(v, analysis.ScaleLinear)
	hist := &doc.Table{ID: id, Caption: "Distribution of annual loss", Columns: []doc.Column{
		{Key: "from", Title: "Annual loss from", Type: doc.ColAmount}, {Key: "to", Title: "to", Type: doc.ColAmount},
		{Key: "share", Title: "Share of years", Type: doc.ColPercent}}}
	for i, c := range h.Counts {
		hist.Rows = append(hist.Rows, []string{num(h.Edges[i]), num(h.Edges[i+1]), num(float64(c) / float64(h.N))})
	}
	if len(hist.Rows) == 0 {
		return doc.Block{}, false
	}
	return doc.Block{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartHistogram, Title: title,
		Alt:  fmt.Sprintf("A histogram of %d simulated years; %s of them have no loss.", h.N, Display(doc.ColPercent, num(h.ZeroShare))),
		Data: hist, XKey: "from", Series: []doc.Ref{{ID: "share", Name: "Share of years"}}}}, true
}

// curveAlt describes a curve in words: the chance of exceeding its middle point.
func curveAlt(t *doc.Table) string {
	r := t.Rows[len(t.Rows)/2]
	return fmt.Sprintf("the chance of losing more than %s is %s", Display(doc.ColAmount, r[0]), Display(doc.ColPercent, r[1]))
}

// anyNum is a decoded JSON number as a canonical decimal ("" otherwise).
func anyNum(v any) string {
	if f, ok := v.(float64); ok {
		return num(f)
	}
	return ""
}

// cellNum is a numeric analysis cell as a canonical decimal.
func cellNum(c analysis.Cell) string {
	s := c.String()
	if s == "" {
		return ""
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return ""
	}
	return num(f)
}

// provenanceSections list the estimates of the scenario's version (the
// pinned run's, or the latest) with their sources and elicitation (method,
// request, number of answers; never calibration), and the scenario's
// estimate requests.
func provenanceSections(ctx context.Context, tx pgx.Tx, n int, scenario string, version *int) ([]doc.Section, error) {
	var body []byte
	q := "SELECT document FROM risk.scenario_version WHERE scenario_id = $1 ORDER BY version DESC LIMIT 1"
	args := []any{scenario}
	if version != nil {
		q, args = "SELECT document FROM risk.scenario_version WHERE scenario_id = $1 AND version = $2", []any{scenario, *version}
	}
	if err := tx.QueryRow(ctx, q, args...).Scan(&body); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	est := &doc.Table{ID: fmt.Sprintf("s%d-estimates", n), Caption: "Estimates and their provenance", Columns: []doc.Column{
		{Key: "input", Title: "Input", Type: doc.ColText, Width: 2}, {Key: "range", Title: "Minimum, most likely, maximum", Type: doc.ColText, Width: 2},
		{Key: "confidence", Title: "Confidence", Type: doc.ColPercent}, {Key: "sources", Title: "Sources", Type: doc.ColText, Width: 2.5},
		{Key: "elicitation", Title: "Elicited", Type: doc.ColText, Width: 2}}}
	if body != nil {
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, err
		}
		walkEstimates("", v, func(ptr string, e map[string]any) {
			var srcs []string
			for _, s := range asList(e["sources"]) {
				m, _ := s.(map[string]any)
				src := fmt.Sprint(m["type"]) + ": " + fmt.Sprint(m["ref"])
				if note, _ := m["note"].(string); note != "" {
					src += " (" + note + ")"
				}
				srcs = append(srcs, src)
			}
			elicited := ""
			if el, ok := e["elicitation"].(map[string]any); ok {
				elicited = fmt.Sprintf("%v, %d answers, request %v", el["method"], len(asList(el["answers"])), el["request"])
				if imp, _ := el["imported"].(bool); imp {
					elicited += " (imported)"
				}
			}
			unit, _ := e["unit"].(string)
			conf := ""
			if c, err := decimal(e["confidence"]); err == nil {
				conf = c
			}
			est.Rows = append(est.Rows, []string{ptr, fmt.Sprintf("%v, %v, %v %s", e["min"], e["ml"], e["max"], unit), conf, strings.Join(srcs, "; "), elicited})
		})
	}
	reqs := &doc.Table{ID: fmt.Sprintf("s%d-requests", n), Caption: "Estimate requests", Columns: []doc.Column{
		{Key: "title", Title: "Request", Type: doc.ColText, Width: 2.5}, {Key: "version", Title: "Scenario version", Type: doc.ColNumber},
		{Key: "status", Title: "Status", Type: doc.ColText}, {Key: "due", Title: "Due", Type: doc.ColDate}, {Key: "created", Title: "Created", Type: doc.ColDate}}}
	rows, err := tx.Query(ctx, `SELECT title, scenario_version, status, due_at, created_at FROM estimate.request WHERE scenario_id = $1 ORDER BY seq`, scenario)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var title, status string
		var v int
		var due, created time.Time
		if err := rows.Scan(&title, &v, &status, &due, &created); err != nil {
			rows.Close()
			return nil, err
		}
		reqs.Rows = append(reqs.Rows, []string{title, strconv.Itoa(v), status, date(&due), date(&created)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return []doc.Section{{Heading: "Provenance", Level: 2, Blocks: []doc.Block{table(est), table(reqs)}}}, nil
}

// walkEstimates calls fn for every estimate (an object with min, ml, max
// and unit) in v, by JSON pointer, in key order.
func walkEstimates(ptr string, v any, fn func(string, map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		_, a := x["min"]
		_, b := x["ml"]
		_, c := x["max"]
		if _, d := x["unit"]; a && b && c && d {
			fn(ptr, x)
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			walkEstimates(ptr+"/"+k, x[k], fn)
		}
	case []any:
		for i, e := range x {
			walkEstimates(ptr+"/"+strconv.Itoa(i), e, fn)
		}
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// decimal is a JSON decimal (a number or a decimal string) as a canonical decimal.
func decimal(v any) (string, error) {
	switch x := v.(type) {
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return "", err
		}
		return num(f), nil
	case float64:
		return num(x), nil
	}
	return "", errors.New("not a number")
}

// treatmentSection is the risk's treatment plan as the requester sees it.
func treatmentSection(ctx context.Context, tx pgx.Tx, risk string) (doc.Section, error) {
	sec := doc.Section{Heading: "Treatment", Level: 1}
	var body []byte
	var version int
	err := tx.QueryRow(ctx, `SELECT v.document, t.current_version FROM register.treatment t
		JOIN register.treatment_version v ON v.risk_id = t.risk_id AND v.version = t.current_version WHERE t.risk_id = $1`, risk).Scan(&body, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		sec.Blocks = append(sec.Blocks, para("No treatment plan the requester can see."))
		return sec, nil
	}
	if err != nil {
		return sec, err
	}
	tr, err := register.DecodeTreatment(body)
	if err != nil {
		return sec, err
	}
	dec := "none"
	if tr.Decision != nil {
		dec = *tr.Decision
	}
	sec.Blocks = append(sec.Blocks, pairs(doc.Pair{Label: "Decision", Value: dec}, doc.Pair{Label: "Plan version", Value: strconv.Itoa(version)}))
	if s := strings.TrimSpace(tr.Rationale); s != "" {
		sec.Blocks = append(sec.Blocks, para(s))
	}
	day, err := today(ctx, tx)
	if err != nil {
		return sec, err
	}
	var owners []string
	for _, a := range tr.Actions {
		owners = append(owners, a.Owner)
	}
	who, err := names(ctx, tx, owners)
	if err != nil {
		return sec, err
	}
	t := &doc.Table{ID: "actions", Caption: "Actions", Columns: []doc.Column{{Key: "due", Title: "Due", Type: doc.ColDate},
		{Key: "action", Title: "Action", Type: doc.ColText, Width: 3}, {Key: "owner", Title: "Owner", Type: doc.ColText, Width: 1.5},
		{Key: "state", Title: "State", Type: doc.ColText}, {Key: "overdue", Title: "Overdue", Type: doc.ColText}}}
	for _, a := range tr.Actions {
		overdue := "no"
		if a.Overdue(day) {
			overdue = "yes"
		}
		t.Rows = append(t.Rows, []string{a.Due, a.Title, nameOf(who, a.Owner), strings.ReplaceAll(a.State, "_", " "), overdue})
	}
	sec.Blocks = append(sec.Blocks, table(t))
	return sec, nil
}

// acceptanceSection is the risk's acceptance history: every step of every
// acceptance the requester sees.
func acceptanceSection(ctx context.Context, tx pgx.Tx, risk string) (doc.Section, error) {
	sec := doc.Section{Heading: "Acceptance history", Level: 1}
	rows, err := tx.Query(ctx, `SELECT s.at, s.kind, coalesce(s.actor::text, ''), coalesce(s.reason, ''), x.tier, x.expires_on, `+effective+`
		FROM acceptance.step s JOIN acceptance.acceptance x ON x.id = s.acceptance_id WHERE x.risk_id = $1 ORDER BY s.at, x.seq, s.n`, risk)
	if err != nil {
		return sec, err
	}
	type step struct {
		at                         time.Time
		kind, actor, reason, state string
		tier                       int
		expires                    time.Time
	}
	var steps []step
	for rows.Next() {
		var s step
		if err := rows.Scan(&s.at, &s.kind, &s.actor, &s.reason, &s.tier, &s.expires, &s.state); err != nil {
			rows.Close()
			return sec, err
		}
		steps = append(steps, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return sec, err
	}
	var ids []string
	for _, s := range steps {
		ids = append(ids, s.actor)
	}
	who, err := acceptancePeople(ctx, tx, ids)
	if err != nil {
		return sec, err
	}
	t := &doc.Table{ID: "acceptance-history", Caption: "Acceptance steps, oldest first", Columns: []doc.Column{
		{Key: "at", Title: "When", Type: doc.ColTime}, {Key: "step", Title: "Step", Type: doc.ColText}, {Key: "by", Title: "By", Type: doc.ColText, Width: 1.5},
		{Key: "tier", Title: "Tier", Type: doc.ColNumber}, {Key: "expires", Title: "Expires", Type: doc.ColDate}, {Key: "reason", Title: "Reason", Type: doc.ColText, Width: 3}}}
	for _, s := range steps {
		by := "the system"
		if s.actor != "" {
			by = nameOf(who, s.actor)
		}
		t.Rows = append(t.Rows, []string{s.at.UTC().Format(time.RFC3339), strings.ReplaceAll(s.kind, "_", " "), by, strconv.Itoa(s.tier),
			s.expires.Format(time.DateOnly), s.reason})
	}
	if len(steps) == 0 {
		sec.Blocks = append(sec.Blocks, para("No acceptance the requester can see."))
	}
	sec.Blocks = append(sec.Blocks, table(t))
	return sec, nil
}

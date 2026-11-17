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

	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-10 (F-010-AC-08, AC-10, AC-11; design §3.4): the register report.
// One row per open risk in the BU's subtree the requester sees, with the
// register's own status, exposure and acceptance SQL (register.StatusSQL,
// ExposureSQL, AcceptanceSQL), so it agrees with the register API.

// RegisterParams are the register report's filters, as the register
// list's (status, owner, category, decision, acceptance).
type RegisterParams struct {
	Acceptance string `json:"acceptance,omitempty"`
	Category   string `json:"category,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Status     string `json:"status,omitempty"`
}

var (
	statuses    = []string{"current", "stale", "unquantified", "computing"}
	decisions   = []string{"mitigate", "transfer", "avoid", "accept", "none"}
	acceptances = []string{"active", "pending", "suspended", "expired", "needs_review", "expiring", "none"}
)

func (p RegisterParams) check() error {
	switch {
	case p.Status != "" && !slices.Contains(statuses, p.Status):
		return errors.New("status is current, stale, unquantified or computing")
	case p.Decision != "" && !slices.Contains(decisions, p.Decision):
		return errors.New("decision is mitigate, transfer, avoid, accept or none")
	case p.Acceptance != "" && !slices.Contains(acceptances, p.Acceptance):
		return errors.New("acceptance is active, pending, suspended, expired, needs_review, expiring or none")
	case p.Owner != "" && !uuidRE.MatchString(p.Owner):
		return errors.New("owner is a user id")
	case p.Category != "" && !uuidRE.MatchString(p.Category):
		return errors.New("category is a category id")
	}
	return nil
}

// RegisterKind is the register report.
var RegisterKind = Kind{Name: "register", Title: "Risk register",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p RegisterParams
		out, err := strictParams(raw, &p)
		if err != nil {
			return nil, err
		}
		return out, p.check()
	},
	Read: readRegister}

// registerSQL lists the open risks of $1's subtree the caller sees, with
// filters (as registerapi's list).
func registerSQL(p RegisterParams) (string, []any) {
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	where := []string{"r.state = 'open'", "r.bu_id IN (SELECT register.subtree(" + arg("") + "::uuid))"}
	if p.Owner != "" {
		where = append(where, "r.owner = "+arg(p.Owner)+"::uuid")
	}
	if p.Category != "" {
		where = append(where, "r.category_id = "+arg(p.Category)+"::uuid")
	}
	if p.Status != "" {
		where = append(where, "("+register.StatusSQL+") = "+arg(p.Status))
	}
	const seesTreatment = "r.bu_id = ANY ((SELECT authz.visible_bus('treatment', 'read'))::uuid[])"
	switch p.Decision {
	case "":
	case "none":
		where = append(where, seesTreatment, "NOT EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision IS NOT NULL)")
	default:
		where = append(where, seesTreatment, "EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision = "+arg(p.Decision)+")")
	}
	switch p.Acceptance {
	case "":
	case "none":
		where = append(where, "("+register.AcceptanceSQL+") IS NULL")
	case "needs_review":
		where = append(where, "jsonb_array_length(("+register.AcceptanceSQL+") -> 'needs_review') > 0")
	case "expiring":
		where = append(where, "("+register.AcceptanceSQL+") ->> 'state' = 'active' AND (("+register.AcceptanceSQL+") ->> 'expires_on')::date <= current_date + 30")
	default:
		where = append(where, "("+register.AcceptanceSQL+") ->> 'state' = "+arg(p.Acceptance))
	}
	mean := register.ExposureSQL("{ale,mean}")
	sql := `SELECT r.id::text, r.title, r.owner::text, c.name, ` + register.StatusSQL + `, ` + mean + `, ` + register.ExposureSQL("{ale,percentiles,p10}") + `, ` +
		register.ExposureSQL("{ale,percentiles,p90}") + `,
		CASE WHEN ` + seesTreatment + ` THEN coalesce((SELECT t.decision FROM register.treatment t WHERE t.risk_id = r.id), 'none') END, ` + register.AcceptanceSQL + `
		FROM register.risk r LEFT JOIN register.category c ON c.id = r.category_id` + register.LinkStats + `
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + mean + ` DESC NULLS LAST, lower(r.title), r.id`
	return sql, args
}

// RegisterRow is one risk of the register report.
type RegisterRow struct {
	ID, Title, Owner, Category, Status, Decision string
	Mean, P10, P90                               *float64
	Acceptance                                   string // state, or ""
	Expires                                      string // the acceptance's expiry, or ""
}

// RegisterRows reads the register report's rows in tx (the caller's view).
func RegisterRows(ctx context.Context, tx pgx.Tx, bu string, p RegisterParams) ([]RegisterRow, error) {
	sql, args := registerSQL(p)
	args[0] = bu
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegisterRow
	for rows.Next() {
		var x RegisterRow
		var title, owner, cat, decision *string
		var acc []byte
		if err := rows.Scan(&x.ID, &title, &owner, &cat, &x.Status, &x.Mean, &x.P10, &x.P90, &decision, &acc); err != nil {
			return nil, err
		}
		x.Title, x.Owner, x.Category, x.Decision = str(title), str(owner), str(cat), str(decision)
		if acc != nil {
			var a struct {
				State   string `json:"state"`
				Expires string `json:"expires_on"`
			}
			if err := json.Unmarshal(acc, &a); err != nil {
				return nil, err
			}
			x.Acceptance, x.Expires = a.State, a.Expires
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func readRegister(ctx context.Context, tx pgx.Tx, r Run) (Built, error) {
	var p RegisterParams
	if err := json.Unmarshal(r.Params, &p); err != nil {
		return Built{}, err
	}
	risks, err := RegisterRows(ctx, tx, r.BU.ID, p)
	if err != nil {
		return Built{}, err
	}
	var owners, ids []string
	for _, x := range risks {
		owners = append(owners, x.Owner)
		ids = append(ids, x.ID)
	}
	who, err := names(ctx, tx, owners)
	if err != nil {
		return Built{}, err
	}
	t := &doc.Table{ID: "risks", Caption: "Open risks by mean annualized loss", Columns: []doc.Column{
		{Key: "risk", Title: "Risk", Type: doc.ColText, Width: 3}, {Key: "owner", Title: "Owner", Type: doc.ColText, Width: 1.5},
		{Key: "category", Title: "Category", Type: doc.ColText, Width: 1.2}, {Key: "mean", Title: "Mean", Type: doc.ColAmount},
		{Key: "p10", Title: "10th percentile", Type: doc.ColAmount}, {Key: "p90", Title: "90th percentile", Type: doc.ColAmount},
		{Key: "status", Title: "Exposure status", Type: doc.ColText}, {Key: "decision", Title: "Treatment", Type: doc.ColText},
		{Key: "acceptance", Title: "Acceptance", Type: doc.ColText}, {Key: "expires", Title: "Acceptance expires", Type: doc.ColDate}}}
	count := map[string]int{}
	var sum float64
	summed := 0
	for _, x := range risks {
		t.Rows = append(t.Rows, []string{x.Title, nameOf(who, x.Owner), x.Category, numPtr(x.Mean), numPtr(x.P10), numPtr(x.P90), x.Status,
			x.Decision, x.Acceptance, x.Expires})
		count[x.Status]++
		if x.Mean != nil {
			sum += *x.Mean
			summed++
		}
	}
	runs, err := runRefs(ctx, tx, ids)
	if err != nil {
		return Built{}, err
	}
	cov, err := coverage(ctx, tx, "register", r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	left := map[string]int{"unquantified": count["unquantified"]}
	notes := []string{}
	if n := len(risks) - summed; n > 0 {
		notes = append(notes, fmt.Sprintf("%d open risks have no exposure the requester can see (unquantified, or computing); they are listed without figures and left out of the sum.", n))
	}
	cov.leftOutUnits(left, &notes)
	d := doc.Document{Metadata: doc.Metadata{Title: "Risk register: " + r.BU.Name, Filters: p.filters(), Runs: runs, LeftOut: left, Notes: notes},
		Sections: []doc.Section{
			{Heading: "Summary", Level: 1, Blocks: []doc.Block{
				pairs(doc.Pair{Label: "Open risks", Value: strconv.Itoa(len(risks))}, doc.Pair{Label: "Current", Value: strconv.Itoa(count["current"])},
					doc.Pair{Label: "Stale", Value: strconv.Itoa(count["stale"])}, doc.Pair{Label: "Computing", Value: strconv.Itoa(count["computing"])},
					doc.Pair{Label: "Unquantified", Value: strconv.Itoa(count["unquantified"])},
					doc.Pair{Label: "Sum of mean annualized losses (" + strconv.Itoa(summed) + " risks; a sum of means, not a percentile of the total)", Value: Display(doc.ColAmount, num(sum))}),
			}},
			{Heading: "Risks", Level: 1, Blocks: []doc.Block{table(t)}},
		}}
	return Built{Doc: d, Risks: len(risks)}, nil
}

func (p RegisterParams) filters() map[string]string {
	f := map[string]string{}
	for k, v := range map[string]string{"status": p.Status, "owner": p.Owner, "category": p.Category, "decision": p.Decision, "acceptance": p.Acceptance} {
		if v != "" {
			f[k] = v
		}
	}
	return f
}

// today is the date the database reads in tx (current_date).
func today(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var d time.Time
	err := tx.QueryRow(ctx, "SELECT current_date").Scan(&d)
	return d, err
}

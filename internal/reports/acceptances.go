package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-10 (F-010-AC-08, AC-10, AC-11; design §3.4): the acceptances
// report: the acceptances of the BU's subtree the requester sees, by state
// as read (F-008's effective state), those expiring within N days, and the
// decisions in a period with their tier, approver and reason.

// AcceptanceParams are the acceptances report's filters.
type AcceptanceParams struct {
	DecidedFrom    string `json:"decided_from,omitempty"` // YYYY-MM-DD; default 90 days before decided_to
	DecidedTo      string `json:"decided_to,omitempty"`   // YYYY-MM-DD; default today
	ExpiringWithin *int   `json:"expiring_within,omitempty"`
}

func (p AcceptanceParams) check() error {
	if p.ExpiringWithin != nil && (*p.ExpiringWithin < 0 || *p.ExpiringWithin > 3650) {
		return errors.New("expiring_within is 0 to 3,650 days")
	}
	var from, to time.Time
	var err error
	if p.DecidedFrom != "" {
		if from, err = time.Parse(time.DateOnly, p.DecidedFrom); err != nil {
			return errors.New("decided_from is a date (YYYY-MM-DD)")
		}
	}
	if p.DecidedTo != "" {
		if to, err = time.Parse(time.DateOnly, p.DecidedTo); err != nil {
			return errors.New("decided_to is a date (YYYY-MM-DD)")
		}
	}
	if p.DecidedFrom != "" && p.DecidedTo != "" && from.After(to) {
		return errors.New("decided_from is on or before decided_to")
	}
	return nil
}

// AcceptancesKind is the acceptances report.
var AcceptancesKind = Kind{Name: "acceptances", Title: "Risk acceptances",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p AcceptanceParams
		out, err := strictParams(raw, &p)
		if err != nil {
			return nil, err
		}
		return out, p.check()
	},
	Read: readAcceptances}

// effective is an acceptance's state as read (F-008 design §3.2).
const effective = `CASE WHEN x.state IN ('active', 'suspended') AND x.expires_on <= current_date THEN 'expired' ELSE x.state END`

// AcceptanceRow is one acceptance of the report.
type AcceptanceRow struct {
	ID, Risk, State, RequestedBy string
	Tier                         int
	Mean                         float64
	Expires                      time.Time
}

// AcceptanceRows are the acceptances of bu's subtree the caller sees, but
// those ended (withdrawn, rejected, revoked, replaced, risk closed), newest
// first.
func AcceptanceRows(ctx context.Context, tx pgx.Tx, bu string) ([]AcceptanceRow, error) {
	rows, err := tx.Query(ctx, `SELECT x.id::text, coalesce(r.title, ''), `+effective+`, x.requested_by::text, x.tier, x.mean::float8, x.expires_on
		FROM acceptance.acceptance x LEFT JOIN register.risk r ON r.id = x.risk_id
		WHERE x.bu_id IN (SELECT acceptance.subtree($1::uuid)) AND x.state <> 'ended'
		ORDER BY x.seq DESC`, bu)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AcceptanceRow
	for rows.Next() {
		var a AcceptanceRow
		if err := rows.Scan(&a.ID, &a.Risk, &a.State, &a.RequestedBy, &a.Tier, &a.Mean, &a.Expires); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type decision struct {
	at                            time.Time
	risk, kind, actor, reason, id string
	tier                          int
}

func readAcceptances(ctx context.Context, tx pgx.Tx, r Run) (Built, error) {
	var p AcceptanceParams
	if err := json.Unmarshal(r.Params, &p); err != nil {
		return Built{}, err
	}
	day, err := today(ctx, tx)
	if err != nil {
		return Built{}, err
	}
	within := 30
	if p.ExpiringWithin != nil {
		within = *p.ExpiringWithin
	}
	to := day
	if p.DecidedTo != "" {
		to, _ = time.Parse(time.DateOnly, p.DecidedTo)
	}
	from := to.AddDate(0, 0, -90)
	if p.DecidedFrom != "" {
		from, _ = time.Parse(time.DateOnly, p.DecidedFrom)
	}
	all, err := AcceptanceRows(ctx, tx, r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	rows, err := tx.Query(ctx, `SELECT s.at, coalesce(r.title, ''), s.kind, coalesce(s.actor::text, ''), coalesce(s.reason, ''), x.id::text, x.tier
		FROM acceptance.step s JOIN acceptance.acceptance x ON x.id = s.acceptance_id LEFT JOIN register.risk r ON r.id = x.risk_id
		WHERE x.bu_id IN (SELECT acceptance.subtree($1::uuid)) AND s.kind IN ('approved', 'rejected', 'revoked')
		  AND s.at >= $2::date AND s.at < $3::date + 1
		ORDER BY s.at, x.id, s.n`, r.BU.ID, from, to)
	if err != nil {
		return Built{}, err
	}
	var decided []decision
	for rows.Next() {
		var d decision
		if err := rows.Scan(&d.at, &d.risk, &d.kind, &d.actor, &d.reason, &d.id, &d.tier); err != nil {
			rows.Close()
			return Built{}, err
		}
		decided = append(decided, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Built{}, err
	}
	var ids []string
	for _, a := range all {
		ids = append(ids, a.RequestedBy)
	}
	for _, d := range decided {
		ids = append(ids, d.actor)
	}
	who, err := acceptancePeople(ctx, tx, ids)
	if err != nil {
		return Built{}, err
	}
	cols := []doc.Column{{Key: "risk", Title: "Risk", Type: doc.ColText, Width: 3}, {Key: "state", Title: "State", Type: doc.ColText},
		{Key: "tier", Title: "Tier", Type: doc.ColNumber}, {Key: "mean", Title: "Mean accepted", Type: doc.ColAmount},
		{Key: "expires", Title: "Expires", Type: doc.ColDate}, {Key: "requested_by", Title: "Requested by", Type: doc.ColText, Width: 1.5}}
	open := &doc.Table{ID: "acceptances", Caption: "Acceptances by state", Columns: cols}
	expiring := &doc.Table{ID: "expiring", Caption: fmt.Sprintf("Active acceptances expiring within %d days", within), Columns: cols}
	order := []string{"pending", "active", "suspended", "expired"}
	slices.SortStableFunc(all, func(a, b AcceptanceRow) int {
		if d := slices.Index(order, a.State) - slices.Index(order, b.State); d != 0 {
			return d
		}
		return a.Expires.Compare(b.Expires)
	})
	count := map[string]int{}
	limit := day.AddDate(0, 0, within)
	for _, a := range all {
		row := []string{a.Risk, a.State, strconv.Itoa(a.Tier), num(a.Mean), a.Expires.Format(time.DateOnly), nameOf(who, a.RequestedBy)}
		open.Rows = append(open.Rows, row)
		count[a.State]++
		if a.State == "active" && !a.Expires.After(limit) {
			expiring.Rows = append(expiring.Rows, row)
			count["expiring"]++
		}
	}
	dec := &doc.Table{ID: "decisions", Caption: fmt.Sprintf("Decisions from %s to %s", from.Format(time.DateOnly), to.Format(time.DateOnly)), Columns: []doc.Column{
		{Key: "at", Title: "When", Type: doc.ColTime}, {Key: "risk", Title: "Risk", Type: doc.ColText, Width: 2.5}, {Key: "tier", Title: "Tier", Type: doc.ColNumber},
		{Key: "decision", Title: "Decision", Type: doc.ColText}, {Key: "by", Title: "By", Type: doc.ColText, Width: 1.5},
		{Key: "reason", Title: "Reason", Type: doc.ColText, Width: 3}}}
	for _, d := range decided {
		dec.Rows = append(dec.Rows, []string{d.at.UTC().Format(time.RFC3339), d.risk, strconv.Itoa(d.tier), d.kind, nameOf(who, d.actor), d.reason})
	}
	cov, err := coverage(ctx, tx, "acceptance", r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	left, notes := map[string]int{}, []string{}
	cov.leftOutUnits(left, &notes)
	filters := map[string]string{"expiring_within": strconv.Itoa(within), "decided_from": from.Format(time.DateOnly), "decided_to": to.Format(time.DateOnly)}
	d := doc.Document{Metadata: doc.Metadata{Title: "Risk acceptances: " + r.BU.Name, Filters: filters, LeftOut: left, Notes: notes},
		Sections: []doc.Section{
			{Heading: "Summary", Level: 1, Blocks: []doc.Block{pairs(
				doc.Pair{Label: "Active", Value: strconv.Itoa(count["active"])},
				doc.Pair{Label: fmt.Sprintf("Expiring within %d days", within), Value: strconv.Itoa(count["expiring"])},
				doc.Pair{Label: "Expired", Value: strconv.Itoa(count["expired"])},
				doc.Pair{Label: "Suspended", Value: strconv.Itoa(count["suspended"])},
				doc.Pair{Label: "Awaiting decision", Value: strconv.Itoa(count["pending"])},
				doc.Pair{Label: "Decisions in the period", Value: strconv.Itoa(len(decided))})}},
			{Heading: "Acceptances", Level: 1, Blocks: []doc.Block{table(open)}},
			{Heading: "Expiring", Level: 1, Blocks: []doc.Block{table(expiring)}},
			{Heading: "Decisions", Level: 1, Blocks: []doc.Block{table(dec)}},
		}}
	return Built{Doc: d, Risks: len(all)}, nil
}

// acceptancePeople names requesters and deciders as the acceptance API does
// (acceptance.people).
func acceptancePeople(ctx context.Context, tx pgx.Tx, ids []string) (map[string]string, error) {
	out := map[string]string{}
	var uniq []string
	for _, id := range ids {
		if uuidRE.MatchString(id) && !slices.Contains(uniq, id) {
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, "SELECT user_id::text, name FROM acceptance.people($1::uuid[])", uniq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

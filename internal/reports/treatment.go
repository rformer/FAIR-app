package reports

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-10 (F-010-AC-08, AC-10, AC-11; design §3.4): the treatment
// report: the actions of the current treatment plans of the open risks of
// the BU's subtree the requester sees (risk and treatment alike), overdue
// first, then by due date and owner, with each risk's decision.

// TreatmentParams are the treatment report's filters.
type TreatmentParams struct {
	Owner string `json:"owner,omitempty"` // an action owner's user id
}

// TreatmentKind is the treatment report.
var TreatmentKind = Kind{Name: "treatment", Title: "Treatment progress",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p TreatmentParams
		out, err := strictParams(raw, &p)
		if err != nil {
			return nil, err
		}
		if p.Owner != "" && !uuidRE.MatchString(p.Owner) {
			return nil, errors.New("owner is a user id")
		}
		return out, nil
	},
	Read: readTreatment}

// ActionRow is one action of the treatment report.
type ActionRow struct {
	RiskID, Risk, Decision string
	register.Action
	Overdue bool
}

// ActionRows are the actions (cancelled ones left out) of bu's subtree as
// the caller sees them, overdue first, then by due date, owner and title.
func ActionRows(ctx context.Context, tx pgx.Tx, bu, owner string, day time.Time) ([]ActionRow, error) {
	rows, err := tx.Query(ctx, `SELECT r.id::text, r.title, t.decision, v.document
		FROM register.treatment t JOIN register.treatment_version v ON v.risk_id = t.risk_id AND v.version = t.current_version
		JOIN register.risk r ON r.id = t.risk_id
		WHERE r.state = 'open' AND r.bu_id IN (SELECT register.subtree($1::uuid))
		ORDER BY r.id`, bu)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionRow
	for rows.Next() {
		var id string
		var title, decision *string
		var body []byte
		if err := rows.Scan(&id, &title, &decision, &body); err != nil {
			return nil, err
		}
		tr, err := register.DecodeTreatment(body)
		if err != nil {
			return nil, err
		}
		for _, a := range tr.Actions {
			if a.State == "cancelled" || (owner != "" && a.Owner != owner) {
				continue
			}
			dec := "none"
			if decision != nil {
				dec = *decision
			}
			out = append(out, ActionRow{RiskID: id, Risk: str(title), Decision: dec, Action: a, Overdue: a.Overdue(day)})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(out, func(a, b ActionRow) int {
		switch {
		case a.Overdue != b.Overdue:
			if a.Overdue {
				return -1
			}
			return 1
		case a.Due != b.Due:
			return strings.Compare(a.Due, b.Due)
		case a.Owner != b.Owner:
			return strings.Compare(a.Owner, b.Owner)
		}
		return strings.Compare(a.Title, b.Title)
	})
	return out, nil
}

func readTreatment(ctx context.Context, tx pgx.Tx, r Run) (Built, error) {
	var p TreatmentParams
	if err := json.Unmarshal(r.Params, &p); err != nil {
		return Built{}, err
	}
	day, err := today(ctx, tx)
	if err != nil {
		return Built{}, err
	}
	actions, err := ActionRows(ctx, tx, r.BU.ID, p.Owner, day)
	if err != nil {
		return Built{}, err
	}
	var ids []string
	for _, a := range actions {
		ids = append(ids, a.Owner)
	}
	who, err := names(ctx, tx, ids)
	if err != nil {
		return Built{}, err
	}
	t := &doc.Table{ID: "actions", Caption: "Actions, overdue first, by due date and owner", Columns: []doc.Column{
		{Key: "due", Title: "Due", Type: doc.ColDate}, {Key: "action", Title: "Action", Type: doc.ColText, Width: 3},
		{Key: "owner", Title: "Owner", Type: doc.ColText, Width: 1.5}, {Key: "state", Title: "State", Type: doc.ColText},
		{Key: "overdue", Title: "Overdue", Type: doc.ColText}, {Key: "risk", Title: "Risk", Type: doc.ColText, Width: 2.5},
		{Key: "decision", Title: "Decision", Type: doc.ColText}}}
	count := map[string]int{}
	risks := map[string]bool{}
	for _, a := range actions {
		risks[a.RiskID] = true
		overdue := "no"
		if a.Overdue {
			overdue = "yes"
			count["overdue"]++
		}
		if a.State == "planned" || a.State == "in_progress" {
			count["open"]++
		}
		t.Rows = append(t.Rows, []string{a.Due, a.Title, nameOf(who, a.Owner), strings.ReplaceAll(a.State, "_", " "), overdue, a.Risk, a.Decision})
	}
	cov, err := coverage(ctx, tx, "treatment", r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	left, notes := map[string]int{}, []string{"Actions of risks whose treatment or register entry the requester cannot see are not listed."}
	cov.leftOutUnits(left, &notes)
	filters := map[string]string{}
	if p.Owner != "" {
		filters["owner"] = p.Owner
	}
	d := doc.Document{Metadata: doc.Metadata{Title: "Treatment progress: " + r.BU.Name, Filters: filters, LeftOut: left, Notes: notes},
		Sections: []doc.Section{
			{Heading: "Summary", Level: 1, Blocks: []doc.Block{pairs(
				doc.Pair{Label: "Open actions", Value: strconv.Itoa(count["open"])},
				doc.Pair{Label: "Overdue actions", Value: strconv.Itoa(count["overdue"])},
				doc.Pair{Label: "Actions listed (done included, cancelled left out)", Value: strconv.Itoa(len(actions))})}},
			{Heading: "Actions", Level: 1, Blocks: []doc.Block{table(t)}},
		}}
	return Built{Doc: d, Risks: len(risks)}, nil
}

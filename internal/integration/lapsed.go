package integration

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// F-011 T-13 (F-011-AC-24; design §3.7): a control a scenario relies on
// that is no longer in place, computed on read under the reader's RLS.

// Lapse is a use of a control as in place, in a current control set of a
// scenario's latest version, whose latest control version (as the reader
// sees it) records another status.
type Lapse struct {
	ScenarioID string  `json:"scenario_id"`
	ControlID  string  `json:"control_id"`
	Status     string  `json:"status"`
	AssessedOn *string `json:"assessed_on"`
}

// ControlLapsed reads the lapses of the scenarios in tx, by scenario.
// Scenarios and controls the reader cannot see are left out.
func ControlLapsed(ctx context.Context, tx pgx.Tx, scenarios []string) (map[string][]Lapse, error) {
	out := map[string][]Lapse{}
	if len(scenarios) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.id::text, c.id::text, cd.d #>> '{implementation,status}', cd.d #>> '{implementation,assessed_on}'
		FROM risk.scenario s
		JOIN risk.scenario_version v ON v.scenario_id = s.id AND v.version = s.current_version
		CROSS JOIN LATERAL jsonb_array_elements(convert_from(v.document, 'UTF8')::jsonb -> 'control_sets') cs
		CROSS JOIN LATERAL jsonb_array_elements(cs -> 'controls') cu
		JOIN risk.control c ON c.id::text = cu ->> 'id'
		JOIN risk.control_version x ON x.control_id = c.id AND x.version = c.current_version
		CROSS JOIN LATERAL (SELECT convert_from(x.document, 'UTF8')::jsonb AS d) cd
		WHERE s.id = ANY ($1::uuid[]) AND (cs ->> 'current')::boolean AND cu ->> 'status' = 'in_place'
		  AND cd.d #>> '{implementation,status}' IS NOT NULL AND cd.d #>> '{implementation,status}' <> 'in_place'
		ORDER BY 1, 2`, scenarios)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l Lapse
		if err := rows.Scan(&l.ScenarioID, &l.ControlID, &l.Status, &l.AssessedOn); err != nil {
			return nil, err
		}
		out[l.ScenarioID] = append(out[l.ScenarioID], l)
	}
	return out, rows.Err()
}

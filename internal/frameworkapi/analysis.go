package frameworkapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-09 (F-013-AC-16, AC-18; design §3.6): from requirements to
// analysis. Everything risk-side is read under the caller's row-level
// security (framework.requirement_scenarios and framework.addressed are
// invoker functions).

// getRequirementScenarios answers the controls mapped to the requirement,
// their FAIR effects, and the scenarios that use them in a current control
// set or, in the controls' subtrees, could (?limit= 1 to 200, 200).
func (a *API) getRequirementScenarios(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	v, ok := id(w, r)
	if !ok {
		return
	}
	limit, _, ok := page(w, r, 200, 200)
	if ok {
		a.answer(w, r, p, "SELECT framework.requirement_scenarios($1, $2)", v, limit)
	}
}

// Addressed is, for the given scenarios, the requirements the controls of
// their latest versions' current control sets map to, by framework version
// (the register's risk view, AC-18), as the caller in tx may read them.
func Addressed(ctx context.Context, tx pgx.Tx, scenarios []string) (json.RawMessage, error) {
	if len(scenarios) == 0 {
		return json.RawMessage("[]"), nil
	}
	var raw json.RawMessage
	err := tx.QueryRow(ctx, "SELECT framework.addressed($1::uuid[])", scenarios).Scan(&raw)
	return raw, err
}

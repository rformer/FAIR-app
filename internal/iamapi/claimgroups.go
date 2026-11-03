package iamapi

import (
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Claim groups (T-24b, AC-12, AC-13): the groups an IdP's group claim
// (the group_claim setting) may put a user in at sign-in. An administrator
// declares each with the value the IdP sends and a display name; values
// nobody declared are ignored. Mappings (T-24) then take them like any
// group. idp.view to list, idp.manage to add or remove (checked by the
// database), audited high; removal is refused while a mapping uses one.

type claimGroup struct {
	ID          string    `json:"id"`
	ClaimValue  string    `json:"claim_value"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	Members     int       `json:"members"`
	Mappings    int       `json:"mappings"`
}

// validClaimName: a group_claim setting is a string of 1 to 256 printable
// characters (a SAML attribute name may be a URI).
func validClaimName(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > 256 {
		return false
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

func (a *API) listClaimGroups(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out := []claimGroup{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, claim_value, display_name, created_at, members, mappings
			FROM iam.claim_group_list($1)`, id)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (claimGroup, error) {
			var g claimGroup
			err := row.Scan(&g.ID, &g.ClaimValue, &g.DisplayName, &g.CreatedAt, &g.Members, &g.Mappings)
			return g, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"claim_groups": out})
}

func (a *API) addClaimGroup(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ClaimValue  string `json:"claim_value"`
		DisplayName string `json:"display_name"`
		Reason      string `json:"reason"`
	}
	if !a.view(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var gid string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.claim_group_add($1, $2, $3, $4)::text",
			id, body.ClaimValue, body.DisplayName, body.Reason).Scan(&gid)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": gid})
}

func (a *API) removeClaimGroup(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	id, gid := r.PathValue("id"), r.PathValue("group")
	if !uuidRE.MatchString(id) || !uuidRE.MatchString(gid) {
		fail(w, errNotFound)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.claim_group_remove($1, $2, $3)", id, gid, r.URL.Query().Get("reason"))
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

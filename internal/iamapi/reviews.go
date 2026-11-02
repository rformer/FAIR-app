package iamapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Access review campaigns (T-39; AC-49; design §6 /access-reviews):
//
//	GET  /api/v1/access-reviews                                  campaigns the caller manages or reviews in
//	POST /api/v1/access-reviews                                  open a campaign (access_review.manage at its BU)
//	GET  /api/v1/access-reviews/{id}                             the campaign and the items the caller may see
//	POST /api/v1/access-reviews/{id}/close                       close it now (its policy applies to undecided items)
//	POST /api/v1/access-reviews/{id}/items/{item}/decision       certify or revoke (access_review.decide at the item's BU)
//
// Without access_review.manage or access_review.decide anywhere the routes
// do not exist (404). The database checks every rule from the signed
// context: no self-review, nobody reviews access they granted, named
// reviewers, a comment for revocations; a revocation applies at once.

type campaign struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	BUID      string     `json:"bu_id"`
	BUCode    string     `json:"bu_code"`
	RoleIDs   []string   `json:"role_ids"`
	Reviewers []string   `json:"reviewers"`
	DueAt     time.Time  `json:"due_at"`
	OnExpiry  string     `json:"on_expiry"`
	Reason    string     `json:"reason"`
	State     string     `json:"state"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at"`
	ClosedBy  *string    `json:"closed_by"`
	Manages   bool       `json:"manages"`
	Items     int        `json:"items"`
	Decided   int        `json:"decided"`
	Revoked   int        `json:"revoked"`
	OpenForMe int        `json:"open_for_me"`
}

type reviewItem struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	AssignmentID *string         `json:"assignment_id"`
	MappingID    *string         `json:"mapping_id"`
	RoleID       string          `json:"role_id"`
	BUID         string          `json:"bu_id"`
	Snapshot     json.RawMessage `json:"snapshot"`
	Decision     *string         `json:"decision"`
	DecidedBy    *string         `json:"decided_by"`
	DecidedAt    *time.Time      `json:"decided_at"`
	Comment      *string         `json:"comment"`
	Outcome      *string         `json:"outcome"`
	CanDecide    bool            `json:"can_decide"`
}

func (a *API) reviewsVisible(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	if a.holdsSomewhere(r, p, "access_review.manage") || a.holdsSomewhere(r, p, "access_review.decide") {
		return true
	}
	problem(w, http.StatusNotFound, "not_found", "", nil)
	return false
}

func (a *API) campaigns(tx pgx.Tx, r *http.Request, id string) ([]campaign, error) {
	rows, err := tx.Query(r.Context(), `SELECT id::text, name, bu_id::text, bu_code, role_ids::text[], reviewers::text[], due_at, on_expiry, reason,
		state, created_by::text, created_at, closed_at, closed_by, manages, items, decided, revoked, open_for_me
		FROM iam.access_review_list($1)`, nilIfEmpty(id))
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[campaign])
	for i := range out {
		if out[i].RoleIDs == nil {
			out[i].RoleIDs = []string{}
		}
		if out[i].Reviewers == nil {
			out[i].Reviewers = []string{}
		}
	}
	return out, err
}

func (a *API) listReviews(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewsVisible(w, r, p) {
		return
	}
	var out []campaign
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		out, err = a.campaigns(tx, r, "")
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []campaign{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": out})
}

func (a *API) oneReview(w http.ResponseWriter, r *http.Request, p authz.Principal, id string, status int) {
	var cs []campaign
	var items []reviewItem
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		if cs, err = a.campaigns(tx, r, id); err != nil || len(cs) == 0 {
			return err
		}
		rows, err := tx.Query(r.Context(), `SELECT id::text, kind, assignment_id::text, mapping_id::text, role_id::text, bu_id::text, snapshot,
			decision, decided_by::text, decided_at, comment, outcome, can_decide FROM iam.access_review_items($1)`, id)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[reviewItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if len(cs) == 0 {
		fail(w, errNotFound)
		return
	}
	if items == nil {
		items = []reviewItem{}
	}
	writeJSON(w, status, map[string]any{"campaign": cs[0], "items": items})
}

func (a *API) getReview(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewsVisible(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	a.oneReview(w, r, p, id, http.StatusOK)
}

func (a *API) openReview(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name      string    `json:"name"`
		BUID      string    `json:"bu_id"`
		RoleIDs   []string  `json:"role_ids"`
		Reviewers []string  `json:"reviewers"`
		DueAt     time.Time `json:"due_at"`
		OnExpiry  string    `json:"on_expiry"`
		Reason    string    `json:"reason"`
	}
	if !a.reviewsVisible(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id must be a BU id", nil)
		return
	}
	for _, list := range [][]string{body.RoleIDs, body.Reviewers} {
		for _, id := range list {
			if !uuidRE.MatchString(id) {
				problem(w, http.StatusBadRequest, "invalid_value", "role_ids and reviewers are ids", nil)
				return
			}
		}
	}
	if body.OnExpiry == "" {
		body.OnExpiry = "keep"
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.access_review_open($1, $2, $3, $4, $5, $6, $7)::text",
			body.Name, body.BUID, body.RoleIDs, body.Reviewers, body.DueAt, body.OnExpiry, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.oneReview(w, r, p, id, http.StatusCreated)
}

func (a *API) closeReview(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.reviewsVisible(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.access_review_close($1, $2)", id, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.oneReview(w, r, p, id, http.StatusOK)
}

func (a *API) decideReviewItem(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Decision string `json:"decision"`
		Comment  string `json:"comment"`
	}
	if !a.reviewsVisible(w, r, p) || !decode(w, r, &body) {
		return
	}
	id, item := r.PathValue("id"), r.PathValue("item")
	if !uuidRE.MatchString(id) || !uuidRE.MatchString(item) {
		fail(w, errNotFound)
		return
	}
	var outcome string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var one int // the item is this campaign's, and visible to the caller
		if err := tx.QueryRow(r.Context(), "SELECT 1 FROM iam.access_review_items($1) WHERE id = $2", id, item).Scan(&one); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT iam.access_review_decide($1, $2, $3)", item, body.Decision, body.Comment).Scan(&outcome)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = errNotFound
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": item, "decision": body.Decision, "outcome": outcome})
}

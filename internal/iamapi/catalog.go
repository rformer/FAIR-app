package iamapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Catalog upgrades and role export/import (T-29; AC-57, AC-58; D-OQ5).
// Upgrades leave notices (new, retired, restored and reclassified
// permissions, custom roles that lost retired ones) for role.manage
// holders to acknowledge. Custom roles move between instances as
// fair.roles.v1 documents; an import is previewed with ?dry_run=true and
// applied all or nothing.

type catalogNotice struct {
	ID             string          `json:"id"`
	CatalogVersion int             `json:"catalog_version"`
	Kind           string          `json:"kind"`
	Subject        string          `json:"subject"`
	Detail         json.RawMessage `json:"detail"`
	CreatedAt      time.Time       `json:"created_at"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at"`
	AcknowledgedBy *string         `json:"acknowledged_by"`
}

func (a *API) listCatalogNotices(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	out := []catalogNotice{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, catalog_version, kind, subject, detail, created_at, acknowledged_at,
			acknowledged_by::text FROM iam.catalog_notice_list($1)`, r.URL.Query().Get("pending") == "true")
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[catalogNotice])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notices": out})
}

func (a *API) acknowledgeCatalogNotices(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	for _, id := range body.IDs {
		if !uuidRE.MatchString(id) {
			problem(w, http.StatusBadRequest, "invalid_value", "ids are notice ids", nil)
			return
		}
	}
	var n int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.catalog_notice_acknowledge($1::uuid[])", body.IDs).Scan(&n)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": n})
}

// exportRoles answers a fair.roles.v1 document of the custom roles
// (?ids=a,b for some).
func (a *API) exportRoles(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	var ids []string
	for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		if !uuidRE.MatchString(id) {
			problem(w, http.StatusBadRequest, "invalid_value", "ids are role ids", nil)
			return
		}
		ids = append(ids, id)
	}
	var doc json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var arg any
		if ids != nil {
			arg = ids
		}
		return tx.QueryRow(r.Context(), "SELECT iam.role_export($1::uuid[])", arg).Scan(&doc)
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="roles.json"`)
	writeJSON(w, http.StatusOK, doc)
}

// errRollBack ends a dry run's or a failed import's transaction.
var errRollBack = errors.New("iamapi: roll back")

// importRoles imports a fair.roles.v1 document: ?dry_run=true reports
// what would happen; otherwise every role is applied, or none when one
// fails (409 with the report).
func (a *API) importRoles(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Document json.RawMessage `json:"document"`
		Reason   string          `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	dry := r.URL.Query().Get("dry_run") == "true"
	var report struct {
		Roles  json.RawMessage `json:"roles"`
		Errors int             `json:"errors"`
		Source *int            `json:"source_catalog_version"`
		Local  *int            `json:"catalog_version"`
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), "SELECT iam.role_import($1::jsonb, $2)", string(body.Document), body.Reason).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			return err
		}
		if dry || report.Errors > 0 {
			return errRollBack
		}
		return nil
	})
	if err != nil && !errors.Is(err, errRollBack) {
		fail(w, err)
		return
	}
	out := map[string]any{"roles": report.Roles, "errors": report.Errors, "applied": err == nil, "dry_run": dry,
		"source_catalog_version": report.Source, "catalog_version": report.Local}
	if !dry && report.Errors > 0 {
		writeJSON(w, http.StatusConflict, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

package iamapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/report"
	"github.com/rformer/fair-app/pkg/authz"
)

// The entitlement report and the restricted-BU access listing (T-38;
// AC-48, AC-64; design §6 /entitlements/report):
//
//	GET /api/v1/entitlements/report[?format=json|csv|pdf]      entitlement.view (+ entitlement.export for files)
//	GET /api/v1/entitlements/restricted[?format=json|csv|pdf]  the same
//
// Report filters: user, role, bu (its subtree), source (manual, group,
// mapped, service_account, breakglass), restricted_only, expiring_before
// (RFC 3339), include_inactive. Rows cover the BUs where the caller holds
// entitlement.view (restricted subtrees only by an explicit assignment), and
// for a file also entitlement.export. A file is audited
// (entitlement.exported) in the transaction that read it. The PDF report
// carries both the entitlements and the restricted-BU listing (AC-64).

type entitlementRow struct {
	UserID         string     `json:"user_id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	UserKind       string     `json:"user_kind"`
	UserStatus     string     `json:"user_status"`
	LastLoginAt    *time.Time `json:"last_login_at"`
	Breakglass     bool       `json:"breakglass"`
	RoleID         string     `json:"role_id"`
	RoleName       string     `json:"role_name"`
	RoleBuiltin    bool       `json:"role_builtin"`
	Permissions    []string   `json:"permissions"`
	BUID           string     `json:"bu_id"`
	BUCode         string     `json:"bu_code"`
	BUName         string     `json:"bu_name"`
	BURestricted   bool       `json:"bu_restricted"`
	Source         string     `json:"source"`
	ViaGroup       *string    `json:"via_group"`
	GrantedBy      *string    `json:"granted_by"`
	GrantedByEmail *string    `json:"granted_by_email"`
	GrantedAt      time.Time  `json:"granted_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	AssignmentID   string     `json:"assignment_id"`
}

type restrictedRow struct {
	BUID          string   `json:"bu_id"`
	BUCode        string   `json:"bu_code"`
	BUName        string   `json:"bu_name"`
	ParentCode    *string  `json:"parent_code"`
	RollupMode    string   `json:"rollup_mode"`
	Archived      bool     `json:"archived"`
	UserID        *string  `json:"user_id"`
	Email         *string  `json:"email"`
	DisplayName   *string  `json:"display_name"`
	UserKind      *string  `json:"user_kind"`
	Access        *string  `json:"access"`
	ResourceTypes []string `json:"resource_types"`
}

type reportFilters struct {
	User           *string    `json:"user,omitempty"`
	Role           *string    `json:"role,omitempty"`
	BU             *string    `json:"bu,omitempty"`
	Source         *string    `json:"source,omitempty"`
	RestrictedOnly bool       `json:"restricted_only,omitempty"`
	ExpiringBefore *time.Time `json:"expiring_before,omitempty"`
	Inactive       bool       `json:"include_inactive,omitempty"`
}

func parseFilters(r *http.Request) (reportFilters, string) {
	q := r.URL.Query()
	var f reportFilters
	for _, x := range []struct {
		name string
		dst  **string
	}{{"user", &f.User}, {"role", &f.Role}, {"bu", &f.BU}} {
		if v := q.Get(x.name); v != "" {
			if !uuidRE.MatchString(v) {
				return f, x.name + " must be an id"
			}
			*x.dst = &v
		}
	}
	if v := q.Get("source"); v != "" {
		f.Source = &v
	}
	f.RestrictedOnly = q.Get("restricted_only") == "true"
	f.Inactive = q.Get("include_inactive") == "true"
	if v := q.Get("expiring_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, "expiring_before must be an RFC 3339 time"
		}
		f.ExpiringBefore = &t
	}
	return f, ""
}

// entitlementFormat checks access and returns the format (json, csv, pdf).
func (a *API) entitlementFormat(w http.ResponseWriter, r *http.Request, p authz.Principal) (string, bool) {
	if !a.somewhere(w, r, p, "entitlement.view") {
		return "", false
	}
	format := r.URL.Query().Get("format")
	switch format {
	case "":
		return "json", true
	case "json":
		return format, true
	case "csv", "pdf":
		if !a.holdsSomewhere(r, p, "entitlement.export") {
			problem(w, http.StatusForbidden, "forbidden", "exporting needs entitlement.export", nil)
			return "", false
		}
		return format, true
	}
	problem(w, http.StatusBadRequest, "invalid_value", "format is json, csv or pdf", nil)
	return "", false
}

func (a *API) entitlementRows(tx pgx.Tx, r *http.Request, f reportFilters, export bool) ([]entitlementRow, error) {
	rows, err := tx.Query(r.Context(), `SELECT user_id::text, email, display_name, user_kind, user_status, last_login_at, breakglass,
		role_id::text, role_name, role_builtin, permissions, bu_id::text, bu_code, bu_name, bu_restricted, source, via_group,
		granted_by::text, granted_by_email, granted_at, expires_at, assignment_id::text
		FROM iam.entitlement_report($1, $2, $3, $4, $5, $6, $7, $8)`,
		export, f.User, f.Role, f.BU, f.Source, f.RestrictedOnly, f.ExpiringBefore, f.Inactive)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[entitlementRow])
	if out == nil {
		out = []entitlementRow{}
	}
	return out, err
}

func (a *API) restrictedRows(tx pgx.Tx, r *http.Request) ([]restrictedRow, int, error) {
	rows, err := tx.Query(r.Context(), `SELECT bu_id::text, bu_code, bu_name, parent_code, rollup_mode, archived, user_id::text, email,
		display_name, user_kind, access, resource_types, hidden_count FROM iam.restricted_bu_access()`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []restrictedRow{}
	hidden := 0
	for rows.Next() {
		var x restrictedRow
		var bu, code, name, mode *string
		var archived *bool
		if err := rows.Scan(&bu, &code, &name, &x.ParentCode, &mode, &archived, &x.UserID, &x.Email, &x.DisplayName, &x.UserKind,
			&x.Access, &x.ResourceTypes, &hidden); err != nil {
			return nil, 0, err
		}
		if bu == nil {
			continue // no restricted BU visible: only the hidden count
		}
		x.BUID, x.BUCode, x.BUName, x.RollupMode, x.Archived = *bu, *code, *name, *mode, *archived
		if x.ResourceTypes == nil {
			x.ResourceTypes = []string{}
		}
		out = append(out, x)
	}
	return out, hidden, rows.Err()
}

func (a *API) entitlementReport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	format, ok := a.entitlementFormat(w, r, p)
	if !ok {
		return
	}
	f, bad := parseFilters(r)
	if bad != "" {
		problem(w, http.StatusBadRequest, "invalid_value", bad, nil)
		return
	}
	var rows []entitlementRow
	var restricted []restrictedRow
	var hidden int
	asOf := time.Now().UTC()
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		if rows, err = a.entitlementRows(tx, r, f, format != "json"); err != nil {
			return err
		}
		if restricted, hidden, err = a.restrictedRows(tx, r); err != nil {
			return err
		}
		if format != "json" {
			filters, _ := json.Marshal(f)
			_, err = tx.Exec(r.Context(), "SELECT iam.entitlement_export_audit('entitlements', $1, $2, $3)", format, filters, len(rows))
		}
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	switch format {
	case "json":
		writeJSON(w, http.StatusOK, map[string]any{"as_of": asOf, "filters": f, "entitlements": rows,
			"restricted_bus": restricted, "restricted_bus_not_shown": hidden})
	case "csv":
		b, err := report.CSV(entitlementColumns, entitlementCells(rows))
		if err != nil {
			fail(w, err)
			return
		}
		sendFile(w, b, "text/csv; charset=utf-8", "entitlements", asOf, "csv")
	case "pdf":
		b, err := report.Document{Title: "Entitlement report", Author: "FAIR platform", Created: asOf,
			Subtitle: subtitle(asOf, p, f, len(rows)),
			Sections: []report.Section{
				{Heading: "Entitlements", Note: "One row per user and live assignment (a group's assignment once per member).",
					Columns: entitlementPDFColumns, Rows: entitlementPDFCells(rows)},
				restrictedSection(restricted, hidden),
			}}.PDF()
		if err != nil {
			fail(w, err)
			return
		}
		sendFile(w, b, "application/pdf", "entitlements", asOf, "pdf")
	}
}

func (a *API) restrictedListing(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	format, ok := a.entitlementFormat(w, r, p)
	if !ok {
		return
	}
	var restricted []restrictedRow
	var hidden int
	asOf := time.Now().UTC()
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		if restricted, hidden, err = a.restrictedRows(tx, r); err != nil {
			return err
		}
		if format != "json" {
			_, err = tx.Exec(r.Context(), "SELECT iam.entitlement_export_audit('restricted_bus', $1, '{}', $2)", format, len(restricted))
		}
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	switch format {
	case "json":
		writeJSON(w, http.StatusOK, map[string]any{"as_of": asOf, "restricted_bus": restricted, "not_shown": hidden})
	case "csv":
		b, err := report.CSV(restrictedColumns, restrictedCells(restricted))
		if err != nil {
			fail(w, err)
			return
		}
		sendFile(w, b, "text/csv; charset=utf-8", "restricted-bus", asOf, "csv")
	case "pdf":
		b, err := report.Document{Title: "Restricted BU access", Author: "FAIR platform", Created: asOf,
			Subtitle: fmt.Sprintf("As of %s, for %s.", asOf.Format(time.RFC3339), p.UserID),
			Sections: []report.Section{restrictedSection(restricted, hidden)}}.PDF()
		if err != nil {
			fail(w, err)
			return
		}
		sendFile(w, b, "application/pdf", "restricted-bus", asOf, "pdf")
	}
}

func sendFile(w http.ResponseWriter, b []byte, ctype, name string, asOf time.Time, ext string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, name, asOf.Format("20060102T150405Z"), ext))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func subtitle(asOf time.Time, p authz.Principal, f reportFilters, n int) string {
	var parts []string
	for _, x := range []struct {
		k string
		v *string
	}{{"user", f.User}, {"role", f.Role}, {"BU subtree", f.BU}, {"source", f.Source}} {
		if x.v != nil {
			parts = append(parts, x.k+" "+*x.v)
		}
	}
	if f.RestrictedOnly {
		parts = append(parts, "restricted BUs only")
	}
	if f.ExpiringBefore != nil {
		parts = append(parts, "expiring before "+f.ExpiringBefore.UTC().Format(time.RFC3339))
	}
	if f.Inactive {
		parts = append(parts, "including inactive users")
	}
	filters := "none"
	if len(parts) > 0 {
		filters = strings.Join(parts, "; ")
	}
	return fmt.Sprintf("As of %s, for %s, within the BUs where they may export entitlements. Filters: %s. %d rows.",
		asOf.Format(time.RFC3339), p.UserID, filters, n)
}

func ts(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var entitlementColumns = []string{"user_id", "email", "display_name", "user_kind", "user_status", "last_login_at", "breakglass",
	"role", "role_builtin", "permissions", "bu_code", "bu_name", "bu_restricted", "source", "via_group", "granted_by",
	"granted_at", "expires_at", "assignment_id"}

func entitlementCells(rows []entitlementRow) [][]string {
	out := make([][]string, 0, len(rows))
	for _, e := range rows {
		out = append(out, []string{e.UserID, e.Email, e.DisplayName, e.UserKind, e.UserStatus, ts(e.LastLoginAt), yesNo(e.Breakglass),
			e.RoleName, yesNo(e.RoleBuiltin), strings.Join(e.Permissions, " "), e.BUCode, e.BUName, yesNo(e.BURestricted), e.Source,
			str(e.ViaGroup), str(e.GrantedByEmail), e.GrantedAt.UTC().Format(time.RFC3339), ts(e.ExpiresAt), e.AssignmentID})
	}
	return out
}

var entitlementPDFColumns = []report.Column{{Title: "User", Weight: 2.2}, {Title: "Role", Weight: 1.3}, {Title: "Permissions", Weight: 3.6},
	{Title: "BU", Weight: 1.1}, {Title: "Granted", Weight: 2}, {Title: "Expires", Weight: 1}, {Title: "Last sign-in", Weight: 1}}

func entitlementPDFCells(rows []entitlementRow) [][]string {
	out := make([][]string, 0, len(rows))
	day := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format("2006-01-02")
	}
	for _, e := range rows {
		user := e.DisplayName + "\n" + e.Email + "\n" + e.UserKind + ", " + e.UserStatus
		if e.Breakglass {
			user += ", break-glass"
		}
		role := e.RoleName
		if e.RoleBuiltin {
			role += " (built-in)"
		}
		bu := e.BUCode
		if e.BURestricted {
			bu += " (restricted)"
		}
		granted := e.Source
		if e.ViaGroup != nil {
			granted += " via " + *e.ViaGroup
		}
		granted += "\n" + e.GrantedAt.UTC().Format("2006-01-02")
		if e.GrantedByEmail != nil {
			granted += " by " + *e.GrantedByEmail
		}
		out = append(out, []string{user, role, strings.Join(e.Permissions, ", "), bu, granted, day(e.ExpiresAt), day(e.LastLoginAt)})
	}
	return out
}

var restrictedColumns = []string{"bu_code", "bu_name", "parent_code", "rollup_mode", "archived", "user_id", "email", "display_name",
	"user_kind", "access", "resource_types"}

func restrictedCells(rows []restrictedRow) [][]string {
	out := make([][]string, 0, len(rows))
	for _, x := range rows {
		out = append(out, []string{x.BUCode, x.BUName, str(x.ParentCode), x.RollupMode, yesNo(x.Archived), str(x.UserID), str(x.Email),
			str(x.DisplayName), str(x.UserKind), str(x.Access), strings.Join(x.ResourceTypes, " ")})
	}
	return out
}

func restrictedSection(rows []restrictedRow, hidden int) report.Section {
	note := "Every restricted BU you may see (an explicit assignment there, or managing its restriction) and everyone with access to it."
	if hidden > 0 {
		note += fmt.Sprintf(" %d other restricted BU(s) exist that you may not see.", hidden)
	}
	var cells [][]string
	for _, x := range rows {
		bu := x.BUCode + " " + x.BUName
		if x.ParentCode != nil {
			bu += "\nunder " + *x.ParentCode
		}
		bu += "\nroll-up " + x.RollupMode
		who := "(nobody)"
		if x.UserID != nil {
			who = str(x.DisplayName) + "\n" + str(x.Email) + " (" + str(x.UserKind) + ")"
		}
		cells = append(cells, []string{bu, who, str(x.Access), strings.Join(x.ResourceTypes, ", ")})
	}
	return report.Section{Heading: "Restricted BUs and who can access them", Note: note,
		Columns: []report.Column{{Title: "Restricted BU", Weight: 2}, {Title: "Who", Weight: 2.5}, {Title: "Access", Weight: 0.8},
			{Title: "Resource types", Weight: 3}}, Rows: cells}
}

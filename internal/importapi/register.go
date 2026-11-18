package importapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-14 (F-011-AC-20 to AC-22; design §3.6): the register import. A
// register file (CSV with a column mapping, or fair.register-import.v1)
// becomes a batch of risk records for the BU's file integration of its
// source label: new external IDs create unquantified risks through the
// register's save code in the import's transaction, known ones become
// proposals, all or nothing, after a dry run's fingerprint.

// RegisterImportFormat is the JSON form's format.
const RegisterImportFormat = "fair.register-import.v1"

// Column roles of a CSV mapping. Ratings (likelihood, impact, heat-map
// positions, scores) are never imported (AC-21, P1): a column marked
// "rating" is refused; to keep one, mark it "text".
var columnRoles = map[string]bool{"external_id": true, "title": true, "description": true, "owner": true, "category": true, "text": true, "rating": true}

type importRow struct {
	ExternalID  string            `json:"external_id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Owner       string            `json:"owner,omitempty"`    // an email address
	Category    string            `json:"category,omitempty"` // a category's name
	Text        map[string]string `json:"text,omitempty"`     // kept in the description
}

type registerImportBody struct {
	BU          string            `json:"bu_id"`
	Label       string            `json:"label"`
	Format      string            `json:"format,omitempty"`
	Records     []importRow       `json:"records,omitempty"`
	CSV         string            `json:"csv,omitempty"`
	Columns     map[string]string `json:"columns,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
}

type importProblem struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

// errImport refuses the import whole, with every problem (422).
type errImport struct{ problems []importProblem }

func (e errImport) Error() string { return "importapi: the register file has problems" }

var errFingerprint = errors.New("importapi: the file or mapping changed since the dry run")

// rowsOf reads the body's rows, each with the pointer its problems name.
func rowsOf(b registerImportBody) ([]importRow, []string, []string, []importProblem) {
	if b.CSV == "" {
		if b.Format != RegisterImportFormat {
			return nil, nil, nil, []importProblem{{"/format", "is " + RegisterImportFormat + " (or send csv with columns)"}}
		}
		if len(b.Columns) > 0 {
			return nil, nil, nil, []importProblem{{"/columns", "is used with csv only"}}
		}
		ptrs := make([]string, len(b.Records))
		for i := range b.Records {
			ptrs[i] = "/records/" + strconv.Itoa(i)
		}
		return b.Records, ptrs, nil, nil
	}
	if b.Format != "" || len(b.Records) > 0 {
		return nil, nil, nil, []importProblem{{"/csv", "send csv with columns, or records with the format, not both"}}
	}
	r := csv.NewReader(strings.NewReader(b.CSV))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, nil, nil, []importProblem{{"/csv", "has no header row"}}
	}
	var problems []importProblem
	roles := make([]string, len(header))
	count := map[string]int{}
	for i, h := range header {
		h = strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))
		header[i] = h
		role, ok := b.Columns[h]
		switch {
		case !ok:
			problems = append(problems, importProblem{"/columns/" + h, "is not mapped: map every column (external_id, title, description, owner, category, text or rating)"})
		case !columnRoles[role]:
			problems = append(problems, importProblem{"/columns/" + h, "is " + role + "; a column is external_id, title, description, owner, category, text or rating"})
		}
		roles[i] = role
		count[role]++
	}
	for _, role := range []string{"external_id", "title", "description", "owner", "category"} {
		if count[role] > 1 {
			problems = append(problems, importProblem{"/columns", "maps more than one column to " + role})
		}
	}
	for _, role := range []string{"external_id", "title"} {
		if count[role] == 0 {
			problems = append(problems, importProblem{"/columns", "maps no column to " + role})
		}
	}
	for c := range b.Columns {
		found := false
		for _, h := range header {
			found = found || h == c
		}
		if !found {
			problems = append(problems, importProblem{"/columns/" + c, "is not a column of the file"})
		}
	}
	if problems != nil {
		return nil, nil, nil, problems
	}
	var refusedColumns []string
	for i, role := range roles {
		if role == "rating" {
			refusedColumns = append(refusedColumns, header[i])
		}
	}
	var rows []importRow
	var ptrs []string
	for n := 1; ; n++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, []importProblem{{"/csv", "is not CSV: " + err.Error()}}
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue // a blank line
		}
		if len(rec) != len(header) {
			problems = append(problems, importProblem{fmt.Sprintf("/rows/%d", n), fmt.Sprintf("has %d fields, the header %d", len(rec), len(header))})
			continue
		}
		row := importRow{Text: map[string]string{}}
		for i, v := range rec {
			v = strings.TrimSpace(v)
			switch roles[i] {
			case "external_id":
				row.ExternalID = v
			case "title":
				row.Title = v
			case "description":
				row.Description = v
			case "owner":
				row.Owner = v
			case "category":
				row.Category = v
			case "text":
				if v != "" {
					row.Text[header[i]] = v
				}
			}
		}
		rows = append(rows, row)
		ptrs = append(ptrs, fmt.Sprintf("/rows/%d", n))
	}
	return rows, ptrs, refusedColumns, problems
}

// description is the row's description with its kept columns, in order.
func (r importRow) description() string {
	keys := make([]string, 0, len(r.Text))
	for k := range r.Text {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	if r.Description != "" {
		parts = append(parts, r.Description)
	}
	for _, k := range keys {
		parts = append(parts, "Imported "+k+": "+r.Text[k])
	}
	return strings.Join(parts, "\n\n")
}

func (a *API) registerImport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	bus, err := a.Authz.BUsWith(r.Context(), p, "register.edit")
	if err != nil {
		server.WriteAuthzError(w, err)
		return
	}
	if len(bus) == 0 {
		notFound(w)
		return
	}
	dry := r.URL.Query().Get("dry_run") == "true"
	raw, ok := readBody(w, r, integration.MaxBody)
	if !ok {
		return
	}
	var b registerImportBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a rating field in a record is refused (AC-21)
	if err := dec.Decode(&b); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the body is not a register import: "+err.Error(), nil)
		return
	}
	if !uuidRE.MatchString(b.BU) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id is a business unit id", nil)
		return
	}
	if a.Register == nil || a.Risk == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the register API is not configured", nil)
		return
	}
	rows, ptrs, refusedColumns, problems := rowsOf(b)
	var out map[string]any
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		if problems != nil {
			return errImport{problems}
		}
		var integ string
		if err := tx.QueryRow(ctx, "SELECT integration.register_import($1, $2)::text", b.BU, b.Label).Scan(&integ); err != nil {
			return err
		}
		// Rows: external IDs once, titles, owners among the users who may
		// own a risk there, categories by name.
		seen := map[string]bool{}
		records := make([]map[string]any, 0, len(rows))
		for i, row := range rows {
			ptr := ptrs[i]
			switch {
			case row.ExternalID == "":
				problems = append(problems, importProblem{ptr + "/external_id", "is required"})
			case seen[row.ExternalID]:
				problems = append(problems, importProblem{ptr + "/external_id", "appears twice in the file"})
			}
			seen[row.ExternalID] = true
			if row.Title == "" {
				problems = append(problems, importProblem{ptr + "/title", "is required"})
			}
			if row.Owner != "" {
				var owner *string
				if err := tx.QueryRow(ctx, "SELECT integration.import_owner($1, $2)::text", b.BU, row.Owner).Scan(&owner); err != nil {
					return err
				}
				if owner == nil {
					problems = append(problems, importProblem{ptr + "/owner", "is not an active user who may own a risk at this business unit"})
				}
			}
			if row.Category != "" {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM register.category WHERE lower(name) = lower($1) AND archived_at IS NULL", row.Category).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					problems = append(problems, importProblem{ptr + "/category", "is not a register category"})
				}
			}
			rec := map[string]any{"kind": "risk", "external_id": row.ExternalID, "bu": b.BU, "title": row.Title}
			for k, v := range map[string]string{"description": row.description(), "owner": row.Owner, "category": row.Category} {
				if v != "" {
					rec[k] = v
				}
			}
			records = append(records, rec)
		}
		if problems != nil {
			return errImport{problems}
		}
		body, err := json.Marshal(map[string]any{"format": integration.Format, "records": records})
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(b.BU + "\n" + strings.TrimSpace(b.Label) + "\n" + strings.Join(refusedColumns, ",") + "\n" + string(body)))
		fingerprint := hex.EncodeToString(sum[:])
		if !dry && b.Fingerprint != fingerprint {
			return errFingerprint
		}
		note := "Imported from the register file " + strings.TrimSpace(b.Label)
		// New risks are created in this transaction (accepted as the
		// importer through the register's save code); known ones wait for
		// review as proposals (AC-22).
		hook := func(runID string, counts *Counts) error {
			rows, err := tx.Query(ctx, "SELECT integration.run_creates($1)::text", runID)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			for _, pid := range ids {
				if _, err := a.acceptOne(ctx, tx, p, pid, nil, note, false); err != nil {
					return err
				}
				counts.Applied++
			}
			cj, _ := json.Marshal(counts)
			_, err = tx.Exec(ctx, "SELECT integration.register_imported($1, $2, $3)", runID, strings.TrimSpace(b.Label), cj)
			return err
		}
		res, err := a.runBatch(ctx, tx, p, integ, "application/json", body, dry, "", func(runID string, c *Counts) error {
			if c.Refused > 0 {
				return nil // refused below, before anything is created
			}
			return hook(runID, c)
		})
		if err != nil {
			return err
		}
		if res.counts.Refused > 0 {
			var ps []importProblem
			for _, f := range res.batch.Refused {
				ptr := ""
				if f.N >= 1 && f.N <= len(ptrs) {
					ptr = ptrs[f.N-1]
				}
				ps = append(ps, importProblem{ptr + f.Pointer, f.Message})
			}
			return errImport{ps}
		}
		out = map[string]any{"dry_run": dry, "fingerprint": fingerprint, "integration_id": integ, "counts": res.counts,
			"refused_columns": nonNilStrings(refusedColumns)}
		if dry {
			out["matches"] = nonNilMatches(res.preview)
		} else {
			out["run"] = res.run
		}
		return nil
	})
	var ei errImport
	switch {
	case errors.As(err, &ei):
		problem(w, http.StatusUnprocessableEntity, "invalid_import", "the register file has problems; nothing was imported", map[string]any{"problems": ei.problems})
	case errors.As(err, new(errBatch)):
		problem(w, http.StatusUnprocessableEntity, "invalid_import", err.Error(), nil)
	case errors.Is(err, errFingerprint):
		problem(w, http.StatusConflict, "fingerprint_mismatch", "the file or its mapping changed since the dry run: run it again and import with its fingerprint", nil)
	case err != nil:
		if a.answerDecision(w, err) {
			return
		}
	default:
		status := http.StatusCreated
		if dry {
			status = http.StatusOK
		}
		writeJSON(w, status, out)
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

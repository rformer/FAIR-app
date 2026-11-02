package iamapi

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// BU import and export (T-31; AC-19; design §6 /bus/import, /bus/export).
// Both need bu.manage somewhere (404 without it). Documents are fair.bus.v1:
// JSON, or CSV with the same columns. Export covers the BUs the caller
// manages (iam.bu_export); import creates missing BUs and renames existing
// ones (iam.bu_import), previewed with ?dry_run=true, otherwise all or
// nothing like the role import (T-29).

// busCSVHeader is the CSV form's header row, in this order.
var busCSVHeader = []string{"code", "parent_code", "name", "restricted", "rollup_mode"}

type busEntry struct {
	Code       string  `json:"code"`
	ParentCode *string `json:"parent_code"`
	Name       string  `json:"name"`
	Restricted *bool   `json:"restricted,omitempty"`
	RollupMode string  `json:"rollup_mode,omitempty"`
}

type busDoc struct {
	Format string     `json:"format"`
	BUs    []busEntry `json:"bus"`
}

func (a *API) buManage(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.somewhere(w, r, p, "bu.manage")
}

func (a *API) exportBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.buManage(w, r, p) {
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "csv" {
		problem(w, http.StatusBadRequest, "invalid_value", "format is json or csv", nil)
		return
	}
	var raw []byte
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_export()").Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	if format != "csv" {
		w.Header().Set("Content-Disposition", `attachment; filename="bus.json"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	var doc busDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fail(w, err)
		return
	}
	out, err := busToCSV(doc)
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="bus.csv"`)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// importBUs imports a fair.bus.v1 document, given as `document` (JSON) or
// `csv` (text): ?dry_run=true reports what would happen; otherwise every
// entry applies, or none when one fails (409 with the report).
func (a *API) importBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Document json.RawMessage `json:"document"`
		CSV      *string         `json:"csv"`
		Reason   string          `json:"reason"`
	}
	if !a.buManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	doc := []byte(body.Document)
	switch {
	case body.CSV != nil && len(body.Document) > 0:
		problem(w, http.StatusBadRequest, "invalid_request", "give either document or csv", nil)
		return
	case body.CSV != nil:
		parsed, err := busFromCSV(*body.CSV)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_value", err.Error(), nil)
			return
		}
		if doc, err = json.Marshal(parsed); err != nil {
			fail(w, err)
			return
		}
	case len(doc) == 0:
		problem(w, http.StatusBadRequest, "invalid_request", "document or csv is required", nil)
		return
	}
	dry := r.URL.Query().Get("dry_run") == "true"
	var report struct {
		BUs    json.RawMessage `json:"bus"`
		Errors int             `json:"errors"`
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), "SELECT iam.bu_import($1::jsonb, $2)", string(doc), body.Reason).Scan(&raw); err != nil {
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
	out := map[string]any{"bus": report.BUs, "errors": report.Errors, "applied": err == nil, "dry_run": dry}
	if !dry && report.Errors > 0 {
		writeJSON(w, http.StatusConflict, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// busToCSV writes the CSV form. Cells a spreadsheet would run as a formula
// are prefixed with an apostrophe, which busFromCSV removes again.
func busToCSV(doc busDoc) ([]byte, error) {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	if err := cw.Write(busCSVHeader); err != nil {
		return nil, err
	}
	for _, b := range doc.BUs {
		parent, restricted := "", ""
		if b.ParentCode != nil {
			parent = *b.ParentCode
		}
		if b.Restricted != nil {
			restricted = strconv.FormatBool(*b.Restricted)
		}
		if err := cw.Write([]string{csvSafe(b.Code), csvSafe(parent), csvSafe(b.Name), restricted, b.RollupMode}); err != nil {
			return nil, err
		}
	}
	cw.Flush()
	return buf.Bytes(), cw.Error()
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvUnsafe(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

// busFromCSV reads the CSV form: the header row, then one BU per row.
func busFromCSV(text string) (busDoc, error) {
	cr := csv.NewReader(strings.NewReader(text))
	cr.FieldsPerRecord = len(busCSVHeader)
	header, err := cr.Read()
	if err != nil {
		return busDoc{}, fmt.Errorf("csv: %w", err)
	}
	for i, h := range header {
		if strings.TrimSpace(strings.TrimPrefix(h, string(rune(0xFEFF)))) != busCSVHeader[i] {
			return busDoc{}, fmt.Errorf("csv: the header must be %s", strings.Join(busCSVHeader, ","))
		}
	}
	doc := busDoc{Format: "fair.bus.v1", BUs: []busEntry{}}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return busDoc{}, fmt.Errorf("csv: %w", err)
		}
		e := busEntry{Code: csvUnsafe(strings.TrimSpace(rec[0])), Name: csvUnsafe(strings.TrimSpace(rec[2])), RollupMode: strings.TrimSpace(rec[4])}
		if pc := csvUnsafe(strings.TrimSpace(rec[1])); pc != "" {
			e.ParentCode = &pc
		}
		if v := strings.TrimSpace(rec[3]); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return busDoc{}, fmt.Errorf("csv: line %d: restricted is true or false", len(doc.BUs)+2)
			}
			e.Restricted = &b
		}
		doc.BUs = append(doc.BUs, e)
	}
	return doc, nil
}

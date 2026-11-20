package integration

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/rformer/fair-app/internal/risk/model"
)

// Mapping is an integration's declarative CSV mapping (design §3.2): which
// column holds which field (a path such as "name", "value/min" or
// "amounts/response"), source values translated to platform values per
// field, and defaults for fields a row leaves empty. A CSV row is a record
// of the input kind's first record kind. There are no expressions: values
// are copied, translated by the table, or defaulted.
type Mapping struct {
	Columns   map[string]string            `json:"columns"`
	Values    map[string]map[string]string `json:"values,omitempty"`
	Defaults  map[string]string            `json:"defaults,omitempty"`
	Separator string                       `json:"separator,omitempty"` // between list items (members); default ";"
}

// Fields are the field paths a CSV row of each record kind may set.
var Fields = map[string][]string{
	KindAsset:      {"external_id", "bu", "name", "asset_type", "description", "value/min", "value/ml", "value/max", "value/confidence", "value/basis"},
	KindAssetGroup: {"external_id", "bu", "name", "description", "members", "value/min", "value/ml", "value/max", "value/confidence", "value/basis"},
	KindLossEvent: append([]string{"external_id", "bu", "occurred_on", "event_type", "description"},
		prefixed("amounts/", model.FormsOfLoss)...),
	KindRisk:          {"external_id", "bu", "title", "description", "owner", "category"},
	KindControlStatus: {"external_id", "control", "status", "assessed_on", "note"},
}

func prefixed(p string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

// CheckMapping refuses a mapping that names a field the input kind's CSV
// rows do not have, maps no column to external_id, or maps one field twice.
func CheckMapping(input string, m Mapping) error {
	kinds, ok := RecordKinds[input]
	if !ok {
		return fmt.Errorf("integration: unknown input kind %q", input)
	}
	fields := Fields[kinds[0]]
	used := map[string]string{}
	for col, f := range m.Columns {
		switch {
		case strings.TrimSpace(col) == "":
			return errors.New("integration: a column without a name")
		case !slices.Contains(fields, f):
			return fmt.Errorf("integration: column %q maps to %q, not a field of a %s (%s)", col, f, kinds[0], strings.Join(fields, ", "))
		case used[f] != "":
			return fmt.Errorf("integration: columns %q and %q both map to %q", used[f], col, f)
		}
		used[f] = col
	}
	if used["external_id"] == "" && m.Defaults["external_id"] == "" {
		return errors.New("integration: no column maps to external_id")
	}
	for f := range m.Values {
		if !slices.Contains(fields, f) {
			return fmt.Errorf("integration: values for %q, not a field of a %s", f, kinds[0])
		}
	}
	for f := range m.Defaults {
		if !slices.Contains(fields, f) || f == "external_id" {
			return fmt.Errorf("integration: a default for %q, not a field of a %s that may be defaulted", f, kinds[0])
		}
	}
	if len(m.Separator) > 1 {
		return errors.New("integration: the list separator is one character")
	}
	return nil
}

// ParseCSV parses a CSV file (UTF-8, a header row) by the mapping for an
// integration of the given input kind. Columns the mapping does not name
// are ignored; mapped columns missing from the header refuse the file.
func ParseCSV(raw []byte, input string, m Mapping) (*Batch, error) {
	if len(raw) > MaxBody {
		return nil, batchError("the file is larger than %d bytes", MaxBody)
	}
	if err := CheckMapping(input, m); err != nil {
		return nil, batchError("%v", err)
	}
	kind := RecordKinds[input][0]
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	header, err := r.Read()
	if err != nil {
		return nil, batchError("no header row: %v", err)
	}
	index := map[string]int{}
	for i, h := range header {
		index[strings.TrimSpace(h)] = i
	}
	var missing []string
	columnOf := map[string]string{} // field path -> column, for refusals
	for col, f := range m.Columns {
		if _, ok := index[col]; !ok {
			missing = append(missing, col)
		}
		columnOf[f] = col
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, batchError("the header has no column %s", strings.Join(missing, ", "))
	}
	sep := ";"
	if m.Separator != "" {
		sep = m.Separator
	}
	b := &Batch{}
	seen := map[string]int{}
	allowed := []string{kind}
	for n := 1; ; n++ {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, batchError("row %d: %v", n, err)
		}
		if n > MaxRecords {
			return nil, batchError("more than %d rows; at most %d in a file", MaxRecords, MaxRecords)
		}
		if blank(row) {
			continue
		}
		rec := mapRecord(kind, m, sep, func(col string) string {
			if i := index[col]; i < len(row) {
				return row[i]
			}
			return ""
		})
		one, err := json.Marshal(rec)
		if err != nil {
			return nil, batchError("row %d: %v", n, err)
		}
		b.add(n, one, allowed, seen, columnOf)
	}
	return b, nil
}

// mapRecord builds a record of kind by the mapping from a source's values:
// get answers the value of a mapped column (a CSV column, or a connector's
// JSON pointer into an item), "" when it is absent. Values are trimmed,
// defaulted, then translated by the mapping's value table (F-011 T-06,
// T-17: CSV files and connectors map alike).
func mapRecord(kind string, m Mapping, sep string, get func(col string) string) map[string]any {
	rec := map[string]any{"kind": kind}
	for _, f := range Fields[kind] {
		val := ""
		if col := colFor(m, f); col != "" {
			val = strings.TrimSpace(get(col))
		}
		if val == "" {
			val = m.Defaults[f]
		}
		if t, ok := m.Values[f][val]; ok {
			val = t
		}
		if val == "" {
			continue
		}
		set(rec, f, val, sep)
	}
	return rec
}

// colFor is the column the mapping maps to field f ("" without one).
func colFor(m Mapping, f string) string {
	for col, x := range m.Columns {
		if x == f {
			return col
		}
	}
	return ""
}

func blank(row []string) bool {
	for _, c := range row {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

// set puts val at path f in rec: "a/b" nests, "members" splits into a list.
func set(rec map[string]any, f, val, sep string) {
	if f == "members" {
		var items []any
		for _, x := range strings.Split(val, sep) {
			if x = strings.TrimSpace(x); x != "" {
				items = append(items, x)
			}
		}
		rec[f] = items
		return
	}
	parent, leaf, nested := strings.Cut(f, "/")
	if !nested {
		rec[f] = val
		return
	}
	sub, _ := rec[parent].(map[string]any)
	if sub == nil {
		sub = map[string]any{}
		rec[parent] = sub
	}
	sub[leaf] = val
}

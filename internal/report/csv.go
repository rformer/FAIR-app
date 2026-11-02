package report

import (
	"bytes"
	"encoding/csv"
	"strings"
)

// CSV renders a header and rows. A cell a spreadsheet would run as a
// formula (starting with =, +, -, @, tab or carriage return) gets a
// leading apostrophe, as the BU export does (T-31).
func CSV(columns []string, rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(string(rune(0xFEFF))) // a BOM, so spreadsheets read UTF-8
	w := csv.NewWriter(&b)
	if err := w.Write(safe(columns)); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := w.Write(safe(r)); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func safe(cells []string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			c = "'" + c
		}
		out[i] = c
	}
	return out
}

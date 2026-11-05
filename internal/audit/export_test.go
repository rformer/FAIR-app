package audit

import (
	"strings"
	"testing"
)

// F-002 T-15: the CSV view does not hand spreadsheets formulas, and the
// manifest states the filter in words (AC-33).
func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"setting.changed":      "setting.changed",
		"=HYPERLINK(\"x\")":    "'=HYPERLINK(\"x\")",
		"+1":                   "'+1",
		"-1":                   "'-1",
		"@SUM(A1)":             "'@SUM(A1)",
		"\tx":                  "'\tx",
		"a=b":                  "a=b",
		"10.0.0.1":             "10.0.0.1",
		"system:audit":         "system:audit",
		"2026-11-05T10:00:00Z": "2026-11-05T10:00:00Z",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDescribeFilter(t *testing.T) {
	all := DescribeFilter([]byte(`{}`))
	if !strings.HasPrefix(all, "Every audit record in the BUs where the requester") || !strings.Contains(all, "closing checkpoint") {
		t.Errorf("no filter: %q", all)
	}
	got := DescribeFilter([]byte(`{"type":"setting.changed","from":"2026-01-01T00:00:00Z","source_ip":"10.0.0.0/8","approval_id":"a-1"}`))
	want := "The audit records recorded at or after 2026-01-01T00:00:00Z, of type setting.changed, from source address 10.0.0.0/8, naming approval a-1, in the BUs"
	if !strings.HasPrefix(got, want) {
		t.Errorf("filter:\n got %q\nwant %q...", got, want)
	}
	for _, k := range filterWords {
		if !strings.Contains(DescribeFilter([]byte(`{"`+k.key+`":"v"}`)), k.words+" v") {
			t.Errorf("%s is not described", k.key)
		}
	}
}

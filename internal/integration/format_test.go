package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// F-011 T-06 (F-011-AC-06, AC-15 to AC-17, AC-23; design §3.2): batches of
// fair.integration.v1 and CSV files are checked record by record; valid
// records are normalized with their digests; refusals carry the position,
// the JSON pointer and, for CSV, the column.

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(p, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p) // #nosec G304 -- the package's own test data
	if err != nil {
		t.Fatalf("%v (FAIR_UPDATE_GOLDEN=1 writes it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("%s differs from the golden file:\n%s", name, got)
	}
}

func render(b *Batch) []byte {
	out, _ := json.MarshalIndent(map[string]any{"complete": b.Complete, "records": b.Records, "refused": b.Refused, "refusals": b.Refusals}, "", "  ")
	return append(out, '\n')
}

func TestParseJSONBatch(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "batch.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseJSON(raw, InputAssets)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "batch.golden.json", render(b))
	if len(b.Records) != 3 || b.Refusals != 5 {
		t.Fatalf("%d records, %d refusals", len(b.Records), b.Refusals)
	}
	// Normalized: trimmed text, canonical decimals; the digest is of the data.
	if !strings.Contains(string(b.Records[0].Data), `"name":"Claims platform"`) || !strings.Contains(string(b.Records[0].Data), `"ml":"1500000"`) ||
		!strings.Contains(string(b.Records[0].Data), `"max":"4000000"`) || !strings.Contains(string(b.Records[0].Data), `"confidence":"0.9"`) {
		t.Errorf("normalized: %s", b.Records[0].Data)
	}
	want := map[int]string{4: "/name", 5: "/external_id", 6: "/kind", 7: "/value", 8: "/owner"}
	for _, r := range b.Refused {
		if want[r.N] != r.Pointer {
			t.Errorf("refusal %+v, want pointer %q", r, want[r.N])
		}
	}
	// The same record twice: the same digest; changed, another.
	again, _ := ParseJSON(raw, InputAssets)
	if again.Records[0].Digest != b.Records[0].Digest || again.Records[0].Digest == again.Records[1].Digest {
		t.Error("digests are not stable per record")
	}
}

func TestParseJSONRefusesBatches(t *testing.T) {
	recs := func(n int) string {
		var s []string
		for i := range n {
			s = append(s, fmt.Sprintf(`{"kind": "risk", "external_id": "r%d", "bu": "A", "title": "t"}`, i))
		}
		return strings.Join(s, ",")
	}
	for name, c := range map[string]struct{ raw, input string }{
		"not JSON":           {`{`, InputRisks},
		"not an object":      {`[]`, InputRisks},
		"another format":     {`{"format": "fair.risk.v1", "records": []}`, InputRisks},
		"no records":         {`{"format": "fair.integration.v1"}`, InputRisks},
		"an unknown member":  {`{"format": "fair.integration.v1", "records": [], "mapping": {}}`, InputRisks},
		"complete as text":   {`{"format": "fair.integration.v1", "complete": "yes", "records": []}`, InputRisks},
		"too many records":   {`{"format": "fair.integration.v1", "records": [` + recs(MaxRecords+1) + `]}`, InputRisks},
		"an unknown input":   {`{"format": "fair.integration.v1", "records": []}`, "vulnerabilities"},
		"a duplicate member": {`{"format": "fair.integration.v1", "format": "fair.integration.v1", "records": []}`, InputRisks},
	} {
		if _, err := ParseJSON([]byte(c.raw), c.input); !errors.Is(err, ErrBatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if b, err := ParseJSON([]byte(`{"format": "fair.integration.v1", "records": [`+recs(MaxRecords)+`]}`), InputRisks); err != nil || len(b.Records) != MaxRecords {
		t.Errorf("%d records: %v", MaxRecords, err)
	}
}

// Each kind's checks, by pointer.
func TestValidateKinds(t *testing.T) {
	for _, c := range []struct{ kind, raw, pointer string }{
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "n", "asset_type": "app"}`, ""},
		{KindAsset, `{"kind": "asset", "external_id": "", "bu": "A", "name": "n", "asset_type": "app"}`, "/external_id"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "name": "n", "asset_type": "app"}`, "/bu"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "n"}`, "/asset_type"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "n", "asset_type": "app", "value": {"min": "-1", "ml": "1", "max": "2"}}`, "/value/min"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "n", "asset_type": "app", "value": {"min": "1", "ml": "1", "max": "2", "confidence": "1"}}`, "/value/confidence"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "line\nbreak", "asset_type": "app"}`, "/name"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": "Bearer abcdefghijklmnopqrstuvwxyz0123456789", "asset_type": "app"}`, "/name"},
		{KindAsset, `{"kind": "asset", "external_id": "a", "bu": "A", "name": 7, "asset_type": "app"}`, "/name"},
		{KindAssetGroup, `{"kind": "asset_group", "external_id": "g", "bu": "A", "name": "n", "members": []}`, "/members"},
		{KindAssetGroup, `{"kind": "asset_group", "external_id": "g", "bu": "A", "name": "n", "members": ["a", "a"]}`, "/members/1"},
		{KindLossEvent, `{"kind": "loss_event", "external_id": "e", "bu": "A", "occurred_on": "2026-02-30", "event_type": "fraud"}`, "/occurred_on"},
		{KindLossEvent, `{"kind": "loss_event", "external_id": "e", "bu": "A", "occurred_on": "2026-02-03", "event_type": "fraud", "amounts": {"brand": "1"}}`, "/amounts/brand"},
		{KindLossEvent, `{"kind": "loss_event", "external_id": "e", "bu": "A", "occurred_on": "2026-02-03", "event_type": "fraud", "amounts": {"response": "1.1234567"}}`, "/amounts/response"},
		{KindLossEvent, `{"kind": "loss_event", "external_id": "e", "bu": "A", "occurred_on": "2026-02-03", "event_type": "fraud", "amounts": {"response": "12.5"}}`, ""},
		{KindRisk, `{"kind": "risk", "external_id": "r", "bu": "A", "title": "t", "owner": "not an address"}`, "/owner"},
		{KindRisk, `{"kind": "risk", "external_id": "r", "bu": "A", "title": "t", "likelihood": "high"}`, "/likelihood"},
		{KindRisk, `{"kind": "risk", "external_id": "r", "bu": "A", "title": "t", "owner": "rio@example.com", "category": "Cyber"}`, ""},
		{KindControlStatus, `{"kind": "control_status", "external_id": "c", "status": "retired", "assessed_on": "2026-11-01"}`, "/status"},
		{KindControlStatus, `{"kind": "control_status", "external_id": "c", "control": "x", "status": "in_place", "assessed_on": "2026-11-01"}`, "/control"},
		{KindControlStatus, `{"kind": "control_status", "external_id": "c", "status": "not_in_place", "assessed_on": "2026-11-01", "note": "Failed the quarterly test"}`, ""},
	} {
		rec, problems := Validate(c.kind, []byte(c.raw))
		switch {
		case c.pointer == "" && len(problems) > 0:
			t.Errorf("%s refused: %v", c.raw, problems)
		case c.pointer == "" && (rec.Digest == "" || rec.ExternalID == ""):
			t.Errorf("%s: %+v", c.raw, rec)
		case c.pointer != "" && (len(problems) == 0 || problems[0].Pointer != c.pointer):
			t.Errorf("%s: problems %v, want one at %q", c.raw, problems, c.pointer)
		}
	}
}

func TestParseCSV(t *testing.T) {
	m := Mapping{
		Columns:  map[string]string{"Event ID": "external_id", "Unit": "bu", "Date": "occurred_on", "Category": "event_type", "Response cost": "amounts/response", "Fine": "amounts/fines_judgments"},
		Values:   map[string]map[string]string{"event_type": {"PHISH": "Phishing", "FRAUD": "Payment fraud"}},
		Defaults: map[string]string{"bu": "CLAIMS"},
	}
	raw := "\xEF\xBB\xBFEvent ID,Unit,Date,Category,Response cost,Fine,Ignored\n" +
		"E-1,,2026-01-15,PHISH,12500.50,,x\n" +
		",,,,,,\n" +
		"E-2,FIN,2026-02-03,FRAUD,4000,250000,y\n" +
		"E-3,FIN,last week,FRAUD,1,,z\n" +
		"E-4,FIN,2026-03-01,FRAUD,=1+1,,z\n"
	b, err := ParseCSV([]byte(raw), InputLossEvents, m)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "csv.golden.json", render(b))
	if len(b.Records) != 2 || b.Refusals != 2 {
		t.Fatalf("%d records, %d refusals: %+v", len(b.Records), b.Refusals, b.Refused)
	}
	if !strings.Contains(string(b.Records[0].Data), `"bu":"CLAIMS"`) || !strings.Contains(string(b.Records[0].Data), `"event_type":"Phishing"`) {
		t.Errorf("defaults and value maps: %s", b.Records[0].Data)
	}
	if r := b.Refused[0]; r.N != 4 || r.Column != "Date" || r.Pointer != "/occurred_on" {
		t.Errorf("refusal %+v", r)
	}
	if r := b.Refused[1]; r.N != 5 || r.Column != "Response cost" {
		t.Errorf("a formula is not an amount: %+v", r)
	}
	// Refused files and mappings.
	if _, err := ParseCSV([]byte("Event ID,Date\nE-1,2026-01-01\n"), InputLossEvents, m); !errors.Is(err, ErrBatch) || !strings.Contains(err.Error(), "Category") {
		t.Errorf("missing columns: %v", err)
	}
	for name, bad := range map[string]Mapping{
		"no external_id":    {Columns: map[string]string{"Name": "name"}},
		"an unknown field":  {Columns: map[string]string{"ID": "external_id", "Risk": "likelihood"}},
		"a field twice":     {Columns: map[string]string{"ID": "external_id", "A": "occurred_on", "B": "occurred_on"}},
		"values of nothing": {Columns: map[string]string{"ID": "external_id"}, Values: map[string]map[string]string{"colour": {"a": "b"}}},
		"a default ID":      {Columns: map[string]string{"ID": "external_id"}, Defaults: map[string]string{"external_id": "x"}},
	} {
		if err := CheckMapping(InputLossEvents, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Asset groups' members from one column, split.
	g, err := ParseCSV([]byte("ID,Unit,Name,Type\nA-1,A,Claims platform,application\n"), InputAssets,
		Mapping{Columns: map[string]string{"ID": "external_id", "Unit": "bu", "Name": "name", "Type": "asset_type"}})
	if err != nil || len(g.Records) != 1 || g.Records[0].Kind != KindAsset {
		t.Errorf("assets from CSV: %+v %v", g, err)
	}
}

// The documented schema accepts the sample batch's valid records and the
// format's shape (docs/formats/fair-integration-v1.schema.json).
func TestSchema(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "formats", "fair-integration-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("fair-integration-v1.schema.json", sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("fair-integration-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	ok := `{"format": "fair.integration.v1", "complete": true, "records": [
		{"kind": "asset", "external_id": "a", "bu": "A", "name": "n", "asset_type": "app", "value": {"min": "1", "ml": "2", "max": "3"}},
		{"kind": "asset_group", "external_id": "g", "bu": "A", "name": "n", "members": ["a"]},
		{"kind": "loss_event", "external_id": "e", "bu": "A", "occurred_on": "2026-01-01", "event_type": "fraud", "amounts": {"response": "1"}},
		{"kind": "risk", "external_id": "r", "bu": "A", "title": "t", "owner": "rio@example.com"},
		{"kind": "control_status", "external_id": "c", "status": "in_place", "assessed_on": "2026-01-01"}]}`
	for _, raw := range []string{ok} {
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(raw))
		if err := s.Validate(inst); err != nil {
			t.Errorf("valid batch refused by the schema: %v", err)
		}
		if _, err := ParseJSON([]byte(raw), InputAssets); err != nil {
			t.Errorf("valid batch refused by ParseJSON: %v", err)
		}
	}
	for _, raw := range []string{
		`{"format": "fair.integration.v1", "records": [{"kind": "risk", "external_id": "r", "bu": "A", "title": "t", "likelihood": "high"}]}`,
		`{"format": "fair.integration.v2", "records": []}`,
	} {
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(raw))
		if err := s.Validate(inst); err == nil {
			t.Errorf("schema accepted %s", raw)
		}
	}
}

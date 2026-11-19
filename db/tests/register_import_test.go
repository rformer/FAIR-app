package tests

import (
	"strings"
	"testing"
)

// F-011 T-14 (F-011-AC-20 to AC-22; design §3.6): the register import
// through the register API: a CSV mapping, owners by email, categories by
// name, ratings refused or kept as text, a dry run's fingerprint, all or
// nothing, repeat imports as proposals.
func TestRegisterImport(t *testing.T) {
	im := reviewAllAPI(t)
	const path = "/api/v1/register/imports"
	csvFile := func(rows ...string) string {
		return "Risk ID,Risk,Details,Owner,Category,Likelihood,Notes\n" + strings.Join(rows, "\n") + "\n"
	}
	columns := map[string]string{"Risk ID": "external_id", "Risk": "title", "Details": "description", "Owner": "owner",
		"Category": "category", "Likelihood": "rating", "Notes": "text"}
	body := func(csv string, cols map[string]string, fp string) map[string]any {
		b := map[string]any{"bu_id": im.bu["A"], "label": "Old GRC", "csv": csv, "columns": cols}
		if fp != "" {
			b["fingerprint"] = fp
		}
		return b
	}
	risks := func() string { return im.adminQuery("SELECT count(*) FROM register.risk") }
	first := csvFile(
		`R-1,Ransomware on claims,Encryption of the claims platform,rowner@example.test,Cyber,High,"Reviewed Q3, keep"`,
		`R-2,Supplier outage,,,,Medium,`)

	// Who may import: register.edit at the BU.
	for _, user := range []string{"analyst", "erin"} {
		if got := im.call(t, "POST", user, path+"?dry_run=true", body(first, columns, "")); got.code != 404 && got.code != 403 {
			t.Errorf("%s imports: %d %s", user, got.code, got.raw)
		}
	}
	// Every column is mapped; owners and categories must match.
	partial := map[string]string{"Risk ID": "external_id", "Risk": "title"}
	if got := im.call(t, "POST", "rowner", path+"?dry_run=true", body(first, partial, "")); got.code != 422 || !strings.Contains(got.raw, "/columns/Likelihood") {
		t.Errorf("unmapped columns: %d %s", got.code, got.raw)
	}
	// Over the platform's 4 MiB, within F-011's 20 MiB: the file reaches the
	// import's checks rather than a 413.
	big := csvFile(`R-1,Ransomware,,,,High,` + strings.Repeat("x", 6<<20))
	if got := im.call(t, "POST", "rowner", path+"?dry_run=true", body(big, partial, "")); got.code != 422 {
		t.Errorf("a 6 MiB file: %d %.300s", got.code, got.raw)
	}
	bad := csvFile(`R-1,Ransomware,,nobody@example.test,Cyber,High,`, `R-2,Outage,,,Weather,Low,`, `,No id,,,,,`)
	got := im.call(t, "POST", "rowner", path+"?dry_run=true", body(bad, columns, ""))
	for _, want := range []string{"/rows/1/owner", "/rows/2/category", "/rows/3/external_id"} {
		if got.code != 422 || !strings.Contains(got.raw, want) {
			t.Errorf("problems (%s): %d %s", want, got.code, got.raw)
		}
	}

	// The dry run: nothing created, the rating column refused.
	got = im.call(t, "POST", "rowner", path+"?dry_run=true", body(first, columns, ""))
	if got.code != 200 || risks() != "0" || !strings.Contains(got.raw, `"refused_columns":["Likelihood"]`) || got.body["counts"].(map[string]any)["new"] != 2.0 {
		t.Fatalf("dry run: %d %s (risks %s)", got.code, got.raw, risks())
	}
	fp := got.body["fingerprint"].(string)
	if got := im.call(t, "POST", "rowner", path, body(first, columns, "")); got.code != 409 {
		t.Errorf("an import without the dry run's fingerprint: %d %s", got.code, got.raw)
	}
	if got := im.call(t, "POST", "rowner", path, body(csvFile(`R-1,Changed,,,,High,`), columns, fp)); got.code != 409 {
		t.Errorf("another file with the fingerprint: %d %s", got.code, got.raw)
	}
	got = im.call(t, "POST", "rowner", path, body(first, columns, fp))
	if got.code != 201 || got.body["counts"].(map[string]any)["applied"] != 2.0 {
		t.Fatalf("import: %d %s", got.code, got.raw)
	}
	r1 := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'R-1'")
	doc := im.adminQuery("SELECT convert_from(document, 'UTF8') FROM register.risk_version WHERE risk_id = '" + r1 + "' AND version = 1")
	if !strings.Contains(doc, "Imported Notes: Reviewed Q3, keep") || strings.Contains(doc, "High") || strings.Contains(doc, "Likelihood") {
		t.Errorf("R-1's document: %s", doc)
	}
	if got := im.adminQuery("SELECT r.state || ':' || (r.owner = " + uid("rowner") + ") || ':' || c.name FROM register.risk r JOIN register.category c ON c.id = r.category_id WHERE r.id = '" + r1 + "'"); got != "open:true:Cyber" {
		t.Errorf("R-1: %s", got)
	}
	// Unquantified: no scenarios.
	if got := im.call(t, "GET", "rowner", "/api/v1/register/risks/"+r1, nil); !strings.Contains(got.raw, "unquantified") || len(got.body["links"].([]any)) != 0 {
		t.Errorf("R-1 is not unquantified: %s", got.raw)
	}
	// Provenance: the file integration of the label.
	if vs := im.call(t, "GET", "rowner", "/api/v1/register/risks/"+r1+"/versions", nil); !strings.Contains(vs.raw, `"integration_name":"Register import: Old GRC"`) {
		t.Errorf("provenance: %s", vs.raw)
	}

	// A repeat: R-1 changed becomes a proposal, R-2 unchanged, R-3 new.
	second := csvFile(
		`R-1,Ransomware on claims and payments,Encryption of the claims platform,rowner@example.test,Cyber,High,"Reviewed Q3, keep"`,
		`R-2,Supplier outage,,,,Medium,`,
		`R-3,Data leak,,,Data privacy,Low,`)
	got = im.call(t, "POST", "rowner", path+"?dry_run=true", body(second, columns, ""))
	c := got.body["counts"].(map[string]any)
	if c["new"] != 1.0 || c["changed"] != 1.0 || c["unchanged"] != 1.0 {
		t.Errorf("the repeat's dry run: %s", got.raw)
	}
	got = im.call(t, "POST", "rowner", path, body(second, columns, got.body["fingerprint"].(string)))
	if got.code != 201 || risks() != "3" {
		t.Fatalf("the repeat: %d %s (risks %s)", got.code, got.raw, risks())
	}
	p := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'R-1' AND state = 'pending'")
	if p == "" {
		t.Fatal("no proposal for R-1")
	}
	if got := im.call(t, "POST", "rowner", "/api/v1/proposals/"+p+"/accept", map[string]any{"expected_version": 1}); got.code != 200 {
		t.Fatalf("accept R-1's change: %d %s", got.code, got.raw)
	}
	if got := im.adminQuery("SELECT title FROM register.risk WHERE id = '" + r1 + "'"); got != "Ransomware on claims and payments" {
		t.Errorf("R-1's title: %s", got)
	}

	// All or nothing: one bad row and nothing is imported.
	broken := csvFile(`R-4,Fraud,,,,Low,`, `R-5,,,,,Low,`)
	got = im.call(t, "POST", "rowner", path+"?dry_run=true", body(broken, columns, ""))
	if got.code != 422 || risks() != "3" {
		t.Errorf("a file with a bad row: %d %s (risks %s)", got.code, got.raw, risks())
	}

	// The JSON form: a rating field is refused, not imported.
	rated := map[string]any{"bu_id": im.bu["A"], "label": "Old GRC", "format": "fair.register-import.v1",
		"records": []any{map[string]any{"external_id": "R-6", "title": "Theft", "likelihood": "High"}}}
	if got := im.call(t, "POST", "rowner", path+"?dry_run=true", rated); got.code != 400 || !strings.Contains(got.raw, "likelihood") {
		t.Errorf("a rating field: %d %s", got.code, got.raw)
	}
	plain := map[string]any{"bu_id": im.bu["A"], "label": "Other", "format": "fair.register-import.v1",
		"records": []any{map[string]any{"external_id": "R-1", "title": "Same ID, another source", "text": map[string]string{"Score": "12"}}}}
	got = im.call(t, "POST", "rowner", path+"?dry_run=true", plain)
	if got.code != 200 || got.body["counts"].(map[string]any)["new"] != 1.0 {
		t.Errorf("external IDs are scoped by label: %d %s", got.code, got.raw)
	}

	if n := im.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'register.imported'"); n != "2" {
		t.Errorf("register.imported events: %s", n)
	}
}

package tests

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// F-001 T-38 (AC-48, AC-64): the entitlement report and the restricted-BU
// access listing, through the gateway and the iam API.

func TestEntitlementReport(t *testing.T) {
	be := bgFixture(t) // posture seeded, F-001 settings registered, nobody signed in yet
	e := be.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.addBU("R1", "R")
	for _, u := range []string{"ann", "auditor", "aud2", "carol", "dave", "viewer", "partial"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + strings.ToUpper(u[:1]) + u[1:] + "')")
	}
	e.mustOwner(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, expires_at)
		VALUES ('user', ` + uid("ann") + `, ` + roleID("Risk Analyst") + `, ` + buID("A") + `, ` + uid("admin") + `, now() + interval '30 days')`)
	e.mustOwner(grant("admin", "user:auditor", "Auditor", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:aud2", "Auditor", "R"))
	e.mustOwner(grant("admin", "user:bob", "Executive Viewer", "R1"))
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Ops')")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT " + grpID("Ops") + ", id FROM iam.app_user WHERE email IN ('carol@example.test', 'dave@example.test')")
	e.mustOwner(grant("admin", "group:Ops", "Executive Viewer", "A"))
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Entitlement Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['entitlement.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:viewer", "Entitlement Viewer", "ENTERPRISE"))
	// partial may view everywhere but export only at A.
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Entitlement Exporter') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['entitlement.export'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:partial", "Entitlement Viewer", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:partial", "Entitlement Exporter", "A"))
	// R becomes restricted, with aggregate roll-up (assignments inside it
	// were made first: restriction blocks granting from above).
	e.mustOwner("UPDATE iam.bu SET restricted = true, rollup_mode = 'aggregate' WHERE code = 'R'")
	// A break-glass account (at install, before anyone signs in).
	e.mustOwner(`SELECT iam.breakglass_install_enable('[{"email": "bg1@example.test", "name": "Break Glass"}]', ARRAY['\x` + strings.Repeat("cd", 32) + `'::bytea], 'DR policy')`)
	e.drain()

	admin := be.login(t, "admin")
	sa := be.do(t, "POST", "/api/v1/service-accounts", admin, map[string]any{"name": "Reporter", "bu_id": e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'"),
		"scopes": []string{"bu.view"}, "auth_method": "client_credentials", "reason": "reporting"}, be.hdrs(admin))
	if sa.code != http.StatusCreated {
		t.Fatalf("service account: %d %s", sa.code, sa.raw)
	}
	e.drain()

	type row = map[string]any
	rowsOf := func(r gwResp, key string) []row {
		list, _ := r.body[key].([]any)
		out := make([]row, 0, len(list))
		for _, x := range list {
			out = append(out, x.(row))
		}
		return out
	}
	report := func(cookie, query string) gwResp {
		t.Helper()
		r := be.do(t, "GET", "/api/v1/entitlements/report"+query, cookie, nil, nil)
		if r.code != 200 {
			t.Fatalf("report %s: %d %s", query, r.code, r.raw)
		}
		return r
	}
	emails := func(rows []row) string {
		var out []string
		for _, x := range rows {
			out = append(out, strings.TrimSuffix(x["email"].(string), "@example.test")+"@"+x["bu_code"].(string))
		}
		sort.Strings(out)
		return strings.Join(out, " ")
	}

	// AC-48: the fields, for an Auditor at the root.
	auditor := be.login(t, "auditor")
	r := report(auditor, "")
	all := rowsOf(r, "entitlements")
	if got := emails(all); strings.Contains(got, "bob@") || strings.Contains(got, "aud2@") ||
		!strings.Contains(got, "ann@A") || !strings.Contains(got, "carol@A") || !strings.Contains(got, "dave@A") || !strings.Contains(got, "bg1@ENTERPRISE") {
		t.Fatalf("an Auditor at the root sees: %s", got) // AC-64: nothing inside the restricted BU
	}
	byEmail := map[string]row{}
	for _, x := range all {
		byEmail[x["email"].(string)+"/"+x["role_name"].(string)] = x
	}
	ann := byEmail["ann@example.test/Risk Analyst"]
	if ann == nil || ann["role_builtin"] != true || ann["source"] != "manual" || ann["granted_by_email"] != "admin@example.test" ||
		ann["expires_at"] == nil || ann["bu_restricted"] != false || ann["user_kind"] != "user" || !strings.Contains(fmt.Sprint(ann["permissions"]), "analysis.edit") {
		t.Fatalf("ann's row: %v", ann)
	}
	if c := byEmail["carol@example.test/Executive Viewer"]; c == nil || c["source"] != "group" || c["via_group"] != "Ops" {
		t.Fatalf("carol's row: %v", c)
	}
	if bg := byEmail["bg1@example.test/Platform Admin"]; bg == nil || bg["breakglass"] != true || bg["user_kind"] != "breakglass" || bg["source"] != "breakglass" {
		t.Fatalf("the break-glass row: %v", bg)
	}
	if s := byEmail[e.adminQuery("SELECT email FROM iam.app_user WHERE display_name = 'Reporter'")+"/service account scopes"]; s == nil ||
		s["user_kind"] != "service_account" || s["source"] != "service_account" || fmt.Sprint(s["permissions"]) != "[bu.view]" {
		t.Fatalf("the service account row: %v", s)
	}
	if strings.Contains(r.raw, "installer@system.invalid") {
		t.Fatal("the Installer stand-in is listed")
	}
	// AC-64: the Auditor at the root sees no restricted BU, only that one exists.
	if rb := rowsOf(r, "restricted_bus"); len(rb) != 0 || r.body["restricted_bus_not_shown"] != float64(1) {
		t.Fatalf("restricted listing for a root Auditor: %v not shown %v", rb, r.body["restricted_bus_not_shown"])
	}

	// Filters.
	if got := emails(rowsOf(report(auditor, "?user="+e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'ann@example.test'")), "entitlements")); got != "ann@A" {
		t.Errorf("user filter: %s", got)
	}
	if got := emails(rowsOf(report(auditor, "?source=group"), "entitlements")); got != "carol@A dave@A" {
		t.Errorf("source filter: %s", got)
	}
	if got := emails(rowsOf(report(auditor, "?bu="+e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")+"&role="+e.adminQuery("SELECT id FROM iam.role WHERE name = 'Risk Analyst'")), "entitlements")); got != "ann@A" {
		t.Errorf("BU and role filters: %s", got)
	}
	if got := emails(rowsOf(report(auditor, "?expiring_before=2099-01-01T00:00:00Z"), "entitlements")); got != "ann@A" {
		t.Errorf("expiring filter: %s", got)
	}
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'dave@example.test'")
	if got := emails(rowsOf(report(auditor, "?source=group"), "entitlements")); got != "carol@A" {
		t.Errorf("inactive users listed: %s", got)
	}
	if got := emails(rowsOf(report(auditor, "?source=group&include_inactive=true"), "entitlements")); got != "carol@A dave@A" {
		t.Errorf("include_inactive: %s", got)
	}
	for _, q := range []string{"?user=nobody", "?source=magic", "?expiring_before=tomorrow", "?format=xml"} {
		if r := be.do(t, "GET", "/api/v1/entitlements/report"+q, auditor, nil, nil); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, r.code)
		}
	}

	// AC-64: an Auditor assigned in the restricted BU sees it and everyone
	// with access to it.
	aud2 := be.login(t, "aud2")
	r = report(aud2, "")
	if got := emails(rowsOf(r, "entitlements")); got != "aud2@R bob@R1" {
		t.Fatalf("an Auditor inside R sees: %s", got)
	}
	if x := rowsOf(r, "entitlements")[1]; x["bu_restricted"] != false || rowsOf(r, "entitlements")[0]["bu_restricted"] != true {
		t.Fatalf("restricted flags: %v", rowsOf(r, "entitlements"))
	}
	listing := func(cookie string) (map[string]string, gwResp) {
		r := be.do(t, "GET", "/api/v1/entitlements/restricted", cookie, nil, nil)
		if r.code != 200 {
			t.Fatalf("listing: %d %s", r.code, r.raw)
		}
		out := map[string]string{}
		for _, x := range rowsOf(r, "restricted_bus") {
			if x["bu_code"] != "R" {
				t.Fatalf("listed %v", x)
			}
			if x["email"] == nil {
				out["(nobody)"] = ""
				continue
			}
			out[strings.TrimSuffix(x["email"].(string), "@example.test")] = x["access"].(string)
		}
		return out, r
	}
	if got, r := listing(aud2); got["aud2"] != "read" || got["bob"] != "" || r.body["not_shown"] != float64(0) {
		t.Fatalf("listing for aud2: %v %v", got, r.raw)
	}
	// bob's access is to R1 (inside R), not R itself; the Auditor at the
	// root reads R only as an aggregate roll-up.
	// The restriction owner (Platform Admin: bu.restrict at R's parent)
	// sees R and who has access, but no entitlement rows inside it.
	got, adminListing := listing(admin)
	if got["aud2"] != "read" || got["auditor"] != "aggregate" {
		t.Fatalf("listing for the restriction owner: %v", got)
	}
	if strings.Contains(emails(rowsOf(report(admin, ""), "entitlements")), "@R") {
		t.Fatal("the restriction owner sees entitlement rows inside R")
	}

	// Files: CSV and PDF need entitlement.export, and are audited.
	viewer := be.login(t, "viewer")
	if r := be.do(t, "GET", "/api/v1/entitlements/report", viewer, nil, nil); r.code != 200 {
		t.Fatalf("viewer JSON: %d", r.code)
	}
	for _, f := range []string{"csv", "pdf"} {
		if r := be.do(t, "GET", "/api/v1/entitlements/report?format="+f, viewer, nil, nil); r.code != http.StatusForbidden ||
			r.body["detail"] != "exporting needs entitlement.export" {
			t.Errorf("%s without entitlement.export: %d %s", f, r.code, r.raw)
		}
	}
	c := be.do(t, "GET", "/api/v1/entitlements/report?format=csv&source=group", auditor, nil, nil)
	if c.code != 200 || !strings.HasPrefix(c.hdr.Get("Content-Type"), "text/csv") || !strings.Contains(c.hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("CSV: %d %v", c.code, c.hdr)
	}
	recs, err := csv.NewReader(bytes.NewReader([]byte(strings.TrimPrefix(c.raw, string(rune(0xFEFF)))))).ReadAll()
	if err != nil || len(recs) != 2 || recs[0][1] != "email" || recs[1][1] != "carol@example.test" || recs[1][14] != "Ops" {
		t.Fatalf("CSV rows: %v %v", recs, err)
	}
	// A file holds only the rows of BUs where the caller may export.
	partial := be.login(t, "partial")
	if got := len(rowsOf(report(partial, ""), "entitlements")); got != len(all)-1 {
		t.Fatalf("partial's JSON rows: %d", got) // all rows but dave's (disabled by now)
	}
	pc := be.do(t, "GET", "/api/v1/entitlements/report?format=csv", partial, nil, nil)
	pr, _ := csv.NewReader(bytes.NewReader([]byte(strings.TrimPrefix(pc.raw, string(rune(0xFEFF)))))).ReadAll()
	for _, rec := range pr[1:] {
		if rec[10] != "A" {
			t.Fatalf("partial exported a row of %s", rec[10])
		}
	}
	if pc.code != 200 || len(pr) < 4 {
		t.Fatalf("partial's CSV: %d %d rows", pc.code, len(pr))
	}
	p := be.do(t, "GET", "/api/v1/entitlements/report?format=pdf", auditor, nil, nil)
	if p.code != 200 || p.hdr.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(p.raw, "%PDF-1.7") ||
		!strings.Contains(p.raw, "(ann@example.test) Tj") || !strings.Contains(p.raw, "/StructTreeRoot") ||
		!strings.Contains(p.raw, "1 other restricted BU\\(s\\) exist") {
		t.Fatalf("PDF: %d %v %.200s", p.code, p.hdr, p.raw)
	}
	if lp := be.do(t, "GET", "/api/v1/entitlements/restricted?format=pdf", admin, nil, nil); lp.code != 200 || !strings.Contains(lp.raw, `(aud2@example.test \(user\)) Tj`) {
		t.Fatalf("listing PDF: %d", lp.code)
	}
	if got := e.adminQuery(`SELECT string_agg(payload->'attributes'->>'format' || ':' || (payload->>'target') || ':' || (payload->'attributes'->>'rows'), ',' ORDER BY id)
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'entitlement.exported'`); got != "csv:report:entitlements:1,csv:report:entitlements:"+fmt.Sprint(len(pr)-1)+",pdf:report:entitlements:"+fmt.Sprint(len(all)-1)+",pdf:report:restricted_bus:"+fmt.Sprint(len(rowsOf(adminListing, "restricted_bus"))) {
		// all included dave before he was disabled; the PDF ran after.
		t.Fatalf("export audit: %s", got)
	}

	// Without entitlement.view the report does not exist.
	if r := be.do(t, "GET", "/api/v1/entitlements/report", be.login(t, "ann"), nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without entitlement.view: %d", r.code)
	}
	e.mustFail("app_rw", "SELECT * FROM iam.entitlement_report(false, NULL, NULL, NULL, NULL, false, NULL, false)", "signed database context")
}

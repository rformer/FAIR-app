package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-10 (F-010-AC-08, AC-10, AC-11; design §3.4): the register,
// acceptances and treatment reports read what the register and acceptance
// APIs show the same person, under RLS: hidden BUs are absent and
// restricted BUs appear only as their roll-up mode allows.

// readAs runs fn in a read-only snapshot under user's session context.
func readAs(t *testing.T, ra *riskAPIEnv, user string, fn func(pgx.Tx) error) {
	t.Helper()
	if err := authz.WithDBSnapshot(context.Background(), ra.appPool(), ra.principal(user).DBToken, fn); err != nil {
		t.Fatal(err)
	}
}

// build reads a kind's document as user at bu, checks it and renders it in
// every format.
func build(t *testing.T, ra *riskAPIEnv, user, bu, buName string, k reports.Kind, params string) reports.Built {
	t.Helper()
	p, err := k.CheckParams(json.RawMessage(params))
	if err != nil {
		t.Fatalf("%s params %s: %v", k.Name, params, err)
	}
	var b reports.Built
	readAs(t, ra, user, func(tx pgx.Tx) error {
		var err error
		b, err = k.Read(context.Background(), tx, reports.Run{ID: "00000000-0000-4000-8000-000000000001", Kind: k.Name, BU: doc.Ref{ID: bu, Name: buName},
			Params: p, RequestedBy: user, RequesterName: user})
		return err
	})
	m := &b.Doc.Metadata
	m.RunID, m.Kind, m.BU, m.GeneratedAt, m.GeneratedBy, m.DataAsOf, m.Currency, m.Marking = "00000000-0000-4000-8000-000000000001", k.Name,
		doc.Ref{ID: bu, Name: buName}, time.Now().UTC(), user, time.Now().UTC(), "USD", "Confidential"
	if err := b.Doc.Validate(); err != nil {
		t.Fatalf("%s as %s: %v", k.Name, user, err)
	}
	if _, err := reports.PDF(b.Doc); err != nil {
		t.Fatalf("%s PDF: %v", k.Name, err)
	}
	if _, err := b.Doc.CSV(); err != nil {
		t.Fatalf("%s CSV: %v", k.Name, err)
	}
	return b
}

func tableOf(d doc.Document, id string) *doc.Table {
	for _, t := range d.Tables() {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func column(t *doc.Table, key string) []string {
	i := slices.IndexFunc(t.Columns, func(c doc.Column) bool { return c.Key == key })
	var out []string
	for _, r := range t.Rows {
		out = append(out, r[i])
	}
	return out
}

func TestReportReaders(t *testing.T) {
	a := acceptanceFixture(t)
	ra, rg := a.ra, a.rg
	ctx := context.Background()
	// R is restricted (under A) and appears in roll-ups as totals only; rown
	// owns a risk there that nobody outside R reads.
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code IN ('R', 'R1')")
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rown@example.test', 'Rown')")
	ra.mustOwner(grant("platform", "user:rown", "Risk Owner", "R"))
	ra.drain()
	rown := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rown@example.test'")
	mk := func(user, bu, title, owner string) string {
		t.Helper()
		got := rg.call(t, "POST", user, "/api/v1/register/risks", map[string]any{"bu_id": bu, "change_note": "x",
			"document": map[string]any{"schema_version": 1, "title": title, "owner": owner, "state": "open", "scenarios": []any{}}})
		if got.code != 201 {
			t.Fatalf("create %s: %d %s", title, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	mk("rown", ra.bu["R"], "Restricted risk", rown)
	unq := mk("chief", ra.bu["B"], "Vendor outage", a.chief)
	accepted := a.accepted(t, "Claims leak", "owen")
	acc, code := a.request(t, "owen", accepted, "Within appetite", days(200), "")
	if code != "" {
		t.Fatalf("request: %s", code)
	}
	if _, code := a.decide(t, "appA1", acc, "approve"); code != "" {
		t.Fatalf("approve: %s", code)
	}
	// owen's first risk gets a plan with an overdue, a future and a done action.
	act := func(id, title, due, state string) map[string]any {
		x := map[string]any{"id": id, "title": title, "owner": a.owen, "due": due, "state": state}
		if state == "cancelled" {
			x["cancel_reason"] = "Not needed"
		}
		return x
	}
	if got := rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+a.risk+"/treatment", map[string]any{"expected_version": 0, "change_note": "plan",
		"document": map[string]any{"schema_version": 1, "decision": "transfer", "rationale": "Insure it.", "actions": []any{
			act("a1a1a1a1-0000-4000-8000-000000000001", "Buy cover", "2099-01-01", "planned"),
			act("a2a2a2a2-0000-4000-8000-000000000002", "Brief the broker", "2020-01-01", "in_progress"),
			act("a3a3a3a3-0000-4000-8000-000000000003", "Get quotes", "2020-02-01", "done"),
			act("a4a4a4a4-0000-4000-8000-000000000004", "Drop it", "2020-02-01", "cancelled")}}}); got.code != 200 {
		t.Fatalf("treatment: %d %s", got.code, got.raw)
	}

	// The register report equals the register API's open risks, for each
	// reader (AC-08, AC-11).
	for _, c := range []struct{ user, bu string }{{"chief", "ENTERPRISE"}, {"owen", "A"}, {"mallory", "B"}, {"mallory", "ENTERPRISE"}} {
		api := rg.call(t, "GET", c.user, "/api/v1/register/risks?state=open&limit=200&bu="+ra.bu[c.bu], nil)
		want := map[string]string{}
		for _, x := range api.body["risks"].([]any) {
			m := x.(map[string]any)
			want[m["id"].(string)] = m["status"].(map[string]any)["status"].(string)
		}
		var rows []reports.RegisterRow
		readAs(t, ra, c.user, func(tx pgx.Tx) error {
			var err error
			rows, err = reports.RegisterRows(ctx, tx, ra.bu[c.bu], reports.RegisterParams{})
			return err
		})
		got := map[string]string{}
		for _, r := range rows {
			got[r.ID] = r.Status
		}
		if fmt.Sprint(got) != fmt.Sprint(want) || len(got) == 0 {
			t.Errorf("%s at %s: report %v, API %v", c.user, c.bu, got, want)
		}
	}
	b := build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.RegisterKind, "")
	risks := tableOf(b.Doc, "risks")
	titles := column(risks, "risk")
	if slices.Contains(titles, "Restricted risk") || !slices.Contains(titles, "Vendor outage") || !slices.Contains(titles, "Claims ransomware") || b.Risks != len(titles) {
		t.Errorf("chief's register: %v", titles)
	}
	if titles[0] != "Claims ransomware" && titles[0] != "Claims leak" { // the quantified ones first
		t.Errorf("order: %v", titles)
	}
	lo := b.Doc.Metadata.LeftOut
	if lo["units_aggregate_only"] != 2 || lo["units_not_visible"] != 0 || lo["unquantified"] != 1 || len(b.Doc.Metadata.Runs) != 2 {
		t.Errorf("chief's left out %v, runs %v", lo, b.Doc.Metadata.Runs)
	}
	if r := b.Doc.Metadata.Runs[0]; r.Seed == "" || r.InputDigest == "" || r.Scenario == "" {
		t.Errorf("run reference: %+v", r)
	}
	row := risks.Rows[slices.Index(titles, "Claims leak")]
	if row[1] != "Owen" || row[3] != "4.5" || row[7] != "accept" || row[8] != "active" || row[9] != days(200).Format(time.DateOnly) {
		t.Errorf("an accepted risk's row: %v", row)
	}
	if row := risks.Rows[slices.Index(titles, "Vendor outage")]; row[3] != "" || row[6] != "unquantified" {
		t.Errorf("an unquantified risk's row: %v", row)
	}
	// Mallory reads only B; the rest of the root's subtree is left out.
	b = build(t, ra, "mallory", ra.bu["ENTERPRISE"], "Enterprise", reports.RegisterKind, "")
	if titles := column(tableOf(b.Doc, "risks"), "risk"); fmt.Sprint(titles) != "[Vendor outage]" || b.Doc.Metadata.LeftOut["units_not_visible"] == 0 {
		t.Errorf("mallory's register: %v %v", titles, b.Doc.Metadata.LeftOut)
	}
	// Filters, as the register list's.
	b = build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.RegisterKind, `{"acceptance":"active","decision":"accept"}`)
	if titles := column(tableOf(b.Doc, "risks"), "risk"); fmt.Sprint(titles) != "[Claims leak]" || b.Doc.Metadata.Filters["acceptance"] != "active" {
		t.Errorf("filtered: %v", titles)
	}
	for _, bad := range []string{`{"status":"red"}`, `{"owner":"x"}`, `{"colour":"red"}`, `{"decision":"maybe"}`} {
		if _, err := reports.RegisterKind.CheckParams(json.RawMessage(bad)); err == nil {
			t.Errorf("params %s accepted", bad)
		}
	}

	// The acceptances report equals the acceptance API's (AC-08).
	ac := acceptanceAPI(t, ra)
	api := ac.call(t, "GET", "chief", "/api/v1/acceptances?bu="+ra.bu["ENTERPRISE"], nil)
	want := map[string]string{}
	for _, x := range api.body["acceptances"].([]any) {
		m := x.(map[string]any)
		if m["state"] != "ended" {
			want[m["id"].(string)] = m["state"].(string)
		}
	}
	var accs []reports.AcceptanceRow
	readAs(t, ra, "chief", func(tx pgx.Tx) error {
		var err error
		accs, err = reports.AcceptanceRows(ctx, tx, ra.bu["ENTERPRISE"])
		return err
	})
	got := map[string]string{}
	for _, x := range accs {
		got[x.ID] = x.State
	}
	if fmt.Sprint(got) != fmt.Sprint(want) || got[acc] != "active" {
		t.Errorf("acceptances: report %v, API %v", got, want)
	}
	b = build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.AcceptancesKind, `{"expiring_within":365}`)
	dec := tableOf(b.Doc, "decisions")
	if len(dec.Rows) != 1 || dec.Rows[0][3] != "approved" || dec.Rows[0][4] != "appA1" || dec.Rows[0][5] != "Reviewed with the committee" ||
		len(tableOf(b.Doc, "expiring").Rows) != 1 || column(tableOf(b.Doc, "acceptances"), "requested_by")[0] != "Owen" {
		t.Errorf("acceptances report: %+v %+v", dec.Rows, tableOf(b.Doc, "acceptances").Rows)
	}
	b = build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.AcceptancesKind, `{"expiring_within":30,"decided_to":"2020-01-01"}`)
	if len(tableOf(b.Doc, "expiring").Rows) != 0 || len(tableOf(b.Doc, "decisions").Rows) != 0 {
		t.Error("the period and the window do not filter")
	}
	if _, err := reports.AcceptancesKind.CheckParams(json.RawMessage(`{"decided_from":"2026-02-01","decided_to":"2026-01-01"}`)); err == nil {
		t.Error("a period ending before it starts")
	}
	b = build(t, ra, "mallory", ra.bu["ENTERPRISE"], "Enterprise", reports.AcceptancesKind, "")
	if len(tableOf(b.Doc, "acceptances").Rows) != 0 {
		t.Error("mallory reads A1's acceptances")
	}

	// The treatment report: overdue first, then by due date; cancelled ones
	// left out; the decision with each (AC-08).
	b = build(t, ra, "owen", ra.bu["A"], "A", reports.TreatmentKind, "")
	acts := tableOf(b.Doc, "actions")
	if fmt.Sprint(column(acts, "action")) != "[Brief the broker Get quotes Buy cover]" || fmt.Sprint(column(acts, "overdue")) != "[yes no no]" ||
		column(acts, "decision")[0] != "transfer" || column(acts, "owner")[0] != "Owen" || b.Risks != 1 {
		t.Errorf("treatment: %v", acts.Rows)
	}
	b = build(t, ra, "owen", ra.bu["A"], "A", reports.TreatmentKind, `{"owner":"`+a.chief+`"}`)
	if len(tableOf(b.Doc, "actions").Rows) != 0 {
		t.Error("the owner filter")
	}
	// Without treatment.view (viewer: register.view alone) nothing is listed.
	b = build(t, ra, "viewer", ra.bu["A"], "A", reports.TreatmentKind, "")
	if len(tableOf(b.Doc, "actions").Rows) != 0 {
		t.Error("viewer reads treatment plans")
	}
	_ = unq

	// End to end: chief generates the register report through the API and
	// worker with the built-in kinds.
	ra.mustOwner(grant("platform", "user:chief", "Report Publisher", "ENTERPRISE"))
	ra.drain()
	re := reportAPI(t, ra, reports.Kinds())
	req := re.call(t, "POST", "chief", "/api/v1/reports", map[string]any{"kind": "register", "bu_id": ra.bu["ENTERPRISE"], "formats": []string{"pdf", "json"},
		"reason": "Committee pack", "params": map[string]any{"status": "current"}})
	if req.code != 202 {
		t.Fatalf("request: %d %s", req.code, req.raw)
	}
	id := req.body["id"].(string)
	if err := re.attempt(t, id, 1); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ' ' || risk_count || ' ' || (left_out ->> 'units_aggregate_only') FROM report.run WHERE id = '" + id + "'"); got != "succeeded 2 2" {
		t.Errorf("the run: %s", got)
	}
	_, body, _ := re.download(t, "chief", id, "json")
	if !strings.Contains(string(body), `"title":"Risk register: `) || strings.Contains(string(body), "Restricted risk") {
		t.Errorf("the JSON: %.300s", body)
	}
	if kinds := re.call(t, "GET", "chief", "/api/v1/reports/kinds", nil); len(kinds.body["kinds"].([]any)) != 5 {
		t.Errorf("kinds: %s", kinds.raw)
	}
}

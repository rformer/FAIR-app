package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// F-007 T-03 (F-007-AC-01 to AC-06, AC-15, AC-17, AC-21; design §3, §5.1):
// the register schema: risk and treatment versions checked in the
// database, heads and links kept by their triggers, one open risk per
// scenario, append-only versions.

// registerDoc is a canonical document and its digest.
func registerDoc(t *testing.T, doc map[string]any) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canon.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b, canon.Digest(b)
}

// newRisk creates a risk head at bu with version 1 as user, returning its
// id, or the error (nothing is kept then).
func newRisk(t *testing.T, ra *riskAPIEnv, user, bu string, doc map[string]any) (string, error) {
	t.Helper()
	var id string
	err := ra.tx(user, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := tx.QueryRow(ctx, "INSERT INTO register.risk (bu_id) VALUES ($1) RETURNING id::text", bu).Scan(&id); err != nil {
			return err
		}
		b, d := registerDoc(t, doc)
		_, err := tx.Exec(ctx, "INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES ($1, 1, $2, $3, 'first')", id, b, d)
		return err
	})
	return id, err
}

// riskVersion adds a version of risk as user.
func riskVersion(t *testing.T, ra *riskAPIEnv, user, risk string, version int, doc map[string]any) error {
	t.Helper()
	return ra.tx(user, func(tx pgx.Tx) error {
		b, d := registerDoc(t, doc)
		_, err := tx.Exec(context.Background(), "INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES ($1, $2, $3, $4, 'change')",
			risk, version, b, d)
		return err
	})
}

// treatmentVersion adds a version of risk's treatment as user, creating
// the treatment head first when version is 1.
func treatmentVersion(t *testing.T, ra *riskAPIEnv, user, risk string, version int, doc map[string]any) error {
	t.Helper()
	return ra.tx(user, func(tx pgx.Tx) error {
		ctx := context.Background()
		if version == 1 {
			if _, err := tx.Exec(ctx, "INSERT INTO register.treatment (risk_id, bu_id) SELECT id, bu_id FROM register.risk WHERE id = $1", risk); err != nil {
				return err
			}
		}
		b, d := registerDoc(t, doc)
		_, err := tx.Exec(ctx, "INSERT INTO register.treatment_version (risk_id, version, document, digest, change_note) VALUES ($1, $2, $3, $4, 'plan')",
			risk, version, b, d)
		return err
	})
}

// with is doc with the given top-level changes (nil deletes a key).
func with(doc map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range doc {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
		} else {
			out[kv[i].(string)] = kv[i+1]
		}
	}
	return out
}

func TestRegisterSchema(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, mallory at B, erin a Risk Owner at A1 (and Executive Viewer at A)
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	seedPosture(t, ra.env) // the settings in force, as in production
	if got := ra.adminQuery("SELECT iam.instance_setting('register.iterations')"); got != "100000" {
		t.Fatalf("register.iterations in force: %q", got)
	}
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s2 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims fraud")
	s3 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims outage")
	s0 := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 100_000, "7")
	r2 := runWith(t, ae, "analyst", s2, 1, 100_000, "7")
	small := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	queued := runOf(t, ae, "analyst", s1, 100_000, true)
	_ = sb
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	mallory := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'mallory@example.test'")
	cyber := ra.adminQuery("SELECT id FROM register.category WHERE name = 'Cyber'")
	link := func(scenario string, pin map[string]any) map[string]any {
		l := map[string]any{"scenario_id": scenario}
		if pin != nil {
			l["pin"] = pin
		}
		return l
	}
	base := map[string]any{"schema_version": 1, "title": "Ransomware on claims", "description": "Encryption of the claims platform.",
		"owner": erin, "category": cyber, "state": "open",
		"scenarios": []any{link(s1, map[string]any{"run_id": r1, "control_set": "Current"}), link(s2, nil)}}

	// A valid risk: the head's summary and the links follow the document.
	risk, err := newRisk(t, ra, "erin", ra.bu["A1"], base)
	if err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT current_version || '|' || state || '|' || title || '|' || owner || '|' || category_id FROM register.risk WHERE id = '" + risk + "'"); got !=
		"1|open|Ransomware on claims|"+erin+"|"+cyber {
		t.Errorf("head: %s", got)
	}
	if got := ra.adminQuery("SELECT string_agg(scenario_id || ':' || open || ':' || coalesce(run_id::text, '-') || ':' || coalesce(pinned_version::text, '-'), ',' ORDER BY scenario_id <> '" + s1 + "') FROM register.risk_scenario WHERE risk_id = '" + risk + "'"); got !=
		s1+":true:"+r1+":1,"+s2+":true:-:-" {
		t.Errorf("links: %s", got)
	}

	// Every rule, by pointer.
	for name, c := range map[string]struct {
		doc  map[string]any
		want string
	}{
		"an unknown field":            {with(base, "colour", "red"), "/colour: is not a known field"},
		"no title":                    {with(base, "title", nil), "/title: is required"},
		"the wrong schema version":    {with(base, "schema_version", 2), "/schema_version: is 1"},
		"an owner who cannot see it":  {with(base, "owner", mallory), "/owner: is a user who holds register.view"},
		"an unknown category":         {with(base, "category", "00000000-0000-4000-8000-000000000000"), "/category: is not a category in use"},
		"an unknown state":            {with(base, "state", "pending"), "/state: is open or closed"},
		"closed without a reason":     {with(base, "state", "closed"), "/close_reason: is required"},
		"a reason while open":         {with(base, "close_reason", "x"), "/close_reason: is given only when the risk is closed"},
		"a scenario outside the BU":   {with(base, "scenarios", []any{link(s0, nil)}), "/scenarios/0/scenario_id: is outside the risk's business unit"},
		"a scenario not seen":         {with(base, "scenarios", []any{link(sb, nil)}), "/scenarios/0/scenario_id: is not a scenario you can see"},
		"a scenario twice":            {with(base, "scenarios", []any{link(s3, nil), link(s3, nil)}), "/scenarios/1/scenario_id: is linked twice"},
		"another scenario's run":      {with(base, "scenarios", []any{link(s3, map[string]any{"run_id": r2, "control_set": "Current"})}), "/scenarios/0/pin/run_id: is not a run of this scenario"},
		"an unfinished run":           {with(base, "scenarios", []any{link(s1, map[string]any{"run_id": queued, "control_set": "Current"})}), "/scenarios/0/pin/run_id: is not a succeeded run"},
		"other iterations":            {with(base, "scenarios", []any{link(s1, map[string]any{"run_id": small, "control_set": "Current"})}), "/scenarios/0/pin/run_id: has 2000 iterations"},
		"not a set of the run":        {with(base, "scenarios", []any{link(s1, map[string]any{"run_id": r1, "control_set": "Elsewhere"})}), "/scenarios/0/pin/control_set"},
		"another set without reason":  {with(base, "scenarios", []any{link(s1, map[string]any{"run_id": r1, "control_set": "Proposed"})}), "/scenarios/0/pin/reason: is required"},
		"a pin with an unknown field": {with(base, "scenarios", []any{link(s1, map[string]any{"run_id": r1, "control_set": "Current", "by": "me"})}), "/scenarios/0/pin/by: is not a known field"},
	} {
		if _, err := newRisk(t, ra, "erin", ra.bu["A1"], c.doc); !strings.HasPrefix(pgCode(err), "PF026 ") || !strings.Contains(pgCode(err), c.want) {
			t.Errorf("%s: %v", name, pgCode(err))
		}
	}
	if _, err := newRisk(t, ra, "erin", ra.bu["A1"], with(base, "scenarios", []any{link(s3, map[string]any{"run_id": r1, "control_set": "Proposed", "reason": "the plan"})})); !strings.Contains(pgCode(err), "is not a run of this scenario") {
		t.Errorf("a reason does not make another scenario's run right: %v", pgCode(err))
	}
	// Without the write scope: RLS (mallory at B; the analyst holds no register.edit).
	if _, err := newRisk(t, ra, "analyst", ra.bu["A1"], base); err == nil {
		t.Error("a Risk Analyst created a risk")
	}

	// One open risk per scenario (AC-02).
	other, err := newRisk(t, ra, "erin", ra.bu["A1"], with(base, "title", "Claims fraud", "scenarios", []any{link(s1, nil)}))
	if !strings.HasPrefix(pgCode(err), "PF026 ") || !strings.Contains(pgCode(err), "linked to another open risk") {
		t.Fatalf("a scenario linked twice: %v", pgCode(err))
	}
	other, err = newRisk(t, ra, "erin", ra.bu["A1"], with(base, "title", "Claims outage", "scenarios", []any{link(s3, nil)}))
	if err != nil {
		t.Fatal(err)
	}

	// Versions: stale numbers, digests, a pin kept or changed.
	if err := riskVersion(t, ra, "erin", risk, 3, base); !strings.Contains(pgCode(err), "is stale") {
		t.Errorf("a stale version: %v", pgCode(err))
	}
	if err := ra.tx("erin", func(tx pgx.Tx) error {
		b, _ := registerDoc(t, base)
		_, err := tx.Exec(context.Background(), "INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES ($1, 2, $2, $3, 'x')",
			risk, b, strings.Repeat("0", 64))
		return err
	}); !strings.Contains(pgCode(err), "the digest does not match") {
		t.Errorf("a wrong digest: %v", pgCode(err))
	}
	if err := riskVersion(t, ra, "erin", risk, 2, with(base, "title", "Ransomware on the claims platform")); err != nil {
		t.Fatal(err)
	}
	pinned := func() string {
		return ra.adminQuery("SELECT coalesce(pinned_version::text, '-') || ':' || coalesce(control_set, '-') FROM register.risk_scenario WHERE risk_id = '" + risk + "' AND scenario_id = '" + s1 + "'")
	}
	if got := pinned(); got != "1:Current" {
		t.Errorf("an unchanged pin: %s", got)
	}
	v3 := with(base, "title", "Ransomware on the claims platform", "scenarios", []any{link(s1, map[string]any{"run_id": r1, "control_set": "Proposed", "reason": "the plan in place"}), link(s2, nil)})
	if err := riskVersion(t, ra, "erin", risk, 3, v3); err != nil {
		t.Fatal(err)
	}
	if got := pinned(); got != "3:Proposed" {
		t.Errorf("a changed pin: %s", got)
	}
	// Unlinking s2 removes its link.
	v4 := with(v3, "scenarios", []any{link(s1, map[string]any{"run_id": r1, "control_set": "Proposed", "reason": "the plan in place"})})
	if err := riskVersion(t, ra, "erin", risk, 4, v4); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT count(*) FROM register.risk_scenario WHERE risk_id = '" + risk + "'"); got != "1" {
		t.Errorf("links after unlinking: %s", got)
	}

	// Closing (AC-04): nothing else changes; a closed risk only reopens, as
	// it was; its scenarios are free meanwhile.
	if err := riskVersion(t, ra, "erin", risk, 5, with(v4, "state", "closed", "close_reason", "Moved to the group register", "title", "Other")); !strings.Contains(pgCode(err), "closing a risk changes nothing else") {
		t.Errorf("closing with a change: %v", pgCode(err))
	}
	closed := with(v4, "state", "closed", "close_reason", "Moved to the group register")
	if err := riskVersion(t, ra, "erin", risk, 5, closed); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ':' || (SELECT bool_or(open)::text FROM register.risk_scenario WHERE risk_id = r.id) FROM register.risk r WHERE id = '" + risk + "'"); got != "closed:false" {
		t.Errorf("closed: %s", got)
	}
	if err := riskVersion(t, ra, "erin", risk, 6, with(closed, "title", "Edited while closed")); !strings.Contains(pgCode(err), "a closed risk changes only by being reopened") {
		t.Errorf("a closed risk edited: %v", pgCode(err))
	}
	if err := riskVersion(t, ra, "erin", other, 2, with(base, "title", "Claims outage", "scenarios", []any{link(s3, nil), link(s1, nil)})); err != nil {
		t.Fatalf("linking a closed risk's scenario: %v", err)
	}
	if err := riskVersion(t, ra, "erin", risk, 6, with(closed, "state", "open", "close_reason", nil)); !strings.Contains(pgCode(err), "linked to another open risk") {
		t.Errorf("reopening onto a scenario linked meanwhile: %v", pgCode(err))
	}
	if err := riskVersion(t, ra, "erin", other, 3, with(base, "title", "Claims outage", "scenarios", []any{link(s3, nil)})); err != nil {
		t.Fatal(err)
	}
	if err := riskVersion(t, ra, "erin", risk, 6, with(closed, "state", "open", "close_reason", nil)); err != nil {
		t.Fatalf("reopening: %v", err)
	}

	// Append-only and definer-only (PF025; privileges for app_rw).
	for name, c := range map[string]struct{ user, sql, code string }{
		"app_rw updates a version": {"erin", "UPDATE register.risk_version SET change_note = 'x' WHERE risk_id = '" + risk + "'", "42501"},
		"app_rw updates a head":    {"erin", "UPDATE register.risk SET title = 'x' WHERE id = '" + risk + "'", "42501"},
		"app_rw writes a link":     {"erin", "INSERT INTO register.risk_scenario (risk_id, scenario_id, bu_id, open) VALUES ('" + risk + "', '" + s2 + "', '" + ra.bu["A1"] + "', true)", "42501"},
		"app_rw adds a category":   {"erin", "INSERT INTO register.category (name) VALUES ('Mine')", "42501"},
	} {
		if err := ra.tx(c.user, func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), c.sql); return err }); !strings.HasPrefix(pgCode(err), c.code+" ") {
			t.Errorf("%s: %v", name, pgCode(err))
		}
	}
	for name, sql := range map[string]string{
		"a version updated":  "UPDATE register.risk_version SET change_note = 'x' WHERE risk_id = '" + risk + "'",
		"a version deleted":  "DELETE FROM register.risk_version WHERE risk_id = '" + risk + "'",
		"a head deleted":     "DELETE FROM register.risk WHERE id = '" + risk + "'",
		"a head updated":     "UPDATE register.risk SET title = 'x' WHERE id = '" + risk + "'",
		"a category deleted": "DELETE FROM register.category WHERE name = 'Fraud'",
	} {
		if code := ra.adminState(sql); code != "PF025" {
			t.Errorf("superuser, %s: %s", name, code)
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM register.category WHERE archived_at IS NULL"); got != "7" {
		t.Errorf("default categories: %s", got)
	}

	// Treatment (AC-15, AC-17).
	action := func(kv ...any) map[string]any {
		return with(map[string]any{"id": "11111111-1111-4111-8111-111111111111", "title": "Deploy phishing-resistant MFA", "owner": erin,
			"due": "2026-12-01", "state": "planned"}, kv...)
	}
	plan := map[string]any{"schema_version": 1, "decision": "mitigate", "rationale": "MFA cuts the frequency of account takeover.",
		"targets": []any{map[string]any{"scenario_id": s1, "control_set": "Proposed"}}, "actions": []any{action()}}
	for name, c := range map[string]struct {
		doc  map[string]any
		want string
	}{
		"a target not linked":      {with(plan, "targets", []any{map[string]any{"scenario_id": s3, "control_set": "Proposed"}}), "/targets/0/scenario_id: is not a scenario of the risk"},
		"an unknown target set":    {with(plan, "targets", []any{map[string]any{"scenario_id": s1, "control_set": "Elsewhere"}}), "/targets/0/control_set"},
		"targets without mitigate": {with(plan, "decision", "transfer"), "/targets: are given only when the decision is mitigate"},
		"no rationale":             {with(plan, "rationale", nil), "/rationale: is required"},
		"an unknown decision":      {with(plan, "decision", "ignore"), "/decision"},
		"a cancelled action":       {with(plan, "actions", []any{action("state", "cancelled")}), "/actions/0/cancel_reason: is required"},
		"an impossible date":       {with(plan, "actions", []any{action("due", "2026-02-30")}), "/actions/0/due: is a date"},
		"an action twice":          {with(plan, "actions", []any{action(), action()}), "/actions/1/id: is used twice"},
		"an owner who is no user":  {with(plan, "actions", []any{action("owner", "00000000-0000-4000-8000-000000000000")}), "/actions/0/owner: is a user"},
	} {
		if err := treatmentVersion(t, ra, "erin", risk, 1, c.doc); !strings.HasPrefix(pgCode(err), "PF026 ") || !strings.Contains(pgCode(err), c.want) {
			t.Errorf("treatment, %s: %v", name, pgCode(err))
		}
	}
	if err := treatmentVersion(t, ra, "erin", risk, 1, plan); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT bu_id || ':' || decision || ':' || current_version FROM register.treatment WHERE risk_id = '" + risk + "'"); got != ra.bu["A1"]+":mitigate:1" {
		t.Errorf("treatment head: %s", got)
	}
	done := with(plan, "actions", []any{action("state", "done")})
	if err := treatmentVersion(t, ra, "erin", risk, 2, done); err != nil {
		t.Fatal(err)
	}
	if code := ra.adminState("UPDATE register.treatment_version SET change_note = 'x' WHERE risk_id = '" + risk + "'"); code != "PF025" {
		t.Errorf("a treatment version updated: %s", code)
	}
	if err := riskVersion(t, ra, "erin", risk, 7, with(closed, "state", "closed")); err != nil {
		t.Fatal(err)
	}
	if err := treatmentVersion(t, ra, "erin", risk, 3, plan); !strings.Contains(pgCode(err), "the risk is closed") {
		t.Errorf("treatment of a closed risk: %v", pgCode(err))
	}
}

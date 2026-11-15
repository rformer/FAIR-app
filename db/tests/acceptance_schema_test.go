package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// F-008 T-02 (F-008-AC-16, AC-17; design §3.1, §5): the acceptance schema:
// only acceptance_definer writes it; the history is append-only for every
// role; one open acceptance per risk, a renewal beside it.
func TestAcceptanceSchema(t *testing.T) {
	f := strideF007Fixture(t) // owen's risk at A1
	ra := f.ra
	head := func(state, renews string) string {
		t.Helper()
		r := "NULL"
		if renews != "" {
			r = "'" + renews + "'"
		}
		return `INSERT INTO acceptance.acceptance (bu_id, risk_id, renews, state, tier, tier_bu_id, approvals_needed, mean, expires_on, requested_by)
			VALUES ('` + ra.bu["A1"] + `', '` + f.risk + `', ` + r + `, '` + state + `', 1, '` + ra.bu["A1"] + `', 1, 1000, current_date + 30, '` + f.owen + `') RETURNING id`
	}
	// The definer writes (its functions come with T-04).
	first := ra.adminQuery("SET ROLE acceptance_definer; " + head("pending", ""))
	if first == "" {
		t.Fatal("no acceptance")
	}
	ra.admin(ra.db, "SET ROLE acceptance_definer; INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind, actor, reason) VALUES ('"+first+"', 1, '"+ra.bu["A1"]+"', 'requested', '"+f.owen+"', 'within appetite')")

	// The application role writes nothing, whoever asks.
	for _, sql := range []string{
		head("pending", ""),
		"INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind) VALUES ('" + first + "', 2, '" + ra.bu["A1"] + "', 'approved')",
		"UPDATE acceptance.acceptance SET state = 'active'",
		"UPDATE acceptance.step SET reason = 'rewritten'",
		"DELETE FROM acceptance.step",
		"DELETE FROM acceptance.acceptance",
	} {
		err := ra.tx("owen", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		})
		if code := pgCode(err); !strings.HasPrefix(code, "42501 ") && !strings.HasPrefix(code, "PF027 ") {
			t.Errorf("owen: %s: %v", sql[:min(len(sql), 60)], code)
		}
	}
	// The history is append-only for every role, the definer included (but
	// for moving a step's BU); heads change only through the definer.
	for name, c := range map[string]struct{ role, sql string }{
		"superuser rewrites a step":   {"", "UPDATE acceptance.step SET reason = 'rewritten'"},
		"superuser deletes a step":    {"", "DELETE FROM acceptance.step"},
		"the definer rewrites a step": {"acceptance_definer", "UPDATE acceptance.step SET reason = 'rewritten'"},
		"the definer deletes a step":  {"acceptance_definer", "DELETE FROM acceptance.step"},
		"superuser changes a head":    {"", "UPDATE acceptance.acceptance SET state = 'active'"},
		"the definer deletes a head":  {"acceptance_definer", "DELETE FROM acceptance.acceptance"},
		"superuser truncates steps":   {"", "TRUNCATE acceptance.step"},
		"superuser truncates heads":   {"", "TRUNCATE acceptance.acceptance CASCADE"},
	} {
		sql := c.sql
		if c.role != "" {
			sql = "SET ROLE " + c.role + "; " + sql
		}
		// PF027 from the triggers; the definer has no DELETE privilege at all (42501).
		if got := ra.adminState(sql); got != "PF027" && !(got == "42501" && strings.Contains(name, "definer deletes")) {
			t.Errorf("%s: %s", name, got)
		}
	}
	ra.admin(ra.db, "SET ROLE acceptance_definer; UPDATE acceptance.step SET bu_id = '"+ra.bu["A"]+"' WHERE acceptance_id = '"+first+"'")
	if got := ra.adminQuery("SELECT bu_id FROM acceptance.step WHERE acceptance_id = '" + first + "'"); got != ra.bu["A"] {
		t.Errorf("the definer moves a step: %s", got)
	}

	// One open acceptance per risk; a renewal beside an active one.
	if got := ra.adminState("SET ROLE acceptance_definer; " + head("pending", "")); got != "23505" {
		t.Errorf("a second pending request: %s", got)
	}
	ra.admin(ra.db, "SET ROLE acceptance_definer; UPDATE acceptance.acceptance SET state = 'active' WHERE id = '"+first+"'")
	if got := ra.adminState("SET ROLE acceptance_definer; " + head("pending", "")); got != "23505" {
		t.Errorf("a fresh request beside an active acceptance: %s", got)
	}
	renewal := ra.adminQuery("SET ROLE acceptance_definer; " + head("pending", first))
	if renewal == "" {
		t.Fatal("no renewal")
	}
	if got := ra.adminState("SET ROLE acceptance_definer; " + head("pending", first)); got != "23505" {
		t.Errorf("a second pending renewal: %s", got)
	}
	// The renewal replaces it: the old one ends first, in the same transaction.
	ra.admin(ra.db, `SET ROLE acceptance_definer; BEGIN;
		UPDATE acceptance.acceptance SET state = 'ended', end_reason = 'replaced', ended_at = now() WHERE id = '`+first+`';
		UPDATE acceptance.acceptance SET state = 'active' WHERE id = '`+renewal+`'; COMMIT`)
	if got := ra.adminQuery("SELECT string_agg(state || coalesce('/' || end_reason, ''), ',' ORDER BY seq) FROM acceptance.acceptance"); got != "ended/replaced,active" {
		t.Errorf("after the renewal: %s", got)
	}
	// Reads: under RLS, acceptance.view at the BU (the analyst holds it at
	// A; mallory at B does not see A).
	for user, want := range map[string]string{"analyst": "2", "mallory": "0", "chief": "2"} {
		if got := f.count(t, user, "acceptance.acceptance"); got != want {
			t.Errorf("%s reads %s acceptances, want %s", user, got, want)
		}
	}
}

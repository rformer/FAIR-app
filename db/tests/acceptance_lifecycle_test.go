package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// hintOf is a database error's hint.
func hintOf(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Hint
	}
	return ""
}

// F-008 T-04 (F-008-AC-01 to AC-07, AC-11, AC-15, AC-18; design §3.2, §3.4):
// requests and decisions through the definer functions.

type acceptanceEnv struct {
	*f007Env
}

// acceptanceFixture: the F-007 STRIDE fixture (owen a Risk Owner at A,
// chief at the root, analyst a Risk Analyst at A, mallory at B), with
// approvers: appA1 at A1, appA at A, root1 and root2 at the root (the
// Approver role). The ramp engine gives every Current set a mean of 4.5.
func acceptanceFixture(t *testing.T) *acceptanceEnv {
	t.Helper()
	f := strideF007Fixture(t)
	for user, bu := range map[string]string{"appA1": "A1", "appA": "A", "root1": "ENTERPRISE", "root2": "ENTERPRISE"} {
		f.ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + user + "@example.test', '" + user + "')")
		f.ra.mustOwner(grant("platform", "user:"+user, "Approver", bu))
	}
	f.ra.drain()
	return &acceptanceEnv{f}
}

// accepted makes a risk at A1 of a new scenario pinned to a new run, owned
// by owner, its treatment decision accept.
func (a *acceptanceEnv) accepted(t *testing.T, name, owner string) string {
	t.Helper()
	s := scenarioAt(t, a.ra, "analyst", a.ra.bu["A1"], name)
	r := runWith(t, a.ae, "analyst", s, 1, 2000, "7")
	d := a.doc(name, s, r)
	d["owner"] = a.ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + owner + "@example.test'")
	got := a.rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": a.ra.bu["A1"], "change_note": "x", "document": d})
	if got.code != 201 {
		t.Fatalf("risk %s: %d %s", name, got.code, got.raw)
	}
	id := got.body["id"].(string)
	a.accept(t, id)
	return id
}

func (a *acceptanceEnv) accept(t *testing.T, risk string) {
	t.Helper()
	if got := a.rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+risk+"/treatment", map[string]any{"expected_version": 0, "change_note": "accept",
		"document": map[string]any{"schema_version": 1, "decision": "accept", "rationale": "Within appetite."}}); got.code != 200 {
		t.Fatalf("treatment: %d %s", got.code, got.raw)
	}
}

// sql runs a statement as user, answering its single value and SQLSTATE.
func (a *acceptanceEnv) sql(t *testing.T, user, q string, args ...any) (string, string) {
	t.Helper()
	var out *string
	err := a.ra.tx(user, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), q, args...).Scan(&out)
	})
	if err != nil {
		code, _, _ := strings.Cut(pgCode(err), " ")
		return "", code + " " + hintOf(err)
	}
	if out == nil {
		return "", ""
	}
	return *out, ""
}

func (a *acceptanceEnv) request(t *testing.T, user, risk, justification string, expires time.Time, renews string) (string, string) {
	t.Helper()
	var rn any
	if renews != "" {
		rn = renews
	}
	return a.sql(t, user, "SELECT acceptance.request($1, $2, 'Monitor monthly', $3, $4)::text", risk, justification, expires.Format(time.DateOnly), rn)
}

func (a *acceptanceEnv) decide(t *testing.T, user, id, decision string) (string, string) {
	t.Helper()
	return a.sql(t, user, "SELECT acceptance.decide($1, $2, 'Reviewed with the committee', NULL)", id, decision)
}

func days(n int) time.Time { return time.Now().UTC().AddDate(0, 0, n) }

func TestAcceptanceLifecycle(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	state := func(id string) string {
		return ra.adminQuery("SELECT state || coalesce('/' || end_reason, '') || '|' || tier || '|' || (SELECT code FROM iam.bu WHERE id = tier_bu_id) || '|' || approvals_needed FROM acceptance.acceptance WHERE id = '" + id + "'")
	}

	// Refusals (AC-02), each with its reason.
	if _, code := a.request(t, "owen", a.risk, "Within appetite", days(90), ""); code != "PF027 not_accept" {
		t.Errorf("not accept: %s", code)
	}
	a.accept(t, a.risk)
	unquantified := a.create(t, "owen", ra.bu["A1"], "Claims compliance", "", "")
	a.accept(t, unquantified)
	for name, c := range map[string]struct {
		user, risk, just string
		expires          time.Time
		want             string
	}{
		"an unquantified risk": {"owen", unquantified, "x", days(90), "PF027 exposure_not_current"},
		"an expiry today":      {"owen", a.risk, "x", days(0), "PF027 invalid_expiry"},
		"beyond the maximum":   {"owen", a.risk, "x", days(366), "PF027 invalid_expiry"},
		"no justification":     {"owen", a.risk, " ", days(90), "PF027 invalid_request"},
		"a viewer":             {"analyst", a.risk, "x", days(90), "42501 forbidden"},
		"another BU's reader":  {"mallory", a.risk, "x", days(90), "P0002 "},
	} {
		if _, code := a.request(t, c.user, c.risk, c.just, c.expires, ""); code != c.want {
			t.Errorf("%s: %q, want %q", name, code, c.want)
		}
	}

	// A request: tier 1 (mean 4.5), approved at A1, one approval; its evidence.
	id, code := a.request(t, "owen", a.risk, "Within appetite", days(200), "")
	if code != "" {
		t.Fatalf("request: %s", code)
	}
	if got := state(id); got != "pending|1|A1|1" {
		t.Errorf("the request: %s", got)
	}
	if got := ra.adminQuery("SELECT (data #>> '{exposure,mean}') || '|' || (data #>> '{tier,n}') || '|' || jsonb_array_length(data -> 'pins') || '|' || (data ->> 'justification') FROM acceptance.step WHERE acceptance_id = '" + id + "' AND kind = 'requested'"); got != "4.5|1|1|Within appetite" {
		t.Errorf("the evidence: %s", got)
	}
	if _, code := a.request(t, "owen", a.risk, "again", days(90), ""); code != "PF027 pending_exists" {
		t.Errorf("a second request: %s", code)
	}

	// Who decides (AC-05): approve at the tier's BU or above, not the
	// requester or the owner.
	if _, code := a.decide(t, "analyst", id, "approve"); code != "42501 not_your_tier" {
		t.Errorf("a viewer: %s", code)
	}
	if _, code := a.decide(t, "mallory", id, "approve"); code != "P0002 " {
		t.Errorf("mallory: %s", code)
	}
	if _, code := a.decide(t, "owen", id, "approve"); code != "42501 not_your_tier" {
		t.Errorf("owen: %s", code)
	}
	// appA holds acceptance.approve at A, above A1: allowed; but appA1 approves first, shortening the expiry.
	if got, code := a.sql(t, "appA1", "SELECT acceptance.decide($1, 'approve', 'Fine', $2)", id, days(100).Format(time.DateOnly)); code != "" || got != "active" {
		t.Fatalf("approve: %s %s", got, code)
	}
	if got := ra.adminQuery("SELECT state || '|' || expires_on || '|' || (SELECT code FROM iam.bu WHERE id = approved_bu_id) FROM acceptance.acceptance WHERE id = '" + id + "'"); got != "active|"+days(100).Format(time.DateOnly)+"|A1" {
		t.Errorf("active: %s", got)
	}
	if _, code := a.decide(t, "appA", id, "approve"); code != "PF027 not_pending" {
		t.Errorf("deciding an active acceptance: %s", code)
	}
	if _, code := a.request(t, "owen", a.risk, "again", days(90), ""); code != "PF027 already_accepted" {
		t.Errorf("a fresh request of an accepted risk: %s", code)
	}

	// Separation of duties: an approver who owns the risk.
	own := a.accepted(t, "Claims fraud by appA1", "appA1")
	oid, code := a.request(t, "owen", own, "Within appetite", days(90), "")
	if code != "" {
		t.Fatalf("request: %s", code)
	}
	if _, code := a.decide(t, "appA1", oid, "approve"); code != "42501 separation_of_duties" {
		t.Errorf("the owner approves: %s", code)
	}
	// Rejection ends it (AC-06).
	if got, code := a.decide(t, "root1", oid, "reject"); got != "ended" || code != "" {
		t.Errorf("reject: %s %s", got, code)
	}
	if got := state(oid); !strings.HasPrefix(got, "ended/rejected") {
		t.Errorf("rejected: %s", got)
	}

	// Tier 2: approvers one level up (A); tier 3: two approvers at the root.
	setInstance(ra.env, "acceptance.tier1_max", "1")
	t2 := a.accepted(t, "Claims outage", "owen")
	t2id, _ := a.request(t, "owen", t2, "Within appetite", days(90), "")
	if got := state(t2id); got != "pending|2|A|1" {
		t.Errorf("tier 2: %s", got)
	}
	if _, code := a.decide(t, "appA1", t2id, "approve"); code != "42501 not_your_tier" {
		t.Errorf("tier 2 by A1's approver: %s", code)
	}
	if got, _ := a.decide(t, "appA", t2id, "approve"); got != "active" {
		t.Errorf("tier 2 by A's approver: %s", got)
	}
	setInstance(ra.env, "acceptance.tier2_max", "2")
	t3 := a.accepted(t, "Claims data loss", "owen")
	t3id, _ := a.request(t, "owen", t3, "Within appetite", days(90), "")
	if got := state(t3id); got != "pending|3|ENTERPRISE|2" {
		t.Errorf("tier 3: %s", got)
	}
	if _, code := a.decide(t, "appA", t3id, "approve"); code != "42501 not_your_tier" {
		t.Errorf("tier 3 by A's approver: %s", code)
	}
	if got, _ := a.decide(t, "root1", t3id, "approve"); got != "pending" {
		t.Errorf("one of two: %s", got)
	}
	if _, code := a.decide(t, "root1", t3id, "approve"); code != "PF027 already_decided" {
		t.Errorf("the same approver twice: %s", code)
	}
	if got, _ := a.decide(t, "root2", t3id, "approve"); got != "active" {
		t.Errorf("two of two: %s", got)
	}
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	setInstance(ra.env, "acceptance.tier2_max", "1000000")

	// Renewal (AC-11): pending beside the active one; approved, it replaces
	// it without a gap.
	ren, code := a.request(t, "owen", a.risk, "Still within appetite", days(300), id)
	if code != "" {
		t.Fatalf("renewal: %s", code)
	}
	if got := ra.adminQuery("SELECT string_agg(state, ',' ORDER BY seq) FROM acceptance.acceptance WHERE risk_id = '" + a.risk + "'"); got != "active,pending" {
		t.Errorf("beside: %s", got)
	}
	if _, code := a.request(t, "owen", a.risk, "again", days(300), id); code != "PF027 pending_exists" {
		t.Errorf("a second renewal: %s", code)
	}
	if got, _ := a.decide(t, "appA1", ren, "approve"); got != "active" {
		t.Fatalf("renewal approved: %s", got)
	}
	if got := ra.adminQuery("SELECT (o.state || '/' || o.end_reason) || '|' || n.state || '|' || (o.ended_at = n.activated_at) FROM acceptance.acceptance o, acceptance.acceptance n WHERE o.id = '" + id + "' AND n.id = '" + ren + "'"); got != "ended/replaced|active|true" {
		t.Errorf("replaced: %s", got)
	}

	// Withdraw (AC-03) and revoke (AC-15).
	wd := a.accepted(t, "Claims vendor", "owen")
	wid, _ := a.request(t, "owen", wd, "Within appetite", days(90), "")
	if _, code := a.sql(t, "appA1", "SELECT acceptance.withdraw($1, 'not mine')::text", wid); code != "42501 forbidden" {
		t.Errorf("another withdraws: %s", code)
	}
	if _, code := a.sql(t, "owen", "SELECT acceptance.withdraw($1, 'risk reassessed')::text", wid); code != "" {
		t.Errorf("withdraw: %s", code)
	}
	if got := state(wid); !strings.HasPrefix(got, "ended/withdrawn") {
		t.Errorf("withdrawn: %s", got)
	}
	if _, code := a.sql(t, "owen", "SELECT acceptance.revoke($1, 'x')::text", ren); code != "42501 not_your_tier" {
		t.Errorf("owen revokes: %s", code)
	}
	if _, code := a.sql(t, "appA1", "SELECT acceptance.revoke($1, 'conditions not met')::text", ren); code != "" {
		t.Errorf("revoke: %s", code)
	}
	if got := state(ren); !strings.HasPrefix(got, "ended/revoked") {
		t.Errorf("revoked: %s", got)
	}

	// A risk moved: its acceptance follows, the pending tier's BU resolved
	// from the new BU; closed: its acceptance ends.
	mv := a.accepted(t, "Claims printing", "owen")
	setInstance(ra.env, "acceptance.tier1_max", "1")
	mid, _ := a.request(t, "owen", mv, "Within appetite", days(90), "")
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	if got := state(mid); got != "pending|2|A|1" {
		t.Fatalf("before the move: %s", got)
	}
	if got := a.rg.call(t, "POST", "chief", "/api/v1/register/risks/"+mv+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "head office"}); got.code != 200 {
		t.Fatalf("move: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (SELECT code FROM iam.bu WHERE id = bu_id) || '|' || (SELECT code FROM iam.bu WHERE id = tier_bu_id) || '|' || (SELECT string_agg(DISTINCT s.bu_id::text, ',') FROM acceptance.step s WHERE s.acceptance_id = '" + mid + "') FROM acceptance.acceptance WHERE id = '" + mid + "'"); got != "A|ENTERPRISE|"+ra.bu["A"] {
		t.Errorf("moved: %s", got)
	}
	if got := a.rg.call(t, "POST", "chief", "/api/v1/register/risks/"+mv+"/close", map[string]any{"reason": "retired"}); got.code != 200 {
		t.Fatalf("close: %d %s", got.code, got.raw)
	}
	if got := state(mid); !strings.HasPrefix(got, "ended/risk_closed") {
		t.Errorf("closed: %s", got)
	}
	if _, code := a.request(t, "chief", mv, "x", days(90), ""); code != "PF027 risk_closed" {
		t.Errorf("a closed risk: %s", code)
	}

	// Every step audited (AC-18), decisions at high severity.
	got := ra.adminQuery(`SELECT string_agg(body ->> 'type' || ':' || (body ->> 'severity') || ':' || n, ',' ORDER BY body ->> 'type') FROM (
		SELECT body, count(*) OVER (PARTITION BY body ->> 'type') AS n, row_number() OVER (PARTITION BY body ->> 'type') AS k FROM audit.intake
		WHERE body ->> 'type' LIKE 'acceptance.%') x WHERE k = 1`)
	for _, want := range []string{"acceptance.activated:low:4", "acceptance.approved:high:5", "acceptance.ended:low:1", "acceptance.rejected:high:1",
		"acceptance.replaced:low:1", "acceptance.requested:low:7", "acceptance.revoked:high:1", "acceptance.withdrawn:low:1"} {
		if !strings.Contains(got, want) {
			t.Errorf("events %s: no %s", got, want)
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' LIKE 'acceptance.%' AND (body ->> 'bu_id' IS NULL OR body ->> 'actor' IS NULL)"); got != "0" {
		t.Errorf("%s events without BU or actor", got)
	}
}

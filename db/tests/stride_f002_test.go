package tests

import (
	"fmt"
	"strings"
	"testing"

	auditsvc "github.com/rformer/fair-app/internal/audit"
)

// F-002 T-21: the STRIDE suite for F-002 (design §8), written as attacks.
// TestSTRIDECatalog maps every §8 threat to these tests and to the earlier
// ones that attack the same mitigation.

// Spoofing: a service claims to be another producer. The body cannot name
// one (submit refuses fields outside the envelope); the trail records the
// database role that submitted, through intake and the sequencer.
func TestSTRIDEF002ProducerSpoofing(t *testing.T) {
	e := setup(t)
	seq := auditsvc.Sequencer{DB: e.auditPool()}
	for _, field := range []string{`"producer": "app_posture"`, `"received_at": "2020-01-01T00:00:00Z"`} {
		out, err := e.as("app_rw", `SELECT audit.submit('{"type": "db.migrated", "severity": "info", "actor": "x", `+field+`}')`)
		if err == nil || !strings.Contains(out, "unknown field") {
			t.Fatalf("a body naming %s: %s %v", field, out, err)
		}
	}
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		submitAs(t, e, role, map[string]any{"id": "from-" + role, "type": "db.migrated", "severity": "info", "actor": "x"})
	}
	drainTrail(t, seq)
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		got := e.adminQuery(fmt.Sprintf(`SELECT producer || '/' || (convert_from(body, 'UTF8')::jsonb ->> 'producer') FROM audit.record WHERE event_id = 'from-%s'`, role))
		if got != role+"/"+role {
			t.Errorf("%s's event recorded as produced by %s", role, got)
		}
	}
	// No application role can write intake directly to choose its producer.
	for _, role := range []string{"app_rw", "app_posture", "app_gateway", "app_audit"} {
		e.mustFail(role, `INSERT INTO audit.intake (event_id, producer, body) VALUES ('forged', 'app_posture', '{}')`, "permission denied")
	}
}

// Information disclosure: display names come only with records the caller
// sees. An auditor at A never learns the name of someone who appears only
// in records of other BUs, and the names function is closed to the API.
func TestSTRIDEF002NameLeak(t *testing.T) {
	ae := auditAPIFixture(t)
	e := ae.e
	r := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'R'")
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('secret@example.test', 'Secret Agent')`)
	secret := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'secret@example.test'")
	submitAs(t, e, "app_rw", map[string]any{"id": "secret1", "type": "setting.change_requested", "severity": "high", "actor": secret, "bu_id": r, "target": "test:r"})
	drainTrail(t, ae.seq)

	for _, path := range []string{"/records?limit=200", "/history?actor=" + secret, "/history?target=test:r", "/requests/req-r"} {
		got := ae.get(t, "aaud", path)
		recs, _ := got.body["records"].([]any)
		leaked := strings.Contains(got.raw, "Secret Agent")
		for _, x := range recs {
			leaked = leaked || x.(map[string]any)["actor"] == secret
		}
		if leaked {
			t.Errorf("A's auditor learned the restricted user through %s: %s", path, got.raw)
		}
	}
	// The root auditor does not see R either (restricted); R's auditor does.
	if got := ae.get(t, "rootaud", "/records?limit=200"); strings.Contains(got.raw, "Secret Agent") {
		t.Error("the root auditor saw a restricted BU's user")
	}
	if got := ae.get(t, "raud", "/history?actor="+secret); !strings.Contains(got.raw, "Secret Agent") {
		t.Errorf("R's auditor lacks the name: %s", got.raw)
	}
	for _, role := range []string{"app_audit", "app_rw", "app_posture"} {
		e.mustFail(role, "SELECT * FROM iam.user_display_names(ARRAY['"+secret+"'::uuid])", "permission denied")
	}
}

// Denial of service: the audit service is down. Producers keep working
// (intake absorbs their events in their own transactions); when the
// sequencer is back, every event is recorded, in order, none lost.
func TestSTRIDEF002ServiceDown(t *testing.T) {
	e := setup(t)
	const n = 200
	for i := 0; i < n; i++ {
		submitAs(t, e, []string{"app_rw", "app_posture", "app_gateway"}[i%3], map[string]any{
			"id": fmt.Sprintf("down-%03d", i), "type": "db.migrated", "severity": "info", "actor": "x"})
	}
	if got := e.adminQuery("SELECT count(*) FROM audit.intake"); got != fmt.Sprint(n) {
		t.Fatalf("intake holds %s of %d while the service is down", got, n)
	}
	if got := e.adminQuery("SELECT count(*) FROM audit.record"); got != "0" {
		t.Fatalf("%s records without a sequencer", got)
	}
	if got := drainTrail(t, auditsvc.Sequencer{DB: e.auditPool(), Batch: 37}); got != n {
		t.Fatalf("sequenced %d of %d", got, n)
	}
	if got := e.adminQuery("SELECT count(*) || '/' || min(seq) || '/' || max(seq) FROM audit.record WHERE event_id LIKE 'down-%'"); got != fmt.Sprintf("%d/1/%d", n, n) {
		t.Fatalf("records after recovery: %s", got)
	}
	// In submission order.
	if got := e.adminQuery("SELECT count(*) FROM (SELECT event_id, seq, lag(event_id) OVER (ORDER BY seq) AS prev FROM audit.record WHERE event_id LIKE 'down-%') x WHERE prev > event_id"); got != "0" {
		t.Fatalf("%s records out of submission order", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM audit.intake"); got != "0" {
		t.Fatalf("intake left %s", got)
	}
}

// Elevation of privilege: audit.hold keeps records from destruction. It is
// privileged, only Platform Admin holds it among the built-in roles (not
// Auditor), and it is required at the root.
func TestSTRIDEF002HoldPrivilege(t *testing.T) {
	e := setup(t)
	if got := e.adminQuery("SELECT action || '/' || privileged FROM iam.permission WHERE key = 'audit.hold'"); got != "admin/true" {
		t.Fatalf("audit.hold is %s", got)
	}
	got := e.adminQuery(`SELECT string_agg(r.name, ',' ORDER BY r.name) FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
		WHERE r.builtin AND 'audit.hold' = ANY (v.permissions)`)
	if got != "Platform Admin" {
		t.Fatalf("built-in roles with audit.hold: %s", got)
	}
	// Placing a hold needs it at the root, whatever else the caller holds.
	e.mustFail("app_audit", `SELECT audit.hold_place('{}', 'x')`, "valid signed database context")
	e.mustFail("app_rw", `SELECT audit.hold_place('{}', 'x')`, "permission denied")
	for _, fn := range []string{"audit.hold_mark_online('00000000-0000-0000-0000-000000000000')", "audit.legal_hold_set(1, false)"} {
		e.mustFail("app_rw", "SELECT "+fn, "permission denied")
	}
}

package tests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-13 (F-002-AC-35; design §3, §5): approval evidence. Events
// recorded in the transaction that consumed an approval carry approval_id
// (stamped by audit.submit), and GET /approvals/{id} shows the request, both
// parties, the decision and the applied change in one view.

// evidenceTypes lists the types of an evidence response's parts, in order:
// request, decision, applied, then the changes.
func evidenceTypes(r apiResp) string {
	var out []string
	for _, k := range []string{"request", "decision", "applied"} {
		if m, ok := r.body[k].(map[string]any); ok {
			out = append(out, k+"="+fmt.Sprint(m["type"]))
		}
	}
	ch, _ := r.body["changes"].([]any)
	for _, x := range ch {
		out = append(out, fmt.Sprint(x.(map[string]any)["type"]))
	}
	return strings.Join(out, ",")
}

func party(r apiResp, k string) string {
	m, _ := r.body[k].(map[string]any)
	return fmt.Sprint(m["id"]) + "|" + fmt.Sprint(m["name"])
}

func TestAuditApprovalEvidence(t *testing.T) {
	ae := auditAPIFixture(t)
	e := ae.e
	e.addBU("A1", "A")
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'A1'")
	a, a1 := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'"), e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A1'")
	admin, admin2 := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'"), e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin2@example.test'")

	// F-001: un-restricting A1 is requested by admin, approved by admin2 and
	// applied by admin. Two more events share the applying transaction: one
	// without approval_id (stamped) and one naming another approval (kept).
	approval := e.mustAsUser("app_rw", "admin", "SELECT iam.bu_set_restricted('"+a1+"', false, 'deal closed')")
	e.mustAsUser("app_rw", "admin2", "SELECT iam.decide_approval('"+approval+"', true, 'confirmed with legal')")
	other := "0d7e2a9c-1b7f-4c1e-9d55-9a3c55b7f001"
	ev := func(id string, attrs map[string]any) string {
		m := map[string]any{"id": id, "type": "setting.change_requested", "severity": "high", "actor": admin, "target": "test:apply", "bu_id": a}
		if attrs != nil {
			m["attributes"] = attrs
		}
		b, _ := json.Marshal(m)
		return "SELECT audit.submit('" + string(b) + "')"
	}
	e.mustAsUser("app_rw", "admin", "SELECT iam.bu_apply_approval('"+approval+"'); "+ev("same-tx", nil)+"; "+ev("explicit", map[string]any{"approval_id": other}))
	// After the transaction, and with the marker forged, nothing is stamped:
	// the approval was consumed in another transaction; a pending one was
	// never consumed; a malformed marker is ignored.
	pending := e.mustAsUser("app_rw", "admin", "SELECT iam.bu_set_rollup('"+a1+"', 'full', 'board reporting')")
	for i, marker := range []string{approval, pending, "not-a-uuid"} {
		e.mustAsUser("app_rw", "admin", fmt.Sprintf("SELECT set_config('audit.approval_id', '%s', true); %s", marker, ev(fmt.Sprintf("forged-%d", i), nil)))
	}
	e.mustAsUser("app_rw", "admin", ev("later", nil))
	e.drain() // A1 is unrestricted: the auditors' scopes follow
	drainTrail(t, ae.seq)

	stamped := e.adminQuery(`SELECT string_agg(event_id || '=' || coalesce(approval_id, '-'), ',' ORDER BY event_id) FROM audit.record
		WHERE event_id IN ('same-tx', 'explicit', 'forged-0', 'forged-1', 'forged-2', 'later')`)
	if want := "explicit=" + other + ",forged-0=-,forged-1=-,forged-2=-,later=-,same-tx=" + approval; stamped != want {
		t.Fatalf("approval_id on the records:\n%s\nwant\n%s", stamped, want)
	}
	if got := e.adminQuery("SELECT approval_id FROM audit.record WHERE type = 'bu.unrestricted'"); got != approval {
		t.Fatalf("the applied change's approval_id %q, want %s", got, approval)
	}
	// Approval events are filed under the request's BU (the parent, A).
	if got := e.adminQuery("SELECT string_agg(DISTINCT bu_id::text, ',') FROM audit.record WHERE target = 'approval:" + approval + "'"); got != a {
		t.Fatalf("approval events filed under %s, want A (%s)", got, a)
	}

	// One view: request, both parties, decision, use, and the change.
	for _, user := range []string{"rootaud", "aaud"} {
		r := ae.get(t, user, "/approvals/"+approval)
		if r.code != 200 {
			t.Fatalf("%s: %d %s", user, r.code, r.raw)
		}
		if got, want := evidenceTypes(r), "request=approval.requested,decision=approval.approved,applied=approval.consumed,bu.unrestricted,setting.change_requested"; got != want {
			t.Errorf("%s evidence %s, want %s", user, got, want)
		}
		if r.body["kind"] != "bu.unrestrict" || r.body["target_ref"] != "bu:"+a1 || r.body["status"] != "approved" {
			t.Errorf("%s summary %v %v %v", user, r.body["kind"], r.body["target_ref"], r.body["status"])
		}
		if got := party(r, "requested_by"); got != admin+"|Admin" {
			t.Errorf("%s requested_by %s", user, got)
		}
		if got := party(r, "decided_by"); got != admin2+"|Admin 2" {
			t.Errorf("%s decided_by %s", user, got)
		}
		req, _ := r.body["request"].(map[string]any)
		dec, _ := r.body["decision"].(map[string]any)
		if req["event"].(map[string]any)["reason"] != "deal closed" || dec["event"].(map[string]any)["reason"] != "confirmed with legal" {
			t.Errorf("%s reasons: %v / %v", user, req["event"], dec["event"])
		}
	}
	// Each record once: the use matches both its target and approval_id.
	if got := e.mustAsUser("app_audit", "rootaud", "SELECT count(*) || '/' || count(DISTINCT seq) FROM audit.approval_evidence('"+approval+"', NULL, 100)"); got != "5/5" {
		t.Errorf("approval_evidence rows/distinct %s, want 5/5", got)
	}
	// Paging, in order.
	p1 := ae.get(t, "rootaud", "/approvals/"+approval+"?limit=2")
	if evidenceTypes(p1) != "request=approval.requested,decision=approval.approved" || p1.body["next_after"] == nil {
		t.Fatalf("first page: %s %v", evidenceTypes(p1), p1.body["next_after"])
	}
	p2 := ae.get(t, "rootaud", fmt.Sprintf("/approvals/%s?after=%v", approval, p1.body["next_after"]))
	if got := evidenceTypes(p2); got != "applied=approval.consumed,bu.unrestricted,setting.change_requested" || p2.body["next_after"] != nil {
		t.Fatalf("second page: %s %v", got, p2.body["next_after"])
	}
	// The pending roll-up approval: its request alone.
	if r := ae.get(t, "aaud", "/approvals/"+pending); r.code != 200 || evidenceTypes(r) != "request=approval.requested" ||
		r.body["status"] != "pending" || r.body["decided_by"] != nil || r.body["decision"] != nil {
		t.Errorf("pending: %d %s", r.code, r.raw)
	}
	// Nothing visible, unknown, malformed or without audit.view: 404 alike.
	for _, c := range []struct{ user, id string }{
		{"raud", approval}, {"rootaud", "6a1f1c55-0000-4000-8000-000000000000"}, {"rootaud", "x"}, {"nobody", approval},
	} {
		if r := ae.get(t, c.user, "/approvals/"+c.id); r.code != 404 {
			t.Errorf("%s /approvals/%s: %d", c.user, c.id, r.code)
		}
	}
	if r := ae.get(t, "rootaud", "/approvals/"+strings.ToUpper(approval)); r.code != 200 || r.body["approval_id"] != approval {
		t.Errorf("upper-case id: %d %v", r.code, r.body["approval_id"])
	}
	if r := ae.get(t, "rootaud", "/approvals/"+approval+"?limit=0"); r.code != 400 {
		t.Errorf("limit 0: %d", r.code)
	}

	// Every read is recorded (AC-20), naming the approval but not as its
	// target, so the evidence never lists its own reads.
	drainTrail(t, ae.seq)
	if got := e.adminQuery(`SELECT count(*) FROM audit.record WHERE type = 'audit.searched' AND target = 'audit:approval:` + approval + `'
		AND convert_from(body, 'UTF8')::jsonb -> 'attributes' ->> 'view' = 'approval'`); got == "0" {
		t.Error("evidence reads are not recorded")
	}
	if got := e.adminQuery(`SELECT count(*) FROM audit.record WHERE type = 'audit.searched' AND target LIKE 'audit:approval:%'
		AND convert_from(body, 'UTF8')::jsonb -> 'attributes' ->> 'result_count' = '0'`); got == "0" {
		t.Error("404 evidence reads are not recorded")
	}
	if r := ae.get(t, "rootaud", "/approvals/"+approval); evidenceTypes(r) != "request=approval.requested,decision=approval.approved,applied=approval.consumed,bu.unrestricted,setting.change_requested" {
		t.Errorf("the evidence after reads: %s", evidenceTypes(r))
	}
}

// F-015: an out-of-bounds setting change. The request names its approval
// (setting.change_requested); applying it consumes the approval, and the
// exception it creates is stamped.
func TestAuditApprovalEvidencePosture(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ev.Audit = audit.WithTrail(audit.NewMemory(), audit.Trail{DB: e.posturePool()})
	approvedException(t, e, ev, 0)
	ae := newAuditAPI(t, e)
	drainTrail(t, ae.seq)
	approval := e.adminQuery("SELECT id FROM iam.approval_request WHERE kind = 'settings.out_of_bounds'")
	r := ae.get(t, "auditor", "/approvals/"+approval)
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	if got, want := evidenceTypes(r), "request=approval.requested,decision=approval.approved,applied=approval.consumed,setting.change_requested,setting.exception_created"; got != want {
		t.Errorf("evidence %s, want %s", got, want)
	}
	if r.body["kind"] != "settings.out_of_bounds" || party(r, "requested_by") != e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")+"|Admin" ||
		party(r, "decided_by") != e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin2@example.test'")+"|Admin 2" {
		t.Errorf("summary: %s", r.raw)
	}
	// Everything the applying transaction recorded names the approval.
	if got := e.adminQuery(`SELECT count(*) FROM audit.record c WHERE c.seq >= (SELECT seq FROM audit.record WHERE type = 'approval.consumed')
		AND c.type NOT LIKE 'audit.%' AND c.approval_id IS DISTINCT FROM '` + approval + `'`); got != "0" {
		t.Errorf("%s records after the approval was consumed do not name it", got)
	}
}

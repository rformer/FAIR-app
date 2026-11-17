package tests

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/authz"
)

var reportKey = authz.ContextKey{ID: "rk1", Secret: []byte("rk1-secret-0123456789abcdef-01234")}

// F-010 T-04 (ADR-007 amendment 6; F-010-AC-11, AC-20; design §3.3): a token
// signed with a report-purpose key is honoured only inside a read-only
// transaction, for the user whose report run is running with that token's
// nonce; then every RLS policy applies as for the user themselves.
func TestReportDelegatedContext(t *testing.T) {
	e := docFixture(t) // erin reads A and A1's documents
	e.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'), 'report')", reportKey.ID, hex.EncodeToString(reportKey.Secret)))
	if got := e.adminState(fmt.Sprintf("SET ROLE fair_owner; PERFORM authz.add_ctx_key('rk2', decode('%s', 'hex'), 'impersonate')", hex.EncodeToString(reportKey.Secret))); got != "23514" {
		t.Errorf("an unknown purpose: %s", got)
	}
	tok := e.mint("erin", reportKey)
	nonce := strings.Split(tok, ".")[5]
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	run := e.adminQuery(fmt.Sprintf(`INSERT INTO report.run (requested_by, bu_id, kind, formats) SELECT id, '%s', 'register', '{csv}' FROM iam.app_user
		WHERE email = 'erin@example.test' RETURNING id`, root))
	setRun := func(state, n string) {
		t.Helper()
		switch state {
		case "running":
			e.adminQuery("UPDATE report.run SET state = 'running', context_nonce = '" + n + "' WHERE id = '" + run + "' RETURNING id")
		case "queued":
			e.adminQuery("UPDATE report.run SET state = 'queued', context_nonce = NULL WHERE id = '" + run + "' RETURNING id")
		case "succeeded":
			e.adminQuery("UPDATE report.run SET state = 'succeeded', context_nonce = NULL, finished_at = now() WHERE id = '" + run + "' RETURNING id")
		}
	}
	readOnly := func(token string) string {
		t.Helper()
		out, err := e.as("app_rw", fmt.Sprintf("BEGIN READ ONLY; SET LOCAL authz.ctx = '%s'; %s; COMMIT;", token, visibleDocs))
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		return strings.TrimSpace(out)
	}

	// Queued: nothing, even read-only.
	if got := readOnly(tok); got != "-" {
		t.Errorf("before the run starts: %q", got)
	}
	setRun("running", nonce)
	if got := readOnly(tok); got != "a,a1" {
		t.Errorf("while the run runs, read-only: %q, want a,a1", got)
	}
	// Not in a read-write transaction, so never for a write.
	if out, err := e.asCtx(tok, visibleDocs); err != nil || out != "-" {
		t.Errorf("read-write: %q %v", out, err)
	}
	if out, err := e.asCtx(tok, "INSERT INTO iam.sample_doc (bu_id, title) VALUES ((SELECT id FROM iam.bu WHERE code = 'A1'), 'w')"); err == nil {
		t.Errorf("a write with a report token: %s", out)
	}
	// Another token of the same key (another nonce), or another user's: nothing.
	if got := readOnly(e.mint("erin", reportKey)); got != "-" {
		t.Errorf("another nonce: %q", got)
	}
	other := e.mint("mallory", reportKey)
	setRun("queued", "")
	setRun("running", strings.Split(other, ".")[5])
	if got := readOnly(other); got != "-" {
		t.Errorf("a token for someone without a run: %q", got)
	}
	setRun("queued", "")
	setRun("running", nonce)
	if got := readOnly(tok); got != "a,a1" {
		t.Errorf("running again: %q", got)
	}
	// Finished: nothing.
	setRun("succeeded", "")
	if got := readOnly(tok); got != "-" {
		t.Errorf("after the run: %q", got)
	}
	// Session tokens are unchanged, in either kind of transaction.
	session := e.mint("erin", ctxKey1)
	if out, err := e.asCtx(session, visibleDocs); err != nil || out != "a,a1" {
		t.Errorf("a session token: %q %v", out, err)
	}
	if got := readOnly(session); got != "a,a1" {
		t.Errorf("a session token, read-only: %q", got)
	}
	// The run table stays the definer's: app_rw cannot fake a running run.
	if got := e.adminState("SET ROLE app_rw; UPDATE report.run SET state = 'queued'"); got != "42501" {
		t.Errorf("app_rw updates runs: %s", got)
	}
}

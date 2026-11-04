package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/rformer/fair-app/pkg/audit"
)

// F-001 T-37 (AC-50), F-002 T-06: every security event the database tests
// cause is checked against the catalog and the event schema: the events in
// each test's audit trail intake when the test ends (checkAuditCatalog,
// registered by setup), and every event emitted to a Memory sink (strict
// mode). Since F-002 T-06 the database's own events reach the trail through
// audit.submit, which refuses uncatalogued ones itself; this checks that the
// two catalogs (Go and the database's) agree on everything recorded.

func init() { audit.SetStrict(true) }

func (e *env) checkAuditCatalog() {
	// The intake is readable only by audit_definer and superusers.
	cmd := exec.CommandContext(context.Background(), "psql", "--no-psqlrc", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", e.db, "-c",
		`SELECT coalesce(json_agg(json_build_object('producer', producer, 'body', body) ORDER BY id), '[]') FROM audit.intake`)
	cmd.Env = e.adminEnv
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return // no trail (a test of migrations themselves)
	}
	// F-002 T-06: every SQL producer's events land in the trail, none in
	// the outbox (the iam.event_outbox trigger).
	if n, err := e.owner("SELECT count(*) FROM iam.event_outbox WHERE topic = 'audit'"); err == nil && n != "0" {
		e.t.Errorf("%s audit rows in iam.event_outbox: the trail's trigger did not take them", n)
	}
	var rows []struct {
		Producer string          `json:"producer"`
		Body     json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rows); err != nil {
		e.t.Errorf("audit intake: %v", err)
		return
	}
	c, err := audit.DefaultCatalog()
	if err != nil {
		e.t.Fatal(err)
	}
	for _, r := range rows {
		var ev audit.Event
		dec := json.NewDecoder(bytes.NewReader(r.Body))
		dec.DisallowUnknownFields()
		err := dec.Decode(&ev)
		if err == nil {
			err = c.Validate(ev)
		}
		if err != nil {
			e.t.Errorf("audit event: %v\n%s", err, r.Body)
		}
		if !strings.HasPrefix(r.Producer, "app_") && r.Producer != "postgres" {
			e.t.Errorf("audit event from producer %q: %s", r.Producer, r.Body)
		}
	}
}

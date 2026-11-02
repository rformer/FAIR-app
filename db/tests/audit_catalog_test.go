package tests

import (
	"encoding/json"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// F-001 T-37 (AC-50): every security event the database tests cause is
// checked against the catalog and the event schema: the audit rows of each
// test's iam.event_outbox when the test ends (checkAuditCatalog, registered
// by setup), and every event emitted to a Memory sink (strict mode).

func init() { audit.SetStrict(true) }

func (e *env) checkAuditCatalog() {
	out, err := e.owner(`SELECT coalesce(json_agg(json_build_object('id', id, 'payload', payload) ORDER BY id), '[]') FROM iam.event_outbox WHERE topic = 'audit'`)
	if err != nil {
		return // no outbox (a test of migrations themselves)
	}
	var rows []struct {
		ID      int64           `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		e.t.Errorf("audit outbox: %v", err)
		return
	}
	c, err := audit.DefaultCatalog()
	if err != nil {
		e.t.Fatal(err)
	}
	for _, r := range rows {
		ev, err := audit.FromOutbox(r.ID, r.Payload)
		if err == nil {
			ev, err = audit.Normalize(ev, time.Now())
		}
		if err == nil {
			err = c.Validate(ev)
		}
		if err != nil {
			e.t.Errorf("audit event %d: %v\n%s", r.ID, err, r.Payload)
		}
	}
}

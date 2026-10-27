package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-26 (AC-37, AC-42): the drift finding lifecycle, and the events
// it sends to the audit trail and the SIEM, checked against the published
// schema in the form the sinks write them.
func TestDriftLifecycleAndEventSchema(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	var lines bytes.Buffer
	sink := audit.NewMemory()
	de.d.Audit = audit.Multi{audit.NewJSONLines(&lines), sink} // what an OTLP/SIEM collector receives

	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	opened := de.scan(t).Opened
	if len(opened) != 2 {
		t.Fatalf("opened %v", ids(opened))
	}
	dev := opened[slices.IndexFunc(opened, func(f posture.Finding) bool { return f.CheckID == posture.CheckDeviation })]

	// Acknowledge: drift.acknowledge and a reason are required, once.
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	e.mustOwner(grant("admin", "user:viewer", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	if _, err := de.d.Acknowledge(ctx, e.principal("viewer"), dev.ID, "seen"); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("without drift.acknowledge: %v", err)
	}
	admin := e.principal("admin")
	if _, err := de.d.Acknowledge(ctx, admin, dev.ID, "  "); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("without a reason: %v", err)
	}
	ack, err := de.d.Acknowledge(ctx, admin, dev.ID, "change window CHG-1234; DBA restoring")
	if err != nil || ack.Status != "acknowledged" || ack.AcknowledgedBy != admin.UserID {
		t.Fatalf("acknowledge: %+v %v", ack, err)
	}
	if _, err := de.d.Acknowledge(ctx, admin, dev.ID, "again"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second acknowledgement: %v", err)
	}

	// Acknowledged is not resolved: the next scans keep it, acknowledged.
	if res := de.scan(t); len(res.Opened)+len(res.Resolved) != 0 {
		t.Fatalf("scan after acknowledgement changed findings: %+v", res)
	}
	fs, err := posture.OpenFindings(ctx, e.posturePool())
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	for _, f := range fs {
		states = append(states, f.CheckID+":"+f.Status+":"+f.AcknowledgeReason)
	}
	slices.Sort(states)
	if !slices.Equal(states, []string{"row_mac_mismatch:open:", "unapproved_deviation:acknowledged:change window CHG-1234; DBA restoring"}) {
		t.Fatalf("findings %v", states)
	}

	// Only the check resolves it, once the value is set properly.
	if r, err := de.set.Set(ctx, admin, settings.Request{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"10m0s"`)}); err != nil || r.Outcome != settings.Applied {
		t.Fatalf("%+v %v", r, err)
	}
	if res := de.scan(t); len(res.Resolved) != 2 {
		t.Fatalf("resolved %v", ids(res.Resolved))
	}
	all, err := posture.Findings(ctx, e.posturePool(), time.Now().Add(-time.Hour))
	if err != nil || len(all) != 2 || all[0].Status != "resolved" || all[0].ResolvedAt == nil {
		t.Fatalf("resolved findings: %+v %v", all, err)
	}
	i := slices.IndexFunc(all, func(f posture.Finding) bool { return f.ID == dev.ID })
	if all[i].AcknowledgedBy != admin.UserID || all[i].AcknowledgedAt == nil {
		t.Fatalf("acknowledgement not kept on the resolved finding: %+v", all[i])
	}
	// The same drift again is a new finding, open.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	for _, f := range de.scan(t).Opened {
		if f.ID == dev.ID {
			t.Fatal("a resolved finding was reopened instead of a new one opened")
		}
	}

	// Every event, as written for the SIEM and as a syslog body, matches the
	// schema; the target is the finding's subject.
	types := map[string]int{}
	sc := bufio.NewScanner(&lines)
	for sc.Scan() {
		if err := posture.ValidateDriftEvent(sc.Bytes()); err != nil {
			t.Errorf("JSON-lines event does not match the schema: %v\n%s", err, sc.Text())
		}
	}
	for _, ev := range sink.Events() {
		types[ev.Type]++
		if ev.Target != ev.Attributes["subject"] {
			t.Errorf("%s: target %q, subject %q", ev.Type, ev.Target, ev.Attributes["subject"])
		}
		msg, err := audit.FormatRFC5424(ev, "posture-0", "fair-posture")
		if err != nil {
			t.Fatal(err)
		}
		body := msg[strings.Index(msg, "{"):]
		if err := posture.ValidateDriftEvent([]byte(body)); err != nil {
			t.Errorf("syslog body does not match the schema: %v\n%s", err, body)
		}
	}
	if types[posture.EventDriftDetected] != 4 || types[posture.EventDriftAcknowledged] != 1 || types[posture.EventDriftResolved] != 2 {
		t.Fatalf("events %v", types)
	}
	ackEv := sink.OfType(posture.EventDriftAcknowledged)[0]
	if ackEv.Actor != admin.UserID || ackEv.Reason == "" || ackEv.Attributes["remediation"] == "" || ackEv.Attributes["controls"] != "CM-3,CM-6" {
		t.Fatalf("acknowledgement event %+v", ackEv)
	}
	for _, ev := range sink.OfType(posture.EventDriftResolved) {
		if ev.Attributes["check_id"] == posture.CheckDeviation && ev.Attributes["acknowledged_by"] != admin.UserID {
			t.Fatalf("resolved event lost the acknowledgement: %+v", ev.Attributes)
		}
	}
}

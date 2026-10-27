package posture

import (
	"encoding/json"
	"strings"
	"testing"
)

// F-015 T-26: the drift event schema (the SIEM contract) accepts the three
// events in both sink forms and refuses events that break it.
func TestDriftEventSchema(t *testing.T) {
	base := func(typ string) map[string]any {
		ev := map[string]any{
			"id": strings.Repeat("ab", 16), "time": "2026-10-27T12:00:00Z", "type": typ, "severity": "high",
			"actor": DriftActor, "target": "setting:session.idle_timeout",
			"attributes": map[string]any{
				"finding_id": "0b0c3f2e-5d1a-4c7e-9f00-1234567890ab", "check_id": "unapproved_deviation", "kind": "app",
				"severity": "high", "controls": "CM-3,CM-6", "subject": "setting:session.idle_timeout",
				"detail": `{"key":"session.idle_timeout"}`, "remediation": "Tighten it.",
			},
		}
		switch typ {
		case EventDriftAcknowledged:
			ev["severity"], ev["actor"], ev["reason"] = "low", "7d1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", "change window"
			ev["attributes"].(map[string]any)["acknowledged_by"] = "7d1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
		case EventDriftResolved:
			ev["severity"] = "info"
		}
		return ev
	}
	check := func(name string, ev map[string]any, ok bool) {
		t.Helper()
		b, _ := json.Marshal(ev)
		if err := ValidateDriftEvent(b); (err == nil) != ok {
			t.Errorf("%s: valid=%t, want %t (%v)", name, err == nil, ok, err)
		}
	}
	attrs := func(ev map[string]any) map[string]any { return ev["attributes"].(map[string]any) }

	for _, typ := range []string{EventDriftDetected, EventDriftAcknowledged, EventDriftResolved} {
		check(typ, base(typ), true)
		withKind := base(typ)
		withKind["kind"] = "audit" // the JSON-lines form
		check(typ+" (JSON lines)", withKind, true)
	}
	critical := base(EventDriftDetected)
	critical["severity"], attrs(critical)["severity"] = "critical", "critical"
	check("critical finding, critical event", critical, true)

	for name, mutate := range map[string]func(map[string]any){
		"unknown type":                   func(ev map[string]any) { ev["type"] = "posture.drift_ignored" },
		"extra field":                    func(ev map[string]any) { ev["password"] = "x" },
		"no attributes":                  func(ev map[string]any) { delete(ev, "attributes") },
		"no controls":                    func(ev map[string]any) { delete(attrs(ev), "controls") },
		"bad controls":                   func(ev map[string]any) { attrs(ev)["controls"] = "cm-6; CM-3" },
		"no remediation":                 func(ev map[string]any) { delete(attrs(ev), "remediation") },
		"unknown attribute":              func(ev map[string]any) { attrs(ev)["note"] = "x" },
		"bad finding id":                 func(ev map[string]any) { attrs(ev)["finding_id"] = "1" },
		"bad target":                     func(ev map[string]any) { ev["target"] = "row 7" },
		"low severity detection":         func(ev map[string]any) { ev["severity"] = "low" },
		"critical finding, high event":   func(ev map[string]any) { attrs(ev)["severity"] = "critical" },
		"detection by a person":          func(ev map[string]any) { ev["actor"] = "7d1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b" },
		"detection with a reason":        func(ev map[string]any) { ev["reason"] = "x" },
		"bad time":                       func(ev map[string]any) { ev["time"] = "yesterday" },
		"detection already acknowledged": func(ev map[string]any) { attrs(ev)["acknowledged_by"] = "7d1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b" },
	} {
		ev := base(EventDriftDetected)
		mutate(ev)
		check(name, ev, false)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no reason":       func(ev map[string]any) { delete(ev, "reason") },
		"system actor":    func(ev map[string]any) { ev["actor"] = DriftActor },
		"no acknowledger": func(ev map[string]any) { delete(attrs(ev), "acknowledged_by") },
		"high severity":   func(ev map[string]any) { ev["severity"] = "high" },
	} {
		ev := base(EventDriftAcknowledged)
		mutate(ev)
		check("acknowledged: "+name, ev, false)
	}
	for name, mutate := range map[string]func(map[string]any){
		"high severity": func(ev map[string]any) { ev["severity"] = "high" },
		"by a person":   func(ev map[string]any) { ev["actor"] = "7d1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b" },
	} {
		ev := base(EventDriftResolved)
		mutate(ev)
		check("resolved: "+name, ev, false)
	}
}

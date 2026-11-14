package register

import (
	"testing"
	"time"
)

func TestActionOverdue(t *testing.T) {
	today := time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		due, state string
		want       bool
	}{
		{"2026-11-13", "planned", true},
		{"2026-11-13", "in_progress", true},
		{"2026-11-14", "planned", false}, // due today: not yet past
		{"2026-11-13", "done", false},
		{"2026-11-13", "cancelled", false},
		{"2026-11-15", "planned", false},
		{"not a date", "planned", false},
	} {
		if got := (Action{Due: c.due, State: c.state}).Overdue(today); got != c.want {
			t.Errorf("%s %s: %v", c.due, c.state, got)
		}
	}
}

func TestActionsChanged(t *testing.T) {
	a := Action{ID: "a", Title: "MFA", Due: "2026-12-01", State: "planned"}
	b := Action{ID: "b", Title: "Backups", Due: "2026-12-01", State: "planned"}
	c := Action{ID: "c", Title: "Training", Due: "2026-12-01", State: "planned"}
	done := b
	done.State = "done"
	if n := ActionsChanged(Treatment{}, Treatment{Actions: []Action{a, b}}); n != 2 {
		t.Errorf("from nothing: %d", n)
	}
	if n := ActionsChanged(Treatment{Actions: []Action{a, b}}, Treatment{Actions: []Action{a, done, c}}); n != 2 {
		t.Errorf("one changed, one added: %d", n)
	}
	if n := ActionsChanged(Treatment{Actions: []Action{a, b}}, Treatment{Actions: []Action{a}}); n != 1 {
		t.Errorf("one removed: %d", n)
	}
	if n := ActionsChanged(Treatment{Actions: []Action{a}}, Treatment{Actions: []Action{a}}); n != 0 {
		t.Errorf("unchanged: %d", n)
	}
}

func TestCanonicalTreatment(t *testing.T) {
	b, digest, problems := CanonicalTreatment([]byte(`{"schema_version":1, "decision":"accept","rationale":"Within appetite."}`))
	if problems != nil || string(b) != `{"decision":"accept","rationale":"Within appetite.","schema_version":1}` || len(digest) != 64 {
		t.Errorf("canonical: %s %v", b, problems)
	}
	if _, _, problems := CanonicalTreatment([]byte(`[1]`)); problems == nil {
		t.Error("an array accepted")
	}
	if tr, err := DecodeTreatment(EmptyTreatment); err != nil || tr.Decision != nil || tr.SchemaVersion != 1 {
		t.Errorf("empty: %+v %v", tr, err)
	}
}

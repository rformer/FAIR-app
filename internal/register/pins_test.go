package register

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	s1 = "11111111-1111-4111-8111-111111111111"
	s2 = "22222222-2222-4222-8222-222222222222"
	s3 = "33333333-3333-4333-8333-333333333333"
	r1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	r2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	r3 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func doc(t *testing.T, links string) []byte {
	t.Helper()
	b, _, problems := Validate([]byte(`{"schema_version":1,"title":"T","owner":"` + s1 + `","category":null,"state":"open","scenarios":[` + links + `]}`))
	if problems != nil {
		t.Fatal(problems)
	}
	return b
}

func TestPinChanges(t *testing.T) {
	from := doc(t, `{"scenario_id":"`+s1+`","pin":{"run_id":"`+r1+`","control_set":"Current"}},{"scenario_id":"`+s2+`","pin":{"run_id":"`+r2+`","control_set":"Current"}},{"scenario_id":"`+s3+`"}`)
	to := doc(t, `{"scenario_id":"`+s1+`","pin":{"run_id":"`+r1+`","control_set":"Current"}},{"scenario_id":"`+s2+`"},{"scenario_id":"`+s3+`","pin":{"run_id":"`+r3+`","control_set":"Proposed","reason":"the plan"}}`)
	got, err := PinChanges(from, to)
	if err != nil {
		t.Fatal(err)
	}
	want := []PinChange{{ScenarioID: s2}, {ScenarioID: s3, Pin: &Pin{RunID: r3, ControlSet: "Proposed", Reason: "the plan"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes: %+v", got)
	}
	if got, _ := PinChanges(nil, from); len(got) != 2 || got[0].ScenarioID != s1 || got[1].ScenarioID != s2 {
		t.Errorf("from nothing: %+v", got)
	}
	if got, _ := PinChanges(to, to); len(got) != 0 {
		t.Errorf("unchanged: %+v", got)
	}
	// A scenario unlinked is not a pin change; one newly linked without a pin neither.
	if got, _ := PinChanges(from, doc(t, `{"scenario_id":"`+s1+`","pin":{"run_id":"`+r1+`","control_set":"Current"}}`)); len(got) != 0 {
		t.Errorf("unlinked: %+v", got)
	}
}

func TestAdoptions(t *testing.T) {
	r, err := Decode(doc(t, `{"scenario_id":"`+s1+`","pin":{"run_id":"`+r1+`","control_set":"Current"}},{"scenario_id":"`+s2+`","pin":{"run_id":"`+r1+`","control_set":"Proposed","reason":"the plan"}},{"scenario_id":"`+s3+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	newer := []NewerRun{
		{ScenarioID: s1, RunID: r3, ControlSets: []string{"Now", "Current"}},
		{ScenarioID: s1, RunID: r2, ControlSets: []string{"Current"}},
		{ScenarioID: s2, RunID: r2, ControlSets: []string{"Current", "Proposed"}},
		{ScenarioID: s3, RunID: r2, ControlSets: []string{"Current"}}, // not pinned: nothing to adopt
	}
	got := Adoptions(r, newer)
	want := map[string]Pin{
		s1: {RunID: r3, ControlSet: "Now"},                          // the newest, its current set
		s2: {RunID: r2, ControlSet: "Proposed", Reason: "the plan"}, // the set kept, with its reason
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("adoptions: %+v", got)
	}
	// A newer run without the pinned set: its current set.
	if got := Adoptions(r, []NewerRun{{ScenarioID: s2, RunID: r3, ControlSets: []string{"Current"}}}); got[s2] != (Pin{RunID: r3, ControlSet: "Current"}) {
		t.Errorf("set gone: %+v", got)
	}
	if got := Adoptions(r, nil); len(got) != 0 {
		t.Errorf("nothing newer: %+v", got)
	}
}

func TestWithPins(t *testing.T) {
	stored := doc(t, `{"scenario_id":"`+s1+`","pin":{"run_id":"`+r1+`","control_set":"Proposed","reason":"x"}},{"scenario_id":"`+s2+`"}`)
	b, digest, err := WithPins(stored, map[string]Pin{s1: {RunID: r2, ControlSet: "Current"}, s2: {RunID: r3, ControlSet: "Current"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, d, problems := Validate(b); problems != nil || d != digest {
		t.Fatalf("not canonical: %v", problems)
	}
	s := string(b)
	if !strings.Contains(s, `"category":null`) || strings.Contains(s, `"reason"`) || strings.Count(s, `"control_set":"Current"`) != 2 {
		t.Errorf("document: %s", s)
	}
	if _, _, err := WithPins(stored, map[string]Pin{s3: {RunID: r3, ControlSet: "Current"}}); !errors.Is(err, ErrNotLinked) {
		t.Errorf("an unlinked scenario: %v", err)
	}
}

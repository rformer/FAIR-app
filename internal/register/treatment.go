package register

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
)

// F-007 T-06 (F-007-AC-15 to AC-18; design §3.2): a risk's treatment plan.
// The database checks the document (register.check_treatment: decision and
// rationale, targets of the linked scenarios' latest versions, actions);
// the service puts it in canonical form and reads it.

// Target is the control set a mitigation expects a scenario to reach.
type Target struct {
	ScenarioID string `json:"scenario_id"`
	ControlSet string `json:"control_set"`
}

// Action is a step of the plan.
type Action struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Owner        string `json:"owner"`
	Due          string `json:"due"`
	State        string `json:"state"`
	CancelReason string `json:"cancel_reason,omitempty"`
}

// Treatment is a treatment document (schema_version 1).
type Treatment struct {
	SchemaVersion int      `json:"schema_version"`
	Decision      *string  `json:"decision"`
	Rationale     string   `json:"rationale,omitempty"`
	Targets       []Target `json:"targets,omitempty"`
	Actions       []Action `json:"actions,omitempty"`
}

// EmptyTreatment is the plan of a risk that has none yet.
var EmptyTreatment = []byte(`{"actions":[],"decision":null,"schema_version":1,"targets":[]}`)

// CanonicalTreatment is a treatment document's canonical form and digest,
// or the problem that keeps it from having one.
func CanonicalTreatment(raw []byte) ([]byte, string, model.Problems) {
	if len(raw) > MaxDocumentBytes {
		return nil, "", model.Problems{{Pointer: "/", Message: fmt.Sprintf("is larger than %d bytes", MaxDocumentBytes)}}
	}
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, "", model.Problems{{Pointer: "/", Message: "is not JSON the platform accepts: " + err.Error()}}
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, "", model.Problems{{Pointer: "/", Message: "is not a JSON object"}}
	}
	b, err := canon.Marshal(v)
	if err != nil {
		return nil, "", model.Problems{{Pointer: "/", Message: err.Error()}}
	}
	return b, canon.Digest(b), nil
}

// DecodeTreatment reads a stored treatment document.
func DecodeTreatment(b []byte) (Treatment, error) {
	var t Treatment
	return t, json.Unmarshal(b, &t)
}

// Overdue reports whether an action is past its due date on day today and
// neither done nor cancelled (AC-17).
func (a Action) Overdue(today time.Time) bool {
	if a.State != "planned" && a.State != "in_progress" {
		return false
	}
	due, err := time.Parse(time.DateOnly, a.Due)
	return err == nil && due.Before(today.UTC().Truncate(24*time.Hour))
}

// ActionsChanged counts the actions added, removed or changed between two
// plans (from nil: every action is added).
func ActionsChanged(from, to Treatment) int {
	before := map[string]Action{}
	for _, a := range from.Actions {
		before[a.ID] = a
	}
	n := 0
	seen := map[string]bool{}
	for _, a := range to.Actions {
		seen[a.ID] = true
		if b, ok := before[a.ID]; !ok || b != a {
			n++
		}
	}
	for id := range before {
		if !seen[id] {
			n++
		}
	}
	return n
}

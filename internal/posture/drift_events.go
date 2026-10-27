package posture

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Drift finding events (F-015 T-26; AC-37, AC-42). Their JSON form, as every
// audit sink writes it, is specified by drift_events.schema.json: the
// contract for SIEM integrations.
const (
	EventDriftDetected     = "posture.drift_detected"
	EventDriftAcknowledged = "posture.drift_acknowledged"
	EventDriftResolved     = "posture.drift_resolved"
)

// DriftEventSchema is the JSON Schema (2020-12) of the drift events.
//
//go:embed drift_events.schema.json
var DriftEventSchema []byte

var (
	eventSchemaOnce sync.Once
	eventSchema     *jsonschema.Schema
	eventSchemaErr  error
)

// ValidateDriftEvent checks one event, as JSON, against DriftEventSchema.
func ValidateDriftEvent(data []byte) error {
	eventSchemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(DriftEventSchema))
		if err != nil {
			eventSchemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		const url = "drift_events.schema.json"
		if err := c.AddResource(url, doc); err != nil {
			eventSchemaErr = err
			return
		}
		eventSchema, eventSchemaErr = c.Compile(url)
	})
	if eventSchemaErr != nil {
		return fmt.Errorf("drift event schema: %w", eventSchemaErr)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("drift event: %w", err)
	}
	return eventSchema.Validate(inst)
}

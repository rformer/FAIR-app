package importapi

import (
	"encoding/json"
	"reflect"
	"slices"

	"github.com/rformer/fair-app/internal/integration"
)

// F-011 T-09 (F-011-AC-10, AC-12 to AC-14; design §3.4 as amended
// 2026-11-18): a run's records become proposals. A proposal holds the
// source record's values and digest; the merged document is computed at
// review, under the reviewer's RLS (T-10). Loss events are not proposed:
// they are data, and the reference classes derived from them are (T-12).

// targetType is the platform record a record kind proposes changes to.
var targetType = map[string]string{
	integration.KindAsset:         "asset",
	integration.KindAssetGroup:    "asset_group",
	integration.KindRisk:          "risk",
	integration.KindControlStatus: "control",
}

// descriptiveFields are the fields a descriptive-only change touches
// (AC-13): names and descriptions; never values, estimates or status.
var descriptiveFields = map[string][]string{
	integration.KindAsset:      {"name", "description"},
	integration.KindAssetGroup: {"name", "description"},
	integration.KindRisk:       {"title", "description"},
}

type proposal struct {
	ExternalID      string          `json:"external_id"`
	TargetType      string          `json:"target_type"`
	TargetID        *string         `json:"target_id"`
	Action          string          `json:"action"`
	BU              string          `json:"bu_id"`
	Document        json.RawMessage `json:"document"`
	Digest          string          `json:"digest"`
	DescriptiveOnly bool            `json:"descriptive_only"`
}

// descriptiveOnly reports whether next differs from prev (the record last
// accepted) in descriptive fields only.
func descriptiveOnly(kind string, prev, next json.RawMessage) bool {
	allowed := descriptiveFields[kind]
	if len(allowed) == 0 || prev == nil {
		return false
	}
	var a, b map[string]any
	if json.Unmarshal(prev, &a) != nil || json.Unmarshal(next, &b) != nil {
		return false
	}
	changed := false
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if reflect.DeepEqual(a[k], b[k]) {
				continue
			}
			if !slices.Contains(allowed, k) {
				return false
			}
			changed = true
		}
	}
	return changed
}

// controlOf is a control status record's named control ("" without one).
func controlOf(rec integration.Record) string {
	var c struct {
		Control string `json:"control"`
	}
	_ = json.Unmarshal(rec.Data, &c)
	return c.Control
}

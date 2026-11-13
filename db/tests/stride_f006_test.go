package tests

import "testing"

// F-006 design §7: the threats to results and their views, attacked
// through the analysis API (the rows join TestSTRIDECatalog with T-08).

// I: a comparison reveals that a hidden result exists, or which item is
// hidden (AC-13). Mallory, at B, compares her own run with a run or an
// aggregate at A1 she cannot see, or with ids that do not exist, at every
// position: the answer is the same 404, byte for byte.
func TestSTRIDEF006ComparisonOracle(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B
	ae := analysisAPI(t, ra, defaultLimits, true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	rb := runWith(t, ae, "mallory", sb, 1, 2000, "7")
	got := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "Claims",
		"members": []map[string]any{{"run_id": r1, "control_set": "Current"}, {"run_id": r1, "control_set": "Proposed"}}, "seed": "1"})
	if got.code != 202 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	a1 := got.body["id"].(string)
	const none = "00000000-0000-4000-8000-000000000000"
	mine := []string{"run:" + rb + ":Current", "run:" + rb + ":Proposed"}
	var first string
	for _, other := range []string{"run:" + r1 + ":Current", "run:" + r1 + ":Elsewhere", "run:" + none + ":Current", "aggregate:" + a1, "aggregate:" + none} {
		for pos := 0; pos <= len(mine); pos++ {
			items := append(append(append([]string{}, mine[:pos]...), other), mine[pos:]...)
			got := ae.call(t, "GET", "mallory", compareURL(items...), nil)
			if got.code != 404 {
				t.Errorf("%s at %d: %d %s", other, pos, got.code, got.raw)
			}
			if first == "" {
				first = got.raw
			} else if got.raw != first {
				t.Errorf("%s at %d answers %s, not %s", other, pos, got.raw, first)
			}
		}
	}
	if got := ae.call(t, "GET", "mallory", compareURL(mine...), nil); got.code != 200 {
		t.Errorf("her own: %d %s", got.code, got.raw)
	}
}

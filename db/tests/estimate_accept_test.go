package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-08 (F-004-AC-15 to AC-19; design §3.4, §3.5, §6.3): review,
// acceptance into a scenario version, and the database's verification of
// the provenance.
func TestEstimateAcceptance(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam", "viewer"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + strings.ToUpper(u[:1]) + u[1:] + "')")
	}
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:sam", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.drain()
	id := func(u string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + u + "@example.test'")
	}
	dana, sam := id("dana"), id("sam")
	doc := ra.scenarioDoc(t)
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	got = ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": sid, "title": "CF and response",
		"due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339), "factors": []any{"/lef/tef/contact_frequency", "/primary_loss/response"},
		"estimators": []any{dana, sam}})
	if got.code != 201 {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	rid := got.body["id"].(string)
	est := func(unit, lo, ml, hi, ref string) map[string]any {
		return map[string]any{"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9", "rationale": "What I have seen.",
			"sources": []any{map[string]any{"type": "person", "ref": ref}}}
	}
	answer := func(user string, answers ...any) {
		t.Helper()
		if got := ea.call(t, "PUT", user, "/api/v1/estimates/inbox/"+rid+"/answers", map[string]any{"submit": true, "answers": answers}); got.code != 200 {
			t.Fatalf("%s answers: %d %s", user, got.code, got.raw)
		}
	}
	answer("dana", map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": est("events_per_year", "2", "5", "10", "Dana's notes")},
		map[string]any{"pointer": "/primary_loss/response", "declined": "Not my area"})
	answer("sam", map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": est("events_per_year", "4", "7", "12", "SOC tickets")},
		map[string]any{"pointer": "/primary_loss/response", "estimate": est("currency", "40000", "120000", "500000", "Past invoices")})

	// Review: side by side, previews of both pools; outsiders see nothing.
	got = ea.call(t, "GET", "viewer", "/api/v1/estimates/requests/"+rid+"/answers", nil)
	if got.code != 200 || !strings.Contains(got.raw, `"equal":{"Min":"3","ML":"6","Max":"11"`) || !strings.Contains(got.raw, `"Dana"`) {
		t.Fatalf("review: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "GET", "mallory", "/api/v1/estimates/requests/"+rid+"/answers", nil); got.code != 404 {
		t.Fatalf("an outsider reviews: %d", got.code)
	}

	accept := func(user string, expected int, factors ...any) apiResp {
		return ea.call(t, "POST", user, "/api/v1/estimates/requests/"+rid+"/accept", map[string]any{"expected_version": expected, "change_note": "Accepted", "factors": factors})
	}
	if got := accept("viewer", 1, map[string]any{"pointer": "/lef/tef/contact_frequency", "method": "equal"}); got.code != 403 {
		t.Fatalf("a viewer accepts: %d", got.code)
	}
	for name, f := range map[string]map[string]any{
		"single of two":        {"pointer": "/lef/tef/contact_frequency", "method": "single"},
		"a declined answer":    {"pointer": "/primary_loss/response", "method": "single", "estimators": []any{dana}},
		"own without estimate": {"pointer": "/primary_loss/response", "method": "own"},
		"not a request factor": {"pointer": "/lef/tef/probability_of_action", "method": "equal"},
	} {
		if got := accept("analyst", 1, f); got.code != 422 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	// Step one: contact frequency by an equal pool.
	got = accept("analyst", 1, map[string]any{"pointer": "/lef/tef/contact_frequency", "method": "equal"})
	if got.code != 200 || got.body["version"] != float64(2) {
		t.Fatalf("accept CF: %d %s", got.code, got.raw)
	}
	if got := accept("analyst", 1, map[string]any{"pointer": "/primary_loss/response", "method": "single", "estimators": []any{sam}}); got.code != 409 {
		t.Fatalf("a stale acceptance: %d %s", got.code, got.raw)
	}
	// Step two: response by Sam's answer alone.
	if got := accept("analyst", 2, map[string]any{"pointer": "/primary_loss/response", "method": "single", "estimators": []any{sam}}); got.code != 200 {
		t.Fatalf("accept response: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT string_agg(pointer || '=' || accepted_version, ',' ORDER BY pointer) FROM estimate.request_factor WHERE request_id = '" + rid + "'"); got !=
		"/lef/tef/contact_frequency=2,/primary_loss/response=3" {
		t.Fatalf("accepted versions: %s", got)
	}
	// The provenance on the scenario.
	read := ra.call(t, "GET", "viewer", "/api/v1/scenarios/"+sid, nil)
	cfDoc := read.body["version"].(map[string]any)["document"].(map[string]any)["lef"].(map[string]any)["tef"].(map[string]any)["contact_frequency"].(map[string]any)
	el := cfDoc["elicitation"].(map[string]any)
	if cfDoc["min"] != "3" || cfDoc["max"] != "11" || el["method"] != "equal" || el["request"] != rid || len(el["answers"].([]any)) != 2 ||
		el["answers"].([]any)[0].(map[string]any)["name"] != "Dana" || el["answers"].([]any)[0].(map[string]any)["calibration"].(map[string]any)["class"] != "not_measured" {
		t.Fatalf("provenance: %v", cfDoc)
	}

	// The database verifies provenance written by anyone: forged values,
	// weights, answers or requests are refused; imported provenance is not
	// verified.
	cur := read.body["version"].(map[string]any)["document"].(map[string]any)
	save := func(d map[string]any, expected int) apiResp {
		return ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+sid, map[string]any{"document": d, "expected_version": expected, "change_note": "x"})
	}
	clone := func() map[string]any {
		b, _ := json.Marshal(cur)
		var d map[string]any
		_ = json.Unmarshal(b, &d)
		return d
	}
	const cf = "/lef/tef/contact_frequency"
	for name, c := range map[string]struct {
		pointer string
		value   any
		problem string
	}{
		"a forged pool":         {cf + "/max", "20", cf + "/max"},
		"a forged answer value": {cf + "/elicitation/answers/0/min", "1", cf + "/elicitation/answers/0/min"},
		"a forged weight":       {cf + "/elicitation/answers/1/weight", "0.5", cf + "/elicitation/answers/1/weight"},
		"a forged revision":     {cf + "/elicitation/answers/0/revision", 9, cf + "/elicitation/answers/0"},
		"a forged calibration":  {cf + "/elicitation/answers/0/calibration/class", "calibrated", cf + "/elicitation/answers/0/calibration"},
		"another request":       {cf + "/elicitation/request", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", cf + "/elicitation/request"},
	} {
		d := clone()
		modeltest.Set(d, c.pointer, c.value)
		if c.pointer == cf+"/elicitation/request" {
			modeltest.Set(d, cf+"/sources/0/ref", c.value)
		}
		got := save(d, 3)
		if got.code != 422 || !strings.Contains(got.raw, c.problem) {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	d := clone()
	modeltest.Set(d, cf+"/elicitation/imported", true)
	modeltest.Set(d, cf+"/max", "20")
	if got := save(d, 3); got.code != 200 {
		t.Fatalf("imported provenance: %d %s", got.code, got.raw)
	}
	// The analyst's own estimate, informed by the answers (weights 0).
	if got := accept("analyst", 4, map[string]any{"pointer": cf, "method": "own", "estimators": []any{sam},
		"estimate": est("events_per_year", "3", "6", "10", "Workshop")}); got.code != 200 {
		t.Fatalf("own: %d %s", got.code, got.raw)
	}
	// Library entries carry no provenance.
	asset := modeltest.Asset()
	asset["value"] = modeltest.Set(modeltest.Elicited(), "/unit", "currency")
	modeltest.Set(asset, "/value/elicitation/imported", true)
	modeltest.Set(asset, "/value/elicitation/answers/0/max", "1000")
	modeltest.Set(asset, "/value/elicitation/answers/1/max", "1000")
	if got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": asset, "change_note": "x"}); got.code != 422 ||
		!strings.Contains(got.raw, "only a scenario") {
		t.Fatalf("a library entry with provenance: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT string_agg(body ->> 'type', ',' ORDER BY id) FROM audit.intake WHERE body ->> 'type' IN ('estimate.accepted', 'scenario.version_saved')`); got !=
		"scenario.version_saved,estimate.accepted,scenario.version_saved,estimate.accepted,scenario.version_saved,scenario.version_saved,estimate.accepted" {
		t.Fatalf("events: %s", got)
	}

	// Go and SQL pool to the same digits.
	ctx := context.Background()
	answers := []estimate.Answer{
		ans3("a", "0.1", "0.35", "0.9", "calibrated", nil), ans3("b", "0.05", "0.2", "0.4", "overconfident", str("0.6667")),
		ans3("c", "0.2", "0.3", "0.333333", "underconfident", str("0.97")), ans3("d", "0", "0.01", "0.75", "not_measured", nil),
	}
	for _, m := range []string{estimate.MethodEqual, estimate.MethodCalibration} {
		for n := 1; n <= len(answers); n++ {
			p, err := estimate.Pool(m, answers[:n], "0.9")
			if err != nil {
				t.Fatal(err)
			}
			var mins []string
			for _, a := range answers[:n] {
				mins = append(mins, a.Min)
			}
			var sqlMin, sqlW string
			if err := ra.tx("analyst", func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, "SELECT estimate.num(estimate.pooled($1::numeric[], $2::numeric[])), array_to_string(ARRAY(SELECT estimate.num(x) FROM unnest($1::numeric[]) x), ',')",
					p.Weights, mins).Scan(&sqlMin, &sqlW)
			}); err != nil {
				t.Fatal(err)
			}
			if sqlMin != p.Min || sqlW != strings.Join(p.Weights, ",") {
				t.Errorf("%s of %d: SQL %s (%s), Go %s (%v)", m, n, sqlMin, sqlW, p.Min, p.Weights)
			}
			for _, a := range answers[:n] {
				var w string
				rate := ""
				if a.RangeRate != nil {
					rate = *a.RangeRate
				}
				if err := ra.tx("analyst", func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, "SELECT estimate.num(round(estimate.calibration_weight($1, nullif($2, '')), 12))", a.Class, rate).Scan(&w)
				}); err != nil {
					t.Fatal(err)
				}
				if want, _ := estimate.Pool(estimate.MethodCalibration, []estimate.Answer{a}, "0.9"); w != want.Weights[0] {
					t.Errorf("%s weight: SQL %s, Go %s", a.Name, w, want.Weights[0])
				}
			}
		}
	}
}

func str(s string) *string { return &s }

func ans3(name, lo, ml, hi, class string, rate *string) estimate.Answer {
	return estimate.Answer{Estimator: name, Name: name, Revision: 1, Min: lo, ML: ml, Max: hi, Confidence: "0.9", Class: class, RangeRate: rate, AsOf: "2026-11-10"}
}

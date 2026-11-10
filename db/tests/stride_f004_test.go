package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-16 (design §8): the STRIDE suite for estimate capture. Each test
// attacks one mitigation of a §8 row through the API or the database, as
// an attacker in that row would; TestSTRIDECatalog ties the rows to them.

// f004 is a request on a scenario at A1, sent by the analyst (A) to Dana
// and Sam (Estimators at A), both of whom answered: Dana 2 – 5 – 10 for
// contact frequency and a decline for response, Sam 4 – 7 – 12 and
// 40000 – 120000 – 500000. Viewer is an Executive Viewer at A, auditor an
// Auditor at the root; mallory is a risk analyst at B.
type f004 struct {
	ra, ea          *riskAPIEnv
	sid, rid        string
	dana, sam, rhea string
	cf, response    string
}

func strideF004Fixture(t *testing.T) f004 {
	t.Helper()
	ra := strideF003Fixture(t)
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam", "rhea", "viewer", "auditor"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + strings.ToUpper(u[:1]) + u[1:] + "')")
	}
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:sam", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:rhea", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.mustOwner(grant("platform", "user:auditor", "Auditor", "ENTERPRISE"))
	ra.drain()
	id := func(u string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + u + "@example.test'")
	}
	f := f004{ra: ra, ea: ea, dana: id("dana"), sam: id("sam"), rhea: id("rhea"), cf: "/lef/tef/contact_frequency", response: "/primary_loss/response"}
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": ra.scenarioDoc(t), "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	f.sid = got.body["id"].(string)
	got = ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": f.sid, "title": "CF and response",
		"due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339), "factors": []any{f.cf, f.response}, "estimators": []any{f.dana, f.sam, f.rhea}})
	if got.code != 201 {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	f.rid = got.body["id"].(string)
	f.answer(t, "dana", true, map[string]any{"pointer": f.cf, "estimate": f.est("events_per_year", "2", "5", "10", "Dana's notes")},
		map[string]any{"pointer": f.response, "declined": "Not my area"})
	f.answer(t, "sam", true, map[string]any{"pointer": f.cf, "estimate": f.est("events_per_year", "4", "7", "12", "SOC tickets")},
		map[string]any{"pointer": f.response, "estimate": f.est("currency", "40000", "120000", "500000", "Past invoices")})
	return f
}

func (f f004) est(unit, lo, ml, hi, ref string) map[string]any {
	return map[string]any{"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9", "rationale": "What I have seen.",
		"sources": []any{map[string]any{"type": "person", "ref": ref}}}
}

func (f f004) answer(t *testing.T, user string, submit bool, answers ...any) {
	t.Helper()
	if got := f.ea.call(t, "PUT", user, "/api/v1/estimates/inbox/"+f.rid+"/answers", map[string]any{"submit": submit, "answers": answers}); got.code != 200 {
		t.Fatalf("%s answers: %d %s", user, got.code, got.raw)
	}
}

// S: an estimator answers as another person.
func TestSTRIDEF004AnswerAuthor(t *testing.T) {
	f := strideF004Fixture(t)
	ctx := context.Background()
	// The body cannot name an estimator; the author is the signed caller.
	if got := f.ea.call(t, "PUT", "dana", "/api/v1/estimates/inbox/"+f.rid+"/answers", map[string]any{"submit": true, "estimator": f.sam,
		"answers": []any{map[string]any{"pointer": f.cf, "estimator": f.sam, "estimate": f.est("events_per_year", "1", "2", "3", "x")}}}); got.code != 400 {
		t.Fatalf("an estimator field: %d %s", got.code, got.raw)
	}
	if got := f.ra.adminQuery("SELECT string_agg(DISTINCT u.email, ',' ORDER BY u.email) FROM estimate.answer a JOIN iam.app_user u ON u.id = a.estimator WHERE a.request_id = '" + f.rid + "'"); got != "dana@example.test,sam@example.test" {
		t.Fatalf("authors: %s", got)
	}
	// Nobody writes answers directly, and the function refuses a caller
	// without a signed context or not addressed.
	f.ra.mustFail("app_rw", fmt.Sprintf(`INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, calibration)
		VALUES ('%s', '%s', '%s', '%s', 9, 'submitted', '{}', '{}')`, f.rid, f.ra.bu["A1"], f.sam, f.cf), "permission denied")
	call := func(user string) error {
		return f.ra.tx(user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT estimate.save_answer($1, $2, NULL, 'mine now', true)", f.rid, f.cf)
			return err
		})
	}
	if err := call(""); !strings.HasPrefix(pgCode(err), "PF022") {
		t.Fatalf("no context: %s", pgCode(err))
	}
	for _, user := range []string{"mallory", "analyst", "viewer"} {
		if err := call(user); !strings.HasPrefix(pgCode(err), "P0002") {
			t.Errorf("%s answers: %s", user, pgCode(err))
		}
		if got := f.ea.call(t, "PUT", user, "/api/v1/estimates/inbox/"+f.rid+"/answers", map[string]any{"submit": true,
			"answers": []any{map[string]any{"pointer": f.cf, "declined": "x"}}}); got.code != 404 {
			t.Errorf("%s through the API: %d", user, got.code)
		}
	}
}

// T: an answer is changed after it was used.
func TestSTRIDEF004AnswerTamper(t *testing.T) {
	f := strideF004Fixture(t)
	if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "Pooled",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "equal"}}}); got.code != 200 {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	// Revisions are append-only for every role, the superuser included.
	for _, q := range []string{"UPDATE estimate.answer SET estimate = estimate || '{\"min\": \"0\"}'", "DELETE FROM estimate.answer", "TRUNCATE estimate.answer"} {
		if err := f.ra.psqlAs(nil, f.ra.db, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("superuser: %s: %v", q, err)
		}
	}
	// A new revision changes nothing already accepted: the provenance names
	// the revisions used, and re-saving the version re-checks them.
	f.answer(t, "dana", true, map[string]any{"pointer": f.cf, "estimate": f.est("events_per_year", "1", "2", "3", "Changed my mind")})
	read := f.ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+f.sid, nil)
	doc := read.body["version"].(map[string]any)["document"].(map[string]any)
	if got := f.ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+f.sid, map[string]any{"document": doc, "expected_version": 2, "change_note": "unchanged"}); got.code != 200 {
		t.Fatalf("re-saving the accepted version: %d %s", got.code, got.raw)
	}
	b, _ := json.Marshal(doc)
	var forged map[string]any
	_ = json.Unmarshal(b, &forged)
	modeltest.Set(forged, f.cf+"/elicitation/answers/0/revision", 2) // Dana's new revision, with the old numbers
	if got := f.ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+f.sid, map[string]any{"document": forged, "expected_version": 3, "change_note": "x"}); got.code != 422 ||
		!strings.Contains(got.raw, f.cf+"/elicitation/answers/0") {
		t.Fatalf("a re-pointed revision: %d %s", got.code, got.raw)
	}
	// The version's stored digest still matches its document.
	if got := f.ra.adminQuery("SELECT bool_and(digest = encode(sha256(document), 'hex')) FROM risk.scenario_version WHERE scenario_id = '" + f.sid + "'"); got != "t" {
		t.Fatalf("digests: %s", got)
	}
}

// T: a client supplies a pooled result.
func TestSTRIDEF004CombinationChecked(t *testing.T) {
	f := strideF004Fixture(t)
	// The accept body takes no result for a pool...
	if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "x",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "equal", "estimate": f.est("events_per_year", "1", "1", "1", "x")}}}); got.code != 422 ||
		!strings.Contains(got.raw, "only with it") {
		t.Fatalf("a pool with a result: %d %s", got.code, got.raw)
	}
	if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "x",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "equal", "min": "1"}}}); got.code != 400 {
		t.Fatalf("a pool with numbers: %d %s", got.code, got.raw)
	}
	// ...and a version written with a forged pool or weights is refused by
	// the database, whoever writes it.
	if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "Pooled",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "calibration"}}}); got.code != 200 {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	read := f.ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+f.sid, nil)
	doc := read.body["version"].(map[string]any)["document"].(map[string]any)
	for name, c := range map[string]struct {
		pointer string
		value   any
	}{
		"the pooled minimum": {f.cf + "/min", "1"},
		"the pooled maximum": {f.cf + "/max", "40"},
		"a weight":           {f.cf + "/elicitation/answers/0/weight", "5"},
	} {
		b, _ := json.Marshal(doc)
		var d map[string]any
		_ = json.Unmarshal(b, &d)
		modeltest.Set(d, c.pointer, c.value)
		if got := f.ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+f.sid, map[string]any{"document": d, "expected_version": 2, "change_note": "x"}); got.code != 422 ||
			!strings.Contains(got.raw, f.cf) {
			t.Errorf("%s forged: %d %s", name, got.code, got.raw)
		}
	}
}

// R: an acceptance cannot be attributed.
func TestEstimateAuditEvents(t *testing.T) {
	f := strideF004Fixture(t)
	if got := f.ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+f.rid, map[string]any{"due_at": time.Now().Add(96 * time.Hour).UTC().Format(time.RFC3339),
		"reason": "More time"}); got.code != 200 {
		t.Fatalf("change: %d %s", got.code, got.raw)
	}
	if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "Pooled",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "equal"}, map[string]any{"pointer": f.response, "method": "single", "estimators": []any{f.sam}}}}); got.code != 200 {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	analyst := f.ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	// Every step recorded, by its actor, against the request, in the BU.
	got := f.ra.adminQuery(`SELECT string_agg(body ->> 'type' || ':' || CASE body ->> 'actor' WHEN '` + analyst + `' THEN 'analyst' WHEN '` + f.dana + `' THEN 'dana'
		WHEN '` + f.sam + `' THEN 'sam' ELSE body ->> 'actor' END, ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'target' = 'estimate_request:` + f.rid + `' AND body ->> 'bu_id' = '` + f.ra.bu["A1"] + `'`)
	// One answer_saved per submitted factor.
	want := "estimate.request_created:analyst,estimate.answer_saved:dana,estimate.answer_saved:dana,estimate.answer_saved:sam,estimate.answer_saved:sam," +
		"estimate.request_changed:analyst,estimate.accepted:analyst"
	if got != want {
		t.Fatalf("events:\n got %s\nwant %s", got, want)
	}
	if got := f.ra.adminQuery(`SELECT body -> 'attributes' ->> 'methods' || '/' || (body -> 'attributes' ->> 'version') FROM audit.intake
		WHERE body ->> 'type' = 'estimate.accepted'`); got != "equal,single/2" {
		t.Fatalf("accepted attributes: %s", got)
	}
	// The version saved in the same transaction, and its provenance naming
	// the request, the method and the answers.
	if got := f.ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'scenario.version_saved' AND body ->> 'target' = 'scenario:` + f.sid + `'`); got != "1" { // version 1 was scenario.created
		t.Fatalf("version events: %s", got)
	}
	read := f.ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+f.sid, nil)
	el := read.body["version"].(map[string]any)["document"].(map[string]any)["primary_loss"].(map[string]any)["response"].(map[string]any)["elicitation"].(map[string]any)
	if el["request"] != f.rid || el["method"] != "single" || len(el["answers"].([]any)) != 1 || el["answers"].([]any)[0].(map[string]any)["estimator"] != f.sam {
		t.Fatalf("provenance: %v", el)
	}
}

// I: an estimator is anchored by other answers or the scenario.
func TestSTRIDEF004Independence(t *testing.T) {
	f := strideF004Fixture(t)
	// A draft of Rhea's: hers alone, never in the review.
	f.answer(t, "rhea", false, map[string]any{"pointer": f.cf, "estimate": f.est("events_per_year", "50", "60", "70", "Rhea's draft")})
	view := f.ea.call(t, "GET", "dana", "/api/v1/estimates/inbox/"+f.rid, nil)
	if view.code != 200 {
		t.Fatalf("dana's view: %d %s", view.code, view.raw)
	}
	for _, leak := range []string{"SOC tickets", "Past invoices", "Rhea's draft", f.sam, f.rhea} {
		if strings.Contains(view.raw, leak) {
			t.Errorf("dana's view holds %q: %s", leak, view.raw)
		}
	}
	// The context snapshot carries no estimate.
	if c, _ := json.Marshal(view.body["context"]); strings.Contains(string(c), `"min"`) || strings.Contains(string(c), "estimate") {
		t.Errorf("context: %s", c)
	}
	if got := f.ea.call(t, "GET", "rhea", "/api/v1/estimates/inbox/"+f.rid, nil); !strings.Contains(got.raw, "Rhea's draft") {
		t.Errorf("rhea's own draft: %s", got.raw)
	}
	if got := f.ea.call(t, "GET", "analyst", "/api/v1/estimates/requests/"+f.rid+"/answers", nil); got.code != 200 || strings.Contains(got.raw, "Rhea's draft") {
		t.Errorf("the review: %d %s", got.code, got.raw)
	}
	// No scenario, library or other request for an estimator.
	for _, path := range []string{"/api/v1/scenarios/" + f.sid, "/api/v1/scenarios", "/api/v1/library"} {
		if got := f.ra.call(t, "GET", "dana", path, nil); got.code != 404 {
			t.Errorf("dana GET %s: %d", path, got.code)
		}
	}
	for _, path := range []string{"/api/v1/estimates/requests/" + f.rid, "/api/v1/estimates/requests/" + f.rid + "/answers", "/api/v1/estimates/requests?scenario=" + f.sid} {
		if got := f.ea.call(t, "GET", "dana", path, nil); got.code != 404 {
			t.Errorf("dana GET %s: %d", path, got.code)
		}
	}
	f.ra.mustFail("app_rw", "SELECT 1 FROM estimate.answer", "permission denied")
}

// I: a removed estimator, or one without the permission at the BU, keeps reading.
func TestSTRIDEF004EstimatorScope(t *testing.T) {
	f := strideF004Fixture(t)
	for _, u := range []string{"dana", "sam"} {
		if got := f.ea.call(t, "GET", u, "/api/v1/estimates/inbox/"+f.rid, nil); got.code != 200 {
			t.Fatalf("%s before: %d", u, got.code)
		}
	}
	if got := f.ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+f.rid, map[string]any{"remove_estimators": []any{f.dana}, "reason": "Left the team"}); got.code != 200 {
		t.Fatalf("remove: %d %s", got.code, got.raw)
	}
	f.ra.mustOwner(revoke("platform", "sam", "Estimator", "A"))
	f.ra.drain()
	for _, u := range []string{"dana", "sam"} {
		if got := f.ea.call(t, "GET", u, "/api/v1/estimates/inbox/"+f.rid, nil); got.code != 404 {
			t.Errorf("%s reads after losing access: %d %s", u, got.code, got.raw)
		}
		if got := f.ea.call(t, "GET", u, "/api/v1/estimates/inbox", nil); strings.Contains(got.raw, f.rid) {
			t.Errorf("%s's inbox still lists it: %s", u, got.raw)
		}
	}
	if got := f.ea.call(t, "PUT", "dana", "/api/v1/estimates/inbox/"+f.rid+"/answers", map[string]any{"submit": true,
		"answers": []any{map[string]any{"pointer": f.cf, "declined": "x"}}}); got.code != 404 {
		t.Errorf("a removed estimator answers: %d", got.code)
	}
	// Their answers stay with the request.
	if got := f.ra.adminQuery("SELECT count(DISTINCT estimator) FROM estimate.answer WHERE request_id = '" + f.rid + "'"); got != "2" {
		t.Fatalf("answers kept: %s", got)
	}
	// Estimators at another BU are not addressed by this one's requests.
	if got := f.ea.call(t, "GET", "rhea", "/api/v1/estimates/inbox/"+f.rid, nil); got.code != 200 {
		t.Fatalf("rhea: %d", got.code)
	}
	f.ra.mustOwner(revoke("platform", "rhea", "Estimator", "A"))
	f.ra.mustOwner(grant("platform", "user:rhea", "Estimator", "B"))
	f.ra.drain()
	if got := f.ea.call(t, "GET", "rhea", "/api/v1/estimates/inbox/"+f.rid, nil); got.code != 404 {
		t.Errorf("an estimator moved to B: %d", got.code)
	}
}

// I: question answers reach a person taking an exercise.
func TestSTRIDEF004QuestionSecrecy(t *testing.T) {
	f := strideF004Fixture(t)
	for _, tbl := range []string{"question", "question_set", "exercise", "exercise_answer"} {
		f.ra.mustFail("app_rw", "SELECT 1 FROM estimate."+tbl+" LIMIT 1", "permission denied")
	}
	got := f.ea.call(t, "POST", "dana", "/api/v1/calibration/exercises", map[string]any{})
	if got.code != 200 {
		t.Fatalf("start: %d %s", got.code, got.raw)
	}
	exID := got.body["id"].(string)
	qs := got.body["questions"].([]any)
	for _, raw := range []string{got.raw, f.ea.call(t, "GET", "dana", "/api/v1/calibration/exercises/"+exID, nil).raw} {
		if strings.Contains(raw, `"answer"`) || strings.Contains(raw, `"source"`) {
			t.Fatalf("an unsubmitted exercise holds answers: %s", raw[:min(len(raw), 400)])
		}
	}
	// Another person cannot open it, nor managers' views.
	if got := f.ea.call(t, "GET", "sam", "/api/v1/calibration/exercises/"+exID, nil); got.code != 404 {
		t.Errorf("another person's exercise: %d", got.code)
	}
	first := qs[0].(map[string]any)["id"].(string)
	for _, path := range []string{"/api/v1/calibration/question-sets", "/api/v1/calibration/question-sets/" + first} {
		if got := f.ea.call(t, "GET", "dana", path, nil); got.code != 404 {
			t.Errorf("dana GET %s: %d", path, got.code)
		}
	}
	// After submitting, the truths and sources.
	answers := make([]any, len(qs))
	for i, q := range qs {
		m := q.(map[string]any)
		if m["kind"] == "range" {
			answers[i] = map[string]any{"id": m["id"], "low": "0", "high": "1"}
		} else {
			answers[i] = map[string]any{"id": m["id"], "choice": true, "confidence": "0.5"}
		}
	}
	if got := f.ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+exID+"/submit", map[string]any{"answers": answers}); got.code != 200 ||
		strings.Count(got.raw, `"source"`) != len(qs) {
		t.Fatalf("submitted: %d %s", got.code, got.raw[:min(len(got.raw), 300)])
	}
}

// I: calibration records are exposed.
func TestSTRIDEF004CalibrationPrivacy(t *testing.T) {
	f := strideF004Fixture(t)
	f.ra.admin(f.ra.db, fmt.Sprintf(`INSERT INTO estimate.score (user_id, score) VALUES ('%s', '{"class":"overconfident","ranges":{"n":20,"hits":12,"rate":"0.6","band":[16,20],"class":"overconfident"}}')`, f.dana))
	person := "/api/v1/calibration/people/" + f.dana
	// Not to a viewer, nor an analyst where Dana is no estimator, nor without a BU.
	for _, c := range []struct{ user, query string }{{"viewer", "?bu=" + f.ra.bu["A"]}, {"mallory", "?bu=" + f.ra.bu["B"]}, {"analyst", ""}, {"sam", "?bu=" + f.ra.bu["A"]}} {
		if got := f.ea.call(t, "GET", c.user, person+c.query, nil); got.code != 404 {
			t.Errorf("%s%s: %d %s", c.user, c.query, got.code, got.raw)
		}
	}
	// An analyst where Dana estimates: class and hit rate only.
	got := f.ea.call(t, "GET", "analyst", person+"?bu="+f.ra.bu["A"], nil)
	if got.code != 200 || !strings.Contains(got.raw, `"overconfident"`) || strings.Contains(got.raw, "history") || strings.Contains(got.raw, "hits") || strings.Contains(got.raw, "exercise") {
		t.Fatalf("analyst: %d %s", got.code, got.raw)
	}
	// An auditor: scores and history, never exercises or answers.
	got = f.ea.call(t, "GET", "auditor", person, nil)
	if got.code != 200 || !strings.Contains(got.raw, `"history"`) || strings.Contains(got.raw, "exercise") {
		t.Fatalf("auditor: %d %s", got.code, got.raw)
	}
	// Every view recorded.
	if got := f.ra.adminQuery(`SELECT string_agg(body -> 'attributes' ->> 'as', ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' = 'calibration.record_viewed' AND body ->> 'target' = 'user:` + f.dana + `'`); got != "requester,auditor" {
		t.Fatalf("views recorded: %s", got)
	}
	// One's own record is one's own.
	if got := f.ea.call(t, "GET", "sam", "/api/v1/calibration/me", nil); got.code != 200 || strings.Contains(got.raw, "overconfident") {
		t.Fatalf("sam's record: %d %s", got.code, got.raw)
	}
	// Retention: records past the period are purged, the latest score kept
	// (TestCalibration covers the job).
	f.ra.admin(f.ra.db, fmt.Sprintf(`UPDATE estimate.score SET computed_at = now() - interval '6 years' WHERE user_id = '%[1]s';
		INSERT INTO estimate.score (user_id, computed_at, score) VALUES ('%[1]s', now() - interval '5 years 6 months', '{"class":"not_measured"}')`, f.dana))
	if err := f.ra.psqlAs(nil, f.ra.db, "SELECT estimate.purge_calibration(interval '5 years')"); err != nil {
		t.Fatal(err)
	}
	if got := f.ra.adminQuery("SELECT count(*) FROM estimate.score WHERE user_id = '" + f.dana + "'"); got != "1" {
		t.Fatalf("purged: %s", got)
	}
}

// D: request, answer or exercise floods.
func TestEstimateLimits(t *testing.T) {
	f := strideF004Fixture(t)
	due := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	many := func(n int, f func(i int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	uuid := func(i int) any { return fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i) }
	for name, body := range map[string]map[string]any{
		"61 factors":     {"scenario_id": f.sid, "title": "x", "due_at": due, "factors": many(61, func(i int) any { return fmt.Sprintf("/x%d", i) }), "estimators": []any{f.dana}},
		"51 estimators":  {"scenario_id": f.sid, "title": "x", "due_at": due, "factors": []any{f.cf}, "estimators": many(51, uuid)},
		"21 references":  {"scenario_id": f.sid, "title": "x", "due_at": due, "factors": []any{f.cf}, "estimators": []any{f.dana}, "references": many(21, func(i int) any { return map[string]any{"id": uuid(i), "version": 1} })},
		"a long title":   {"scenario_id": f.sid, "title": strings.Repeat("x", 201), "due_at": due, "factors": []any{f.cf}, "estimators": []any{f.dana}},
		"a huge request": {"scenario_id": f.sid, "title": "x", "due_at": due, "factors": []any{f.cf}, "estimators": []any{f.dana}, "instructions": strings.Repeat("x", 70_000)},
	} {
		if got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", body); got.code < 400 || got.code >= 500 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	// Per scenario at most 20 open requests (the 21st refused).
	for i := 2; i <= 21; i++ {
		got := f.ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": f.sid, "title": fmt.Sprintf("Again %d", i), "due_at": due,
			"factors": []any{f.cf}, "estimators": []any{f.dana}})
		if i <= 20 && got.code != 201 || i == 21 && (got.code < 400 || got.code >= 500) {
			t.Fatalf("open request %d: %d %s", i, got.code, got.raw)
		}
	}
	// Answers: at most 100 revisions per factor; a body over 64 KiB refused.
	if got := f.ea.call(t, "PUT", "dana", "/api/v1/estimates/inbox/"+f.rid+"/answers", map[string]any{"submit": false,
		"answers": []any{map[string]any{"pointer": f.cf, "declined": strings.Repeat("x", 70_000)}}}); got.code != 400 {
		t.Errorf("a huge answer: %d", got.code)
	}
	if err := f.ra.tx("dana", func(tx pgx.Tx) error {
		for i := 0; i < 100; i++ {
			if _, err := tx.Exec(context.Background(), "SELECT estimate.save_answer($1, $2, NULL, 'again', false)", f.rid, f.cf); err != nil {
				return err
			}
		}
		return nil
	}); !strings.Contains(pgCode(err), "violates") && !strings.HasPrefix(pgCode(err), "PF022") {
		t.Errorf("revision 101: %s", pgCode(err))
	}
	// Exercises: sizes and settings within their bounds, at most 50 answers.
	for _, q := range []string{"SELECT estimate.start_exercise(5, interval '1 day')", "SELECT estimate.start_exercise(51, interval '1 day')",
		"SELECT estimate.submit_exercise(gen_random_uuid(), '[]', interval '1 day', 20)", "SELECT estimate.submit_exercise(gen_random_uuid(), '[]', interval '365 days', 3)"} {
		if err := f.ra.tx("dana", func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), q); return err }); !strings.HasPrefix(pgCode(err), "PF022") {
			t.Errorf("%s: %s", q, pgCode(err))
		}
	}
	if got := f.ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+uuid(1).(string)+"/submit", map[string]any{"answers": many(51, func(i int) any { return map[string]any{"id": uuid(i)} })}); got.code != 400 {
		t.Errorf("51 exercise answers: %d", got.code)
	}
}

// E: an estimator edits the scenario or accepts answers.
func TestSTRIDEF004Escalation(t *testing.T) {
	f := strideF004Fixture(t)
	if got := f.ra.adminQuery(`SELECT array_to_string(ARRAY(SELECT unnest(v.permissions) ORDER BY 1), ',') FROM iam.role r
		JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version WHERE r.name = 'Estimator'`); got != "calibration.take,estimate.submit" {
		t.Fatalf("the Estimator role: %s", got)
	}
	read := f.ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+f.sid, nil)
	doc := read.body["version"].(map[string]any)["document"]
	for name, c := range map[string]struct {
		api          *riskAPIEnv
		method, path string
		body         any
	}{
		"accept":            {f.ea, "POST", "/api/v1/estimates/requests/" + f.rid + "/accept", map[string]any{"expected_version": 1, "change_note": "x", "factors": []any{map[string]any{"pointer": f.cf, "method": "single", "estimators": []any{f.dana}}}}},
		"send a request":    {f.ea, "POST", "/api/v1/estimates/requests", map[string]any{"scenario_id": f.sid, "title": "x", "due_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "factors": []any{f.cf}, "estimators": []any{f.dana}}},
		"change it":         {f.ea, "PATCH", "/api/v1/estimates/requests/" + f.rid, map[string]any{"add_estimators": []any{f.dana}}},
		"cancel it":         {f.ea, "POST", "/api/v1/estimates/requests/" + f.rid + "/cancel", map[string]any{"reason": "x"}},
		"list estimators":   {f.ea, "GET", "/api/v1/estimates/estimators?bu=" + f.ra.bu["A"], nil},
		"edit the scenario": {f.ra, "PUT", "/api/v1/scenarios/" + f.sid, map[string]any{"document": doc, "expected_version": 1, "change_note": "x"}},
	} {
		if got := c.api.call(t, c.method, "dana", c.path, c.body); got.code != 404 && got.code != 403 {
			t.Errorf("an estimator may %s: %d %s", name, got.code, got.raw)
		}
	}
	// A viewer (scenario.view, no estimate.request) cannot accept either.
	if got := f.ea.call(t, "POST", "viewer", "/api/v1/estimates/requests/"+f.rid+"/accept", map[string]any{"expected_version": 1, "change_note": "x",
		"factors": []any{map[string]any{"pointer": f.cf, "method": "equal"}}}); got.code != 403 {
		t.Errorf("a viewer accepts: %d", got.code)
	}
	if got := f.ra.adminQuery("SELECT current_version FROM risk.scenario WHERE id = '" + f.sid + "'"); got != "1" {
		t.Fatalf("the scenario changed: version %s", got)
	}
}

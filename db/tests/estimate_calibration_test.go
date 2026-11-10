package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/estimateapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

type fakeSettings struct {
	ints map[string]int
	durs map[string]time.Duration
}

func (f fakeSettings) Int(key, _ string) (int, error) {
	if v, ok := f.ints[key]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unset %s", key)
}

func (f fakeSettings) Duration(key, _ string) (time.Duration, error) {
	if v, ok := f.durs[key]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unset %s", key)
}

// F-004 T-10 (F-004-AC-20 to AC-23, AC-27 to AC-30; design §3.6, §4.2,
// §4.3, §6.5): exercises, scores, visibility, retention.
func TestCalibration(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A (estimate.request), mallory at B
	pool := ra.appPool()
	api := &estimateapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}),
		Settings: fakeSettings{ints: map[string]int{settings.KeyCalibrationExerciseSize: 20, settings.KeyCalibrationMinAnswers: 10},
			durs: map[string]time.Duration{settings.KeyCalibrationReusePeriod: 180 * 24 * time.Hour, settings.KeyCalibrationWindow: 365 * 24 * time.Hour}}}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	ea := *ra
	ea.url, ea.n = srv.URL, 200000
	for _, u := range []string{"dana", "aud", "viewer"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.drain()
	dana := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'dana@example.test'")

	// A question set: 15 range questions (truth 100·i) and 15 true-or-false.
	var q strings.Builder
	q.WriteString("INSERT INTO estimate.question_set (id, origin, name, status, release) VALUES ('bbbbbbbb-0000-4000-8000-000000000000', 'shipped', 'Test set', 'active', 'test');\n")
	for i := 1; i <= 15; i++ {
		fmt.Fprintf(&q, "INSERT INTO estimate.question (id, version, set_id, kind, text, unit, answer, source) VALUES (gen_random_uuid(), 1, 'bbbbbbbb-0000-4000-8000-000000000000', 'range', 'How many %d?', 'units', '%d', 'Source %d');\n", i, 100*i, i)
		fmt.Fprintf(&q, "INSERT INTO estimate.question (id, version, set_id, kind, text, answer, source) VALUES (gen_random_uuid(), 1, 'bbbbbbbb-0000-4000-8000-000000000000', 'binary', 'Is %d even?', '%t', 'Arithmetic');\n", i, i%2 == 0)
	}
	ra.admin(ra.db, q.String())

	// An exercise: questions only, no truths; asking again resumes it.
	got := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises", nil)
	if got.code != 200 || len(got.body["questions"].([]any)) != 20 {
		t.Fatalf("start: %d %s", got.code, got.raw)
	}
	for _, never := range []string{`"answer"`, `"source"`, `"correct"`} {
		if strings.Contains(got.raw, never) {
			t.Fatalf("the exercise shows %s before submission: %s", never, got.raw)
		}
	}
	ex := got.body["id"].(string)
	if again := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises", nil); again.body["id"] != ex {
		t.Fatalf("not resumed: %s", again.raw)
	}
	if got := ea.call(t, "GET", "analyst", "/api/v1/calibration/exercises/"+ex, nil); got.code != 404 {
		t.Fatalf("another person's exercise: %d", got.code)
	}
	kinds := map[string]int{}
	answerAll := func(qs []any, rangeHit bool) []any {
		var out []any
		for _, x := range qs {
			m := x.(map[string]any)
			kinds[m["kind"].(string)]++
			if m["kind"] == "range" {
				lo, hi := "0", "100000"
				if !rangeHit {
					lo, hi = "1", "2"
				}
				out = append(out, map[string]any{"id": m["id"], "low": lo, "high": hi})
				continue
			}
			var n int
			_, _ = fmt.Sscanf(m["text"].(string), "Is %d even?", &n)
			out = append(out, map[string]any{"id": m["id"], "choice": n%2 == 0, "confidence": "0.9"})
		}
		return out
	}
	qs := got.body["questions"].([]any)
	if got := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+ex+"/submit", map[string]any{"answers": answerAll(qs, true)[:19]}); got.code != 409 {
		t.Fatalf("a question left out: %d %s", got.code, got.raw)
	}
	bad := answerAll(qs, true)
	for i, a := range bad {
		if _, ok := a.(map[string]any)["confidence"]; ok {
			bad[i].(map[string]any)["confidence"] = "0.4"
			break
		}
	}
	if got := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+ex+"/submit", map[string]any{"answers": bad}); got.code != 409 {
		t.Fatalf("a confidence below 0.5: %d %s", got.code, got.raw)
	}
	if kinds["range"] != 20 || kinds["binary"] != 20 { // 10 and 10, built twice
		t.Fatalf("kinds %v", kinds)
	}
	got = ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+ex+"/submit", map[string]any{"answers": answerAll(qs, true)})
	if got.code != 200 || !strings.Contains(got.raw, `"source":"Source`) || !strings.Contains(got.raw, `"correct":true`) {
		t.Fatalf("submit: %d %s", got.code, got.raw)
	}
	score := got.body["score"].(map[string]any)
	if score["class"] != "calibrated" || score["ranges"].(map[string]any)["rate"] != "1" {
		t.Fatalf("score: %v", score)
	}
	// The reuse period: the next exercise has the other questions only.
	got = ea.call(t, "POST", "dana", "/api/v1/calibration/exercises", nil)
	if got.code != 200 || len(got.body["questions"].([]any)) != 10 {
		t.Fatalf("second exercise: %d %s", got.code, got.raw)
	}
	for _, x := range got.body["questions"].([]any) {
		for _, y := range qs {
			if x.(map[string]any)["id"] == y.(map[string]any)["id"] {
				t.Fatalf("a question asked again within the reuse period")
			}
		}
	}
	ex2 := got.body["id"].(string)
	if got := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises/"+ex2+"/submit", map[string]any{"answers": answerAll(got.body["questions"].([]any), false)}); got.code != 200 ||
		got.body["score"].(map[string]any)["class"] != "overconfident" {
		t.Fatalf("second submit: %d %s", got.code, got.raw)
	}
	// No questions left: refused.
	if got := ea.call(t, "POST", "dana", "/api/v1/calibration/exercises", nil); got.code != 409 {
		t.Fatalf("no questions left: %d %s", got.code, got.raw)
	}

	// Visibility: the person sees everything; a requester at a shared BU the
	// score only; an auditor scores and history; others nothing. Views of
	// another person's record are recorded.
	if got := ea.call(t, "GET", "dana", "/api/v1/calibration/me", nil); got.code != 200 || len(got.body["exercises"].([]any)) != 2 || len(got.body["history"].([]any)) != 2 {
		t.Fatalf("own record: %d %s", got.code, got.raw)
	}
	got = ea.call(t, "GET", "analyst", "/api/v1/calibration/people/"+dana+"?bu="+ra.bu["A"], nil)
	if got.code != 200 || got.body["score"].(map[string]any)["class"] != "overconfident" || strings.Contains(got.raw, "history") || strings.Contains(got.raw, "exercises") {
		t.Fatalf("a requester's view: %d %s", got.code, got.raw)
	}
	for user, path := range map[string]string{"analyst": "", "mallory": "?bu=" + ra.bu["B"], "viewer": "?bu=" + ra.bu["A"]} {
		if got := ea.call(t, "GET", user, "/api/v1/calibration/people/"+dana+path, nil); got.code != 404 {
			t.Errorf("%s sees dana's record (%s): %d %s", user, path, got.code, got.raw)
		}
	}
	if got := ea.call(t, "GET", "aud", "/api/v1/calibration/people/"+dana, nil); got.code != 200 || len(got.body["history"].([]any)) != 2 {
		t.Fatalf("an auditor's view: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT string_agg(body -> 'attributes' ->> 'as', ',' ORDER BY id) FROM audit.intake WHERE body ->> 'type' = 'calibration.record_viewed'`); got != "requester,auditor" {
		t.Fatalf("views recorded: %s", got)
	}
	if got := ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'calibration.exercise_submitted'`); got != "2" {
		t.Fatalf("submissions recorded: %s", got)
	}

	// Rescoring as the window moves, and the retention purge.
	ctx := context.Background()
	jobs := estimate.Jobs{DB: pool, MinAnswers: func() int { return 10 }}
	if n, _, _, err := jobs.Daily(ctx); err != nil || n != 0 {
		t.Fatalf("rescoring an unchanged window: %d %v", n, err)
	}
	ra.admin(ra.db, "UPDATE estimate.exercise SET started_at = now() - interval '400 days', submitted_at = now() - interval '400 days' WHERE id = '"+ex+"'")
	if n, ex1, sc, err := jobs.Daily(ctx); err != nil || n != 1 || ex1 != 0 || sc != 0 {
		t.Fatalf("rescoring a moved window: %d %d %d %v", n, ex1, sc, err)
	}
	ra.admin(ra.db, "UPDATE estimate.exercise SET started_at = now() - interval '4 years', submitted_at = now() - interval '4 years'; UPDATE estimate.score SET computed_at = computed_at - interval '4 years' WHERE computed_at < (SELECT max(computed_at) FROM estimate.score)")
	if _, ex1, sc, err := jobs.Daily(ctx); err != nil || ex1 != 2 || sc != 2 {
		t.Fatalf("purge: %d exercises, %d scores, %v", ex1, sc, err)
	}
	if got := ra.adminQuery("SELECT (SELECT count(*) FROM estimate.score) || '/' || (SELECT count(*) FROM estimate.exercise_answer)"); got != "2/0" { // the window's rescore (not measured now) and the one before, both within the retention
		t.Fatalf("after the purge: %s", got)
	}

	// Go and SQL score alike: the band, and whole scores.
	var bands []string
	for n := 1; n <= 300; n++ {
		bands = append(bands, fmt.Sprint(estimate.Band(n)))
	}
	sqlBands := ra.adminQuery("SELECT string_agg('[' || b[1] || ' ' || b[2] || ']', ',' ORDER BY n) FROM generate_series(1, 300) n, estimate.band(n) b")
	if sqlBands != strings.Join(bands, ",") {
		t.Fatalf("bands differ:\n SQL %s\n Go  %s", sqlBands, strings.Join(bands, ","))
	}
	for i, c := range []struct {
		ranges, hits, binary, correct int
		conf                          string
	}{
		{25, 20, 0, 0, ""}, {40, 33, 30, 21, "0.7"}, {12, 12, 25, 25, "1"}, {0, 0, 30, 18, "0.85"}, {30, 30, 22, 11, "0.5"}, {9, 3, 9, 2, "0.95"},
	} {
		user := fmt.Sprintf("parity%d", i)
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + user + "@example.test', 'p')")
		uid := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + user + "@example.test'")
		var sql strings.Builder
		fmt.Fprintf(&sql, `INSERT INTO estimate.exercise (id, user_id, questions, submitted_at) VALUES ('cccccccc-0000-4000-8000-%012d', '%s', '[1,2,3,4,5,6,7,8,9,10]', now());`, i, uid)
		var ranges []bool
		var binary []estimate.BinaryAnswer
		for j := 0; j < c.ranges; j++ {
			hit := j < c.hits
			ranges = append(ranges, hit)
			fmt.Fprintf(&sql, `INSERT INTO estimate.exercise_answer (exercise_id, question_id, version, low, high, correct) SELECT 'cccccccc-0000-4000-8000-%012d', gen_random_uuid(), 1, 0, 1, %t;`, i, hit)
		}
		for j := 0; j < c.binary; j++ {
			ok := j < c.correct
			binary = append(binary, estimate.BinaryAnswer{Confidence: c.conf, Correct: ok})
			fmt.Fprintf(&sql, `INSERT INTO estimate.exercise_answer (exercise_id, question_id, version, choice, confidence, correct) SELECT 'cccccccc-0000-4000-8000-%012d', gen_random_uuid(), 1, true, %s, %t;`, i, c.conf, ok)
		}
		ra.admin(ra.db, "SET session_replication_role = replica; "+sql.String()) // synthetic answers without questions
		goScore, _ := json.Marshal(estimate.ScoreOf(ranges, binary, 20))
		sqlScore := ra.adminQuery("SELECT estimate.compute_score('" + uid + "', interval '365 days', 20)")
		var a, b any
		_ = json.Unmarshal(goScore, &a)
		_ = json.Unmarshal([]byte(sqlScore), &b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("score %d differs:\n SQL %s\n Go  %s", i, sqlScore, goScore)
		}
	}
}

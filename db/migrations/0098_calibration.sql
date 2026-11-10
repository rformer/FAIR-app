-- F-004 T-10 (F-004-AC-20 to AC-23, AC-27 to AC-30; design §3.6, §4.2,
-- §4.3, §6.5): calibration exercises, scores, who sees them, retention.
--
-- Exercises, answers and scores are a person's, reached only through these
-- estimate_definer functions, which take the person from the signed
-- context. A question's truth never leaves the database before the person
-- has submitted the exercise that holds it.
--
-- The database scores (estimate.compute_score), exactly as
-- internal/estimate.ScoreOf does, which is its reference (a parity test):
-- ranges against the central 90% binomial band in integers, binary answers
-- by z² against 2.70569601 in decimals. The service passes the settings
-- (exercise size, reuse period, window, minimum answers, retention), each
-- checked against its bounds.
--
-- Visibility (AC-27 to AC-29): a person sees their whole record; a holder
-- of estimate.request at a BU sees the current class and hit rate of a
-- person holding estimate.submit there; a holder of calibration.audit (at
-- the root) sees scores and their history. Every view of another person's
-- record is recorded in the trail, in its transaction.

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- internal/estimate.Band, exactly.
CREATE FUNCTION estimate.band(n integer) RETURNS integer[]
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE total numeric; term numeric := 1; s numeric := 0; lo integer := -1; hi integer := n; k integer;
BEGIN
  IF n IS NULL OR n <= 0 THEN RETURN ARRAY[0, 0]; END IF;
  total := power(10::numeric, n);
  FOR k IN 0 .. n LOOP
    s := s + term;
    IF lo < 0 AND 20 * s > total THEN lo := k; END IF;
    IF 20 * s >= 19 * total THEN hi := k; EXIT; END IF;
    term := div(term * 9 * (n - k), k + 1);
  END LOOP;
  RETURN ARRAY[lo, hi];
END $$;

-- A person's score over the window (internal/estimate.ScoreOf).
CREATE FUNCTION estimate.compute_score(u uuid, win interval, min_answers integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rn integer; rh integer; band integer[]; rclass text := 'not_measured'; rjson jsonb;
  bn integer; bc integer; mu numeric; v numeric; br numeric; diff numeric; outside boolean; bclass text := 'not_measured'; bjson jsonb;
BEGIN
  SELECT count(*)::int, count(*) FILTER (WHERE a.correct)::int INTO rn, rh
  FROM estimate.exercise_answer a JOIN estimate.exercise e ON e.id = a.exercise_id
  WHERE e.user_id = u AND e.submitted_at >= now() - win AND a.low IS NOT NULL;
  band := estimate.band(rn);
  IF rn >= min_answers AND rn > 0 THEN
    rclass := CASE WHEN rh < band[1] THEN 'overconfident' WHEN rh > band[2] THEN 'underconfident' ELSE 'calibrated' END;
  END IF;
  rjson := jsonb_build_object('n', rn, 'hits', rh, 'band', to_jsonb(band), 'class', rclass);
  IF rn > 0 THEN rjson := rjson || jsonb_build_object('rate', estimate.num(round(rh::numeric / rn, 4))); END IF;

  SELECT count(*)::int, count(*) FILTER (WHERE a.correct)::int, coalesce(sum(a.confidence), 0), coalesce(sum(a.confidence * (1 - a.confidence)), 0),
         coalesce(sum((a.confidence - CASE WHEN a.correct THEN 1 ELSE 0 END) ^ 2), 0)
  INTO bn, bc, mu, v, br
  FROM estimate.exercise_answer a JOIN estimate.exercise e ON e.id = a.exercise_id
  WHERE e.user_id = u AND e.submitted_at >= now() - win AND a.choice IS NOT NULL;
  bjson := jsonb_build_object('n', bn, 'correct', bc, 'class', bclass);
  IF bn > 0 THEN
    diff := bc - mu;
    bjson := bjson || jsonb_build_object('expected', estimate.num(round(mu, 4)), 'brier', estimate.num(round(br / bn, 4)));
    IF v > 0 THEN
      outside := diff * diff / v > 2.70569601;
      bjson := bjson || jsonb_build_object('z', estimate.num((round((diff::float8 / sqrt(v::float8)) * 10000) / 10000)::numeric));
    ELSE
      outside := diff <> 0;
    END IF;
    IF bn >= min_answers THEN
      bclass := CASE WHEN outside AND diff < 0 THEN 'overconfident' WHEN outside AND diff > 0 THEN 'underconfident' ELSE 'calibrated' END;
      bjson := bjson || jsonb_build_object('class', bclass);
    END IF;
  END IF;
  RETURN jsonb_build_object('class', CASE WHEN rclass <> 'not_measured' THEN rclass WHEN bclass <> 'not_measured' THEN bclass ELSE 'not_measured' END,
    'ranges', rjson, 'binary', bjson);
END $$;

-- The caller holds calibration.take somewhere.
CREATE FUNCTION estimate.taker() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.actor();
BEGIN
  IF cardinality(coalesce(authz.visible_bus('calibration', 'read'), '{}')) = 0 THEN
    RAISE EXCEPTION 'estimate: calibration exercises need calibration.take' USING ERRCODE = '42501';
  END IF;
  RETURN u;
END $$;

-- An exercise as its person sees it: before submission the questions only;
-- after, each answer against the truth with its source.
CREATE FUNCTION estimate.exercise(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.taker(); e estimate.exercise;
BEGIN
  SELECT * INTO e FROM estimate.exercise x WHERE x.id = exercise.id AND x.user_id = u;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such exercise %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object('id', e.id, 'started_at', e.started_at, 'submitted_at', e.submitted_at,
    'questions', (SELECT jsonb_agg(
        jsonb_build_object('id', q.id, 'version', q.version, 'kind', q.kind, 'text', q.text, 'unit', q.unit)
        || CASE WHEN e.submitted_at IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('answer', q.answer, 'source', q.source,
             'low', a.low, 'high', a.high, 'choice', a.choice, 'confidence', a.confidence, 'correct', a.correct) END
        ORDER BY o.i)
      FROM jsonb_array_elements(e.questions) WITH ORDINALITY o(x, i)
      JOIN estimate.question q ON q.id = (o.x ->> 'id')::uuid AND q.version = (o.x ->> 'version')::int
      LEFT JOIN estimate.exercise_answer a ON a.exercise_id = e.id AND a.question_id = q.id));
END $$;

-- Start an exercise, or resume the unsubmitted one: about half range and
-- half binary questions from the active sets, none answered within the
-- reuse period.
CREATE FUNCTION estimate.start_exercise(size integer, reuse interval) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.taker(); pending uuid; qs jsonb; n integer; id uuid;
BEGIN
  IF size IS NULL OR size < 10 OR size > 50 OR reuse IS NULL OR reuse < interval '0' THEN
    RAISE EXCEPTION 'estimate: an exercise holds 10 to 50 questions' USING ERRCODE = 'PF022';
  END IF;
  SELECT x.id INTO pending FROM estimate.exercise x WHERE x.user_id = u AND x.submitted_at IS NULL ORDER BY x.started_at DESC LIMIT 1;
  IF FOUND THEN RETURN estimate.exercise(pending); END IF;
  WITH avail AS (
    SELECT DISTINCT ON (q.id) q.id, q.version, q.kind
    FROM estimate.question q JOIN estimate.question_set s ON s.id = q.set_id
    WHERE s.status = 'active' AND q.retired_at IS NULL
      AND NOT EXISTS (SELECT 1 FROM estimate.exercise_answer a JOIN estimate.exercise e ON e.id = a.exercise_id
                      WHERE e.user_id = u AND a.question_id = q.id AND e.submitted_at > now() - reuse)
    ORDER BY q.id, q.version DESC),
  ranked AS (SELECT a.*, row_number() OVER (PARTITION BY a.kind ORDER BY random()) AS r FROM avail a),
  picked AS (SELECT * FROM ranked ORDER BY (r > CASE kind WHEN 'range' THEN (size + 1) / 2 ELSE size / 2 END), r, kind LIMIT size)
  SELECT coalesce(jsonb_agg(jsonb_build_object('id', p.id, 'version', p.version) ORDER BY random()), '[]'), count(*)::int INTO qs, n FROM picked p;
  IF n < 10 THEN
    RAISE EXCEPTION 'estimate: not enough calibration questions to make an exercise (% available)', n USING ERRCODE = 'PF022';
  END IF;
  INSERT INTO estimate.exercise (user_id, questions) VALUES (u, qs) RETURNING exercise.id INTO id;
  RETURN estimate.exercise(id);
END $$;

-- Submit an exercise: every question answered once; scored at once.
CREATE FUNCTION estimate.submit_exercise(id uuid, answers jsonb, win interval, min_answers integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := estimate.taker(); e estimate.exercise; o record; a jsonb; q estimate.question;
  lo numeric; hi numeric; ch boolean; cf numeric; score jsonb;
BEGIN
  IF win IS NULL OR win < interval '30 days' OR min_answers IS NULL OR min_answers < 10 THEN
    RAISE EXCEPTION 'estimate: the score window is at least 30 days and the minimum at least 10 answers' USING ERRCODE = 'PF022';
  END IF;
  SELECT * INTO e FROM estimate.exercise x WHERE x.id = submit_exercise.id AND x.user_id = u FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such exercise %', id USING ERRCODE = 'P0002';
  END IF;
  IF e.submitted_at IS NOT NULL THEN
    RAISE EXCEPTION 'estimate: the exercise was submitted' USING ERRCODE = 'PF022';
  END IF;
  IF jsonb_typeof(answers) <> 'array' OR jsonb_array_length(answers) <> jsonb_array_length(e.questions) THEN
    RAISE EXCEPTION 'estimate: answer every question once' USING ERRCODE = 'PF022';
  END IF;
  FOR o IN SELECT x FROM jsonb_array_elements(e.questions) x LOOP
    SELECT * INTO q FROM estimate.question y WHERE y.id = (o.x ->> 'id')::uuid AND y.version = (o.x ->> 'version')::int;
    SELECT z INTO a FROM jsonb_array_elements(answers) z WHERE z ->> 'id' = q.id::text;
    IF a IS NULL OR (SELECT count(*) FROM jsonb_array_elements(answers) z WHERE z ->> 'id' = q.id::text) <> 1 THEN
      RAISE EXCEPTION 'estimate: answer every question once' USING ERRCODE = 'PF022';
    END IF;
    BEGIN
      IF q.kind = 'range' THEN
        lo := risk.decimal(a -> 'low'); hi := risk.decimal(a -> 'high');
        IF lo IS NULL OR hi IS NULL OR lo > hi OR a ? 'choice' THEN RAISE EXCEPTION 'range'; END IF;
        INSERT INTO estimate.exercise_answer (exercise_id, question_id, version, low, high, correct)
        VALUES (e.id, q.id, q.version, lo, hi, q.answer::numeric BETWEEN lo AND hi);
      ELSE
        ch := (a -> 'choice')::text::boolean; cf := risk.decimal(a -> 'confidence');
        IF ch IS NULL OR cf IS NULL OR cf < 0.5 OR cf > 1 OR a ? 'low' THEN RAISE EXCEPTION 'binary'; END IF;
        INSERT INTO estimate.exercise_answer (exercise_id, question_id, version, choice, confidence, correct)
        VALUES (e.id, q.id, q.version, ch, cf, ch = (q.answer = 'true'));
      END IF;
    EXCEPTION WHEN others THEN
      RAISE EXCEPTION 'estimate: question %: a range is a low and a high (decimals, low ≤ high); a true-or-false answer is a choice and a confidence from 0.5 to 1', q.id
        USING ERRCODE = 'PF022';
    END;
  END LOOP;
  UPDATE estimate.exercise x SET submitted_at = now() WHERE x.id = e.id;
  score := estimate.compute_score(u, win, min_answers);
  INSERT INTO estimate.score (user_id, computed_at, score) VALUES (u, clock_timestamp(), score);
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'calibration.exercise_submitted', 'severity', 'info', 'actor', u::text, 'target', 'exercise:' || e.id,
    'attributes', jsonb_build_object('questions', jsonb_array_length(e.questions), 'class', score ->> 'class')));
  RETURN estimate.exercise(e.id) || jsonb_build_object('score', score);
END $$;

-- The caller's own record (AC-27).
CREATE FUNCTION estimate.my_calibration() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.taker();
BEGIN
  RETURN jsonb_build_object(
    'score', (SELECT s.score || jsonb_build_object('computed_at', s.computed_at) FROM estimate.score s WHERE s.user_id = u ORDER BY s.computed_at DESC LIMIT 1),
    'history', coalesce((SELECT jsonb_agg(jsonb_build_object('computed_at', s.computed_at, 'class', s.score ->> 'class', 'rate', s.score #>> '{ranges,rate}')
                ORDER BY s.computed_at) FROM estimate.score s WHERE s.user_id = u), '[]'),
    'exercises', coalesce((SELECT jsonb_agg(jsonb_build_object('id', e.id, 'started_at', e.started_at, 'submitted_at', e.submitted_at,
                  'questions', jsonb_array_length(e.questions),
                  'correct', (SELECT count(*) FROM estimate.exercise_answer a WHERE a.exercise_id = e.id AND a.correct))
                ORDER BY e.started_at DESC) FROM estimate.exercise e WHERE e.user_id = u), '[]'));
END $$;

-- Another person's record, as far as the caller may see it (AC-28, AC-29);
-- recorded in the trail.
CREATE FUNCTION estimate.calibration_of(person uuid, bu uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.actor(); auditor boolean; s jsonb; name text; out jsonb;
BEGIN
  auditor := iam.holds_permission(u, 'calibration.audit', NULL);
  IF NOT auditor AND (bu IS NULL OR NOT iam.holds_permission(u, 'estimate.request', bu) OR NOT iam.holds_permission(person, 'estimate.submit', bu)) THEN
    RAISE EXCEPTION 'estimate: no such person %', person USING ERRCODE = 'P0002';
  END IF;
  SELECT n.display_name INTO name FROM iam.user_display_names(ARRAY[person]) n;
  IF name IS NULL THEN
    RAISE EXCEPTION 'estimate: no such person %', person USING ERRCODE = 'P0002';
  END IF;
  SELECT x.score || jsonb_build_object('computed_at', x.computed_at) INTO s FROM estimate.score x WHERE x.user_id = person ORDER BY x.computed_at DESC LIMIT 1;
  IF auditor THEN
    out := jsonb_build_object('user_id', person, 'name', name, 'score', s,
      'history', coalesce((SELECT jsonb_agg(jsonb_build_object('computed_at', x.computed_at, 'class', x.score ->> 'class', 'rate', x.score #>> '{ranges,rate}')
                  ORDER BY x.computed_at) FROM estimate.score x WHERE x.user_id = person), '[]'));
  ELSE
    out := jsonb_build_object('user_id', person, 'name', name,
      'score', jsonb_build_object('class', coalesce(s ->> 'class', 'not_measured'), 'rate', s #>> '{ranges,rate}', 'computed_at', s ->> 'computed_at'));
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'calibration.record_viewed', 'severity', 'low', 'actor', u::text, 'target', 'user:' || person,
    'attributes', jsonb_build_object('as', CASE WHEN auditor THEN 'auditor' ELSE 'requester' END, 'bu', bu)));
  RETURN out;
END $$;

-- The daily job: rescore everyone whose score the moving window changes.
CREATE FUNCTION estimate.rescore(win interval, min_answers integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; s jsonb; n integer := 0;
BEGIN
  IF win IS NULL OR win < interval '30 days' OR min_answers IS NULL OR min_answers < 10 THEN
    RAISE EXCEPTION 'estimate: the score window is at least 30 days and the minimum at least 10 answers' USING ERRCODE = 'PF022';
  END IF;
  FOR r IN SELECT DISTINCT e.user_id FROM estimate.exercise e WHERE e.submitted_at IS NOT NULL LOOP
    s := estimate.compute_score(r.user_id, win, min_answers);
    IF s IS DISTINCT FROM (SELECT x.score FROM estimate.score x WHERE x.user_id = r.user_id ORDER BY x.computed_at DESC LIMIT 1) THEN
      INSERT INTO estimate.score (user_id, computed_at, score) VALUES (r.user_id, clock_timestamp(), s);
      n := n + 1;
    END IF;
  END LOOP;
  RETURN n;
END $$;

-- The daily job: delete exercises and score history past the retention,
-- keeping each person's latest score (AC-30); recorded when it deletes.
CREATE FUNCTION estimate.purge_calibration(retention interval) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE ex integer; sc integer;
BEGIN
  IF retention IS NULL OR retention < interval '90 days' THEN
    RAISE EXCEPTION 'estimate: calibration records are kept at least 90 days' USING ERRCODE = 'PF022';
  END IF;
  DELETE FROM estimate.exercise e WHERE coalesce(e.submitted_at, e.started_at) < now() - retention;
  GET DIAGNOSTICS ex = ROW_COUNT;
  DELETE FROM estimate.score s WHERE s.computed_at < now() - retention
    AND s.computed_at < (SELECT max(x.computed_at) FROM estimate.score x WHERE x.user_id = s.user_id);
  GET DIAGNOSTICS sc = ROW_COUNT;
  IF ex + sc > 0 THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'calibration.records_purged', 'severity', 'info', 'actor', 'system:risk', 'target', 'calibration',
      'attributes', jsonb_build_object('exercises', ex, 'scores', sc)));
  END IF;
  RETURN jsonb_build_object('exercises', ex, 'scores', sc);
END $$;

REVOKE ALL ON FUNCTION estimate.band(integer), estimate.compute_score(uuid, interval, integer), estimate.taker(), estimate.exercise(uuid),
  estimate.start_exercise(integer, interval), estimate.submit_exercise(uuid, jsonb, interval, integer), estimate.my_calibration(),
  estimate.calibration_of(uuid, uuid), estimate.rescore(interval, integer), estimate.purge_calibration(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.band(integer), estimate.exercise(uuid), estimate.start_exercise(integer, interval),
  estimate.submit_exercise(uuid, jsonb, interval, integer), estimate.my_calibration(), estimate.calibration_of(uuid, uuid),
  estimate.rescore(interval, integer), estimate.purge_calibration(interval) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;
CREATE INDEX exercise_answer_question ON estimate.exercise_answer (question_id);

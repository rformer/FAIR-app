-- F-004 T-08 (F-004-AC-15 to AC-19, AC-31; design §3.4, §3.5, §6.3):
-- accepting answers into a scenario version, verified by the database.
--
-- An accepted estimate's provenance (its elicitation member) is verified
-- when the scenario version is written, by a trigger of estimate_definer on
-- risk.scenario_version (risk.check_document stays a check of the document
-- alone, which the Go validator mirrors):
-- * the request is a request of this scenario, not cancelled, that asked
--   for this factor, at the stated confidence;
-- * every answer used is a submitted revision of that estimator's answer to
--   this factor, with its values and the calibration it was given exactly;
-- * the weights are the method's (1; the calibration weight; 0 for the
--   analyst's own estimate), and the estimate's values are the method's
--   result: the answer itself (single), or round(Σ w·v / Σ w, 12 places)
--   (equal, calibration), digit for digit what internal/estimate.Pool gives.
-- Provenance marked imported came with an import (AC-31): its request is
-- another installation's, so it is not verified here and is shown as such.
-- Library entries and controls carry no provenance. A verified acceptance
-- records which version accepted each factor (AC-19).
--
-- Analysts read a request's submitted answers (never drafts) through
-- estimate.request_answers, with scenario.view at the request's BU.

-- risk.elicitation as in 0093, with the imported marker.
CREATE OR REPLACE FUNCTION risk.elicitation(x jsonb, ptr text, unit text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; n integer; i integer; a jsonb; ap text; c jsonb; w numeric; r numeric; seen text[] := '{}';
BEGIN
  IF jsonb_typeof(x) <> 'object' THEN RETURN risk.p(ptr, 'must be an object'); END IF;
  p := risk.unknown(x, ptr, ARRAY['request', 'method', 'confidence', 'answers', 'imported']);
  IF x ? 'imported' AND jsonb_typeof(x -> 'imported') <> 'boolean' THEN p := p || risk.p(ptr || '/imported', 'must be true or false'); END IF;
  IF NOT coalesce(risk.is_uuid(x -> 'request'), false) THEN p := p || risk.p(ptr || '/request', 'must be a UUID'); END IF;
  p := p || risk.oneof(x -> 'method', ptr || '/method', ARRAY['single', 'equal', 'calibration', 'own'])
         || risk.confidence(x -> 'confidence', ptr || '/confidence', x ? 'confidence');
  n := risk.array_len(x -> 'answers');
  IF n IS NULL THEN RETURN p || risk.p(ptr || '/answers', 'must be an array'); END IF;
  IF n > 50 THEN
    p := p || risk.p(ptr || '/answers', 'at most 50 answers');
  ELSIF (x ->> 'method') = 'single' AND n <> 1 THEN
    p := p || risk.p(ptr || '/answers', 'the single method uses exactly one answer');
  ELSIF (x ->> 'method') IN ('equal', 'calibration') AND n = 0 THEN
    p := p || risk.p(ptr || '/answers', 'a pool uses at least one answer');
  END IF;
  FOR i IN 0 .. n - 1 LOOP
    a := x -> 'answers' -> i;
    ap := format('%s/answers/%s', ptr, i);
    IF jsonb_typeof(a) <> 'object' THEN
      p := p || risk.p(ap, 'must be an object');
      CONTINUE;
    END IF;
    p := p || risk.unknown(a, ap, ARRAY['estimator', 'name', 'revision', 'weight', 'min', 'ml', 'max', 'confidence', 'calibration']);
    IF NOT coalesce(risk.is_uuid(a -> 'estimator'), false) THEN
      p := p || risk.p(ap || '/estimator', 'must be a UUID');
    ELSIF (a ->> 'estimator') = ANY (seen) THEN
      p := p || risk.p(ap || '/estimator', 'the estimator''s answer is listed twice');
    END IF;
    seen := seen || (a ->> 'estimator');
    p := p || risk.text(a -> 'name', ap || '/name', 200, true, false)
           || risk.int(a -> 'revision', ap || '/revision', 1);
    w := risk.decimal(a -> 'weight');
    IF w IS NULL THEN
      p := p || risk.p(ap || '/weight', CASE WHEN a ? 'weight' THEN 'is not a canonical decimal' ELSE 'is required' END);
    ELSIF w < 0 OR w > 1 THEN
      p := p || risk.p(ap || '/weight', 'must be between 0 and 1');
    END IF;
    p := p || risk.triple(a, ap, unit) || risk.confidence(a -> 'confidence', ap || '/confidence', a ? 'confidence');
    c := a -> 'calibration';
    IF jsonb_typeof(c) IS DISTINCT FROM 'object' THEN
      p := p || risk.p(ap || '/calibration', 'is required');
      CONTINUE;
    END IF;
    p := p || risk.unknown(c, ap || '/calibration', ARRAY['class', 'range_rate', 'as_of'])
           || risk.oneof(c -> 'class', ap || '/calibration/class', ARRAY['calibrated', 'overconfident', 'underconfident', 'not_measured']);
    IF c ? 'range_rate' THEN
      r := risk.decimal(c -> 'range_rate');
      IF r IS NULL THEN
        p := p || risk.p(ap || '/calibration/range_rate', 'is not a canonical decimal');
      ELSIF r < 0 OR r > 1 THEN
        p := p || risk.p(ap || '/calibration/range_rate', 'must be between 0 and 1');
      END IF;
    END IF;
    IF risk.as_date(c -> 'as_of') IS NULL THEN
      p := p || risk.p(ap || '/calibration/as_of', 'must be a date (YYYY-MM-DD)');
    END IF;
  END LOOP;
  RETURN p;
END $$;

GRANT EXECUTE ON FUNCTION iam.user_display_names(uuid[]) TO estimate_definer;
GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- internal/estimate.CalibrationWeight.
CREATE FUNCTION estimate.calibration_weight(class text, rate text) RETURNS numeric
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN class = 'calibrated' THEN 1::numeric
              WHEN class = 'not_measured' OR rate IS NULL THEN 0.5
              ELSE greatest(0.1, 1 - 2.5 * abs(rate::numeric - 0.9)) END;
$$;

-- A numeric written as canon.Decimal writes it: no exponent, no trailing
-- zeros, no trailing point.
CREATE FUNCTION estimate.num(x numeric) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN t LIKE '%.%' THEN rtrim(rtrim(t, '0'), '.') ELSE t END FROM (SELECT x::text AS t) s;
$$;

-- internal/estimate.Pool for equal and calibration: round(Σ w·v / Σ w, 12).
CREATE FUNCTION estimate.pooled(w numeric[], v numeric[]) RETURNS numeric
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT round(sum(a.w * a.v) / sum(a.w), 12) FROM unnest(w, v) AS a(w, v);
$$;

-- Every estimate in a document that carries provenance, with its pointer.
CREATE FUNCTION estimate.elicited(j jsonb, ptr text) RETURNS TABLE (pointer text, e jsonb)
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE k text; i integer;
BEGIN
  CASE jsonb_typeof(j)
  WHEN 'object' THEN
    IF jsonb_typeof(j -> 'elicitation') = 'object' THEN
      pointer := ptr; e := j;
      RETURN NEXT;
    END IF;
    FOR k IN SELECT x FROM jsonb_object_keys(j) x WHERE x <> 'elicitation' LOOP
      RETURN QUERY SELECT * FROM estimate.elicited(j -> k, ptr || '/' || replace(replace(k, '~', '~0'), '/', '~1'));
    END LOOP;
  WHEN 'array' THEN
    FOR i IN 0 .. jsonb_array_length(j) - 1 LOOP
      RETURN QUERY SELECT * FROM estimate.elicited(j -> i, ptr || '/' || i);
    END LOOP;
  ELSE
  END CASE;
END $$;

-- The problems with a scenario version's provenance (as 'pointer: message'),
-- marking the factors it accepts when there are none.
CREATE FUNCTION estimate.verify_provenance(scenario uuid, version integer, d jsonb) RETURNS text[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  x record; el jsonb; ptr text; ep text; req uuid; r estimate.request; method text;
  i integer; n integer; a jsonb; ap text; ans estimate.answer; w numeric; f text;
  ws numeric[]; los numeric[]; mls numeric[]; his numeric[];
  p text[] := '{}'; mine text[];
BEGIN
  FOR x IN SELECT * FROM estimate.elicited(d, '') LOOP
    el := x.e -> 'elicitation';
    ptr := x.pointer;
    ep := ptr || '/elicitation';
    IF (el -> 'imported') = 'true'::jsonb OR NOT coalesce(risk.is_uuid(el -> 'request'), false) THEN
      CONTINUE; -- imported, or malformed (risk.check_document reports it)
    END IF;
    mine := '{}';
    req := (el ->> 'request')::uuid;
    SELECT * INTO r FROM estimate.request q WHERE q.id = req AND q.scenario_id = scenario;
    IF NOT FOUND THEN
      p := p || (ep || '/request: is not an estimate request of this scenario');
      CONTINUE;
    END IF;
    IF r.status = 'cancelled' THEN mine := mine || (ep || '/request: the request was cancelled'); END IF;
    IF NOT EXISTS (SELECT 1 FROM estimate.request_factor rf WHERE rf.request_id = req AND rf.pointer = ptr) THEN
      mine := mine || (ep || ': the request did not ask for this factor');
    END IF;
    IF risk.decimal(el -> 'confidence') IS DISTINCT FROM r.confidence THEN
      mine := mine || (ep || '/confidence: is not the request''s confidence');
    END IF;
    method := el ->> 'method';
    ws := '{}'; los := '{}'; mls := '{}'; his := '{}';
    n := coalesce(risk.array_len(el -> 'answers'), 0);
    FOR i IN 0 .. n - 1 LOOP
      a := el -> 'answers' -> i;
      ap := format('%s/answers/%s', ep, i);
      SELECT * INTO ans FROM estimate.answer x2
      WHERE x2.request_id = req AND x2.pointer = ptr AND x2.state = 'submitted' AND x2.estimate IS NOT NULL
        AND x2.estimator::text = (a ->> 'estimator') AND x2.revision::text = (a ->> 'revision');
      IF NOT FOUND THEN
        mine := mine || (ap || ': is not a submitted answer to this factor');
        CONTINUE;
      END IF;
      FOREACH f IN ARRAY ARRAY['min', 'ml', 'max', 'confidence'] LOOP
        IF (a -> f) IS DISTINCT FROM (ans.estimate -> f) THEN
          mine := mine || (ap || '/' || f || ': differs from the answer');
        END IF;
      END LOOP;
      IF (a -> 'calibration') IS DISTINCT FROM ans.calibration THEN
        mine := mine || (ap || '/calibration: is not the estimator''s calibration when they answered');
      END IF;
      w := CASE method WHEN 'calibration' THEN round(estimate.calibration_weight(ans.calibration ->> 'class', ans.calibration ->> 'range_rate'), 12)
                       WHEN 'own' THEN 0 ELSE 1 END;
      IF risk.decimal(a -> 'weight') IS DISTINCT FROM w THEN
        mine := mine || (ap || '/weight: is not the method''s weight');
      END IF;
      IF method IN ('equal', 'calibration') AND risk.decimal(a -> 'confidence') IS DISTINCT FROM r.confidence THEN
        mine := mine || (ap || '/confidence: a pool takes answers at the request''s confidence');
      END IF;
      ws := ws || w; los := los || risk.decimal(a -> 'min'); mls := mls || risk.decimal(a -> 'ml'); his := his || risk.decimal(a -> 'max');
    END LOOP;
    IF cardinality(mine) = 0 THEN
      CASE method
      WHEN 'single' THEN
        FOREACH f IN ARRAY ARRAY['min', 'ml', 'max', 'confidence'] LOOP
          IF (x.e -> f) IS DISTINCT FROM (el -> 'answers' -> 0 -> f) THEN
            mine := mine || (ptr || '/' || f || ': is not the answer''s');
          END IF;
        END LOOP;
      WHEN 'equal', 'calibration' THEN
        IF (x.e ->> 'min') IS DISTINCT FROM estimate.num(estimate.pooled(ws, los)) THEN mine := mine || (ptr || '/min: is not the pool of the answers'); END IF;
        IF (x.e ->> 'ml') IS DISTINCT FROM estimate.num(estimate.pooled(ws, mls)) THEN mine := mine || (ptr || '/ml: is not the pool of the answers'); END IF;
        IF (x.e ->> 'max') IS DISTINCT FROM estimate.num(estimate.pooled(ws, his)) THEN mine := mine || (ptr || '/max: is not the pool of the answers'); END IF;
        IF risk.decimal(x.e -> 'confidence') IS DISTINCT FROM r.confidence THEN mine := mine || (ptr || '/confidence: is not the request''s confidence'); END IF;
      ELSE
      END CASE;
    END IF;
    IF cardinality(mine) = 0 THEN
      UPDATE estimate.request_factor rf SET accepted_version = version, accepted_at = now()
      WHERE rf.request_id = req AND rf.pointer = ptr AND rf.accepted_version IS NULL;
    END IF;
    p := p || mine;
  END LOOP;
  RETURN p;
END $$;

CREATE FUNCTION estimate.provenance_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE d jsonb; problems text[];
BEGIN
  BEGIN
    d := convert_from(NEW.document, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    RETURN NEW; -- risk.check_document refuses it
  END;
  IF TG_TABLE_NAME = 'scenario_version' THEN
    problems := estimate.verify_provenance(NEW.scenario_id, NEW.version, d);
  ELSIF EXISTS (SELECT 1 FROM estimate.elicited(d, '')) THEN
    problems := ARRAY[(SELECT x.pointer FROM estimate.elicited(d, '') x LIMIT 1) || '/elicitation: only a scenario''s estimates carry provenance'];
  END IF;
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'risk.%: the provenance of an accepted estimate does not verify', TG_TABLE_NAME
      USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
  END IF;
  RETURN NEW;
END $$;

-- A request's submitted answers, for analysts (AC-15): every submitted
-- revision, never drafts, with the estimators' names.
CREATE FUNCTION estimate.request_answers(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r estimate.request;
BEGIN
  PERFORM estimate.actor();
  SELECT * INTO r FROM estimate.request q WHERE q.id = request_answers.id;
  IF NOT FOUND OR NOT r.bu_id = ANY (coalesce(authz.visible_bus('scenario', 'read'), '{}')) THEN
    RAISE EXCEPTION 'estimate: no such request %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'estimators', coalesce((SELECT jsonb_agg(jsonb_build_object('user_id', e.user_id, 'name', n.display_name, 'finished_at', e.finished_at,
                    'removed_at', e.removed_at) ORDER BY n.display_name, e.user_id)
                  FROM estimate.request_estimator e
                  LEFT JOIN iam.user_display_names(ARRAY(SELECT e2.user_id FROM estimate.request_estimator e2 WHERE e2.request_id = r.id)) n ON n.id = e.user_id
                  WHERE e.request_id = r.id), '[]'),
    'answers', coalesce((SELECT jsonb_agg(jsonb_build_object('estimator', a.estimator, 'pointer', a.pointer, 'revision', a.revision,
                    'estimate', a.estimate, 'declined', a.declined, 'calibration', a.calibration, 'created_at', a.created_at)
                  ORDER BY a.pointer, a.estimator, a.revision)
                FROM estimate.answer a WHERE a.request_id = r.id AND a.state = 'submitted'), '[]'));
END $$;

REVOKE ALL ON FUNCTION estimate.calibration_weight(text, text), estimate.num(numeric), estimate.pooled(numeric[], numeric[]),
  estimate.elicited(jsonb, text), estimate.verify_provenance(uuid, integer, jsonb), estimate.provenance_before_insert(),
  estimate.request_answers(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.request_answers(uuid) TO app_rw;
-- For the parity test of the pool (Go and SQL give the same digits).
GRANT EXECUTE ON FUNCTION estimate.calibration_weight(text, text), estimate.num(numeric), estimate.pooled(numeric[], numeric[]) TO app_rw;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION estimate.provenance_before_insert() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;

CREATE TRIGGER estimate_provenance BEFORE INSERT ON risk.scenario_version FOR EACH ROW EXECUTE FUNCTION estimate.provenance_before_insert();
CREATE TRIGGER estimate_provenance BEFORE INSERT ON risk.library_version FOR EACH ROW EXECUTE FUNCTION estimate.provenance_before_insert();
CREATE TRIGGER estimate_provenance BEFORE INSERT ON risk.control_version FOR EACH ROW EXECUTE FUNCTION estimate.provenance_before_insert();

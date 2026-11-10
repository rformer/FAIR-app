-- F-004 T-07 (F-004-AC-04, AC-05, AC-07 to AC-10; design §3.3, §4.2, §6.2,
-- §6.7): estimators and their answers, due dates and reminders.
--
-- An estimator reaches a request only through these functions, and only
-- while they are an estimator of it who has not been removed and who holds
-- estimate.submit at its BU (checked on every call; ADR-007 amendment 3).
-- They see the request's text, the shared context, the factors and the
-- pinned reference classes, and their own answers: never the scenario,
-- never another estimator's answers.
--
-- An answer is appended as a revision: a draft only its author sees, or a
-- submitted answer, either an estimate checked as F-003 checks one (no
-- elicitation provenance) or a decline with a reason. Each revision carries
-- the estimator's calibration as it was (design §3.6). The latest submitted
-- revision is the answer. Answers are taken while the request is open or
-- complete and its due date has not passed.
--
-- An estimator who has submitted an answer for every factor is finished:
-- the analyst is told (once). When every estimator still on the request is
-- finished, the request is complete. At its due date a request closes and
-- its estimators are told; reminders go out a lead time before (the leader
-- job of the risk service).

-- F-003's estimate check, for answers.
GRANT EXECUTE ON FUNCTION risk.estimate(jsonb, text, text), risk.unknown(jsonb, text, text[]), risk.p(text, text), risk.triple(jsonb, text, text),
  risk.decimal(jsonb), risk.confidence(jsonb, text, boolean), risk.text(jsonb, text, integer, boolean, boolean), risk.elicitation(jsonb, text, text),
  risk.is_uuid(jsonb), risk.oneof(jsonb, text, text[]), risk.int(jsonb, text, bigint), risk.array_len(jsonb), risk.as_date(jsonb),
  risk.sources(jsonb, text, text) TO estimate_definer;

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- The request, if the caller is a current estimator of it holding
-- estimate.submit at its BU; otherwise "no such request".
CREATE FUNCTION estimate.addressed(id uuid) RETURNS estimate.request
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.actor(); r estimate.request;
BEGIN
  SELECT * INTO r FROM estimate.request q WHERE q.id = addressed.id;
  IF NOT FOUND
     OR NOT EXISTS (SELECT 1 FROM estimate.request_estimator e WHERE e.request_id = r.id AND e.user_id = u AND e.removed_at IS NULL)
     OR NOT iam.holds_permission(u, 'estimate.submit', r.bu_id) THEN
    RAISE EXCEPTION 'estimate: no such request %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN r;
END $$;

-- The requests addressed to the caller, soonest due first.
CREATE FUNCTION estimate.my_requests()
RETURNS TABLE (id uuid, title text, status text, due_at timestamptz, confidence text, scenario_name text, factors integer, answered integer,
               finished_at timestamptz, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT q.id, q.title, q.status, q.due_at, q.confidence::text, q.context ->> 'name',
         (SELECT count(*)::int FROM estimate.request_factor f WHERE f.request_id = q.id),
         (SELECT count(DISTINCT a.pointer)::int FROM estimate.answer a WHERE a.request_id = q.id AND a.estimator = e.user_id AND a.state = 'submitted'),
         e.finished_at, q.created_at
  FROM estimate.request_estimator e JOIN estimate.request q ON q.id = e.request_id
  WHERE e.user_id = estimate.actor() AND e.removed_at IS NULL AND iam.holds_permission(e.user_id, 'estimate.submit', q.bu_id)
  ORDER BY q.status <> 'open', q.due_at, q.id;
$$;

-- One request as its estimator sees it.
CREATE FUNCTION estimate.request_for_estimator(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r estimate.request := estimate.addressed(id); u uuid := estimate.actor();
BEGIN
  RETURN jsonb_build_object(
    'request', jsonb_build_object('id', r.id, 'bu_id', r.bu_id, 'title', r.title, 'instructions', r.instructions, 'confidence', r.confidence::text,
      'due_at', r.due_at, 'status', r.status,
      'finished_at', (SELECT e.finished_at FROM estimate.request_estimator e WHERE e.request_id = r.id AND e.user_id = u)),
    'context', r.context,
    'factors', coalesce((SELECT jsonb_agg(jsonb_build_object('pointer', f.pointer, 'factor', f.factor, 'unit', f.unit, 'definition', f.definition) ORDER BY f.pointer)
                FROM estimate.request_factor f WHERE f.request_id = r.id), '[]'),
    'references', coalesce((SELECT jsonb_agg(jsonb_build_object('id', x.entry_id, 'version', x.version, 'digest', x.digest,
                  'document', convert_from(x.document, 'UTF8')::jsonb) ORDER BY x.entry_id)
                FROM estimate.request_reference x WHERE x.request_id = r.id), '[]'),
    'answers', coalesce((SELECT jsonb_agg(jsonb_build_object('pointer', a.pointer, 'revision', a.revision, 'state', a.state, 'estimate', a.estimate,
                  'declined', a.declined, 'created_at', a.created_at) ORDER BY a.pointer, a.revision)
                FROM estimate.answer a WHERE a.request_id = r.id AND a.estimator = u), '[]'));
END $$;

-- Append a revision of the caller's answer to one factor.
CREATE FUNCTION estimate.save_answer(id uuid, ptr text, est jsonb, declined text, submit boolean) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r estimate.request := estimate.addressed(id);
  u uuid := estimate.actor();
  unit text;
  problems text[];
  rev integer;
  s jsonb;
  cal jsonb;
BEGIN
  IF r.status NOT IN ('open', 'complete') OR r.due_at <= now() THEN
    RAISE EXCEPTION 'estimate: the request is closed to answers' USING ERRCODE = 'PF022';
  END IF;
  SELECT f.unit INTO unit FROM estimate.request_factor f WHERE f.request_id = r.id AND f.pointer = ptr;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: % is not a factor of this request', ptr USING ERRCODE = 'PF022';
  END IF;
  IF submit IS NULL OR num_nonnulls(est, declined) <> 1 THEN
    RAISE EXCEPTION 'estimate: an answer is an estimate or a decline with a reason' USING ERRCODE = 'PF022';
  END IF;
  IF est IS NOT NULL THEN
    IF jsonb_typeof(est) <> 'object' OR est ? 'elicitation' THEN
      RAISE EXCEPTION 'estimate: an answer is an estimate without elicitation provenance' USING ERRCODE = 'PF022';
    END IF;
    problems := risk.estimate(est, '', unit);
    IF cardinality(problems) > 0 THEN
      RAISE EXCEPTION 'estimate: invalid estimate' USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
    END IF;
  ELSE
    problems := risk.text(to_jsonb(declined), '/declined', 1000, true, false);
    IF cardinality(problems) > 0 THEN
      RAISE EXCEPTION 'estimate: invalid decline' USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
    END IF;
  END IF;
  -- The estimator's calibration as it is now (design §3.6).
  SELECT x.score INTO s FROM estimate.score x WHERE x.user_id = u ORDER BY x.computed_at DESC LIMIT 1;
  cal := jsonb_build_object('class', coalesce(s ->> 'class', 'not_measured'), 'as_of', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD'));
  IF s #>> '{ranges,rate}' IS NOT NULL THEN
    cal := cal || jsonb_build_object('range_rate', s #>> '{ranges,rate}');
  END IF;
  SELECT coalesce(max(a.revision), 0) + 1 INTO rev FROM estimate.answer a WHERE a.request_id = r.id AND a.estimator = u AND a.pointer = ptr;
  INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, declined, calibration)
  VALUES (r.id, r.bu_id, u, ptr, rev, CASE WHEN submit THEN 'submitted' ELSE 'draft' END, est, btrim(declined), cal);
  IF submit AND NOT EXISTS (
       SELECT 1 FROM estimate.request_factor f WHERE f.request_id = r.id
       AND NOT EXISTS (SELECT 1 FROM estimate.answer a WHERE a.request_id = r.id AND a.estimator = u AND a.pointer = f.pointer AND a.state = 'submitted')) THEN
    UPDATE estimate.request_estimator e SET finished_at = now() WHERE e.request_id = r.id AND e.user_id = u AND e.finished_at IS NULL;
    IF FOUND THEN
      INSERT INTO estimate.notice_outbox (kind, user_id, request_id) VALUES ('finished', r.created_by, r.id);
      IF r.status = 'open' AND NOT EXISTS (SELECT 1 FROM estimate.request_estimator e
                                            WHERE e.request_id = r.id AND e.removed_at IS NULL AND e.finished_at IS NULL) THEN
        UPDATE estimate.request q SET status = 'complete', ended_at = now() WHERE q.id = r.id;
      END IF;
    END IF;
  END IF;
  RETURN rev;
END $$;

-- The leader's due-date job: close requests past their due date and tell
-- their estimators; recorded in the trail.
CREATE FUNCTION estimate.close_due() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n integer := 0;
BEGIN
  FOR r IN UPDATE estimate.request q SET status = 'closed', ended_at = coalesce(q.ended_at, now())
           WHERE q.status IN ('open', 'complete') AND q.due_at <= now()
           RETURNING q.id, q.bu_id, q.scenario_id LOOP
    INSERT INTO estimate.notice_outbox (kind, user_id, request_id)
    SELECT 'closed', e.user_id, r.id FROM estimate.request_estimator e WHERE e.request_id = r.id AND e.removed_at IS NULL;
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'estimate.request_closed', 'severity', 'low', 'actor', 'system:risk',
      'target', 'estimate_request:' || r.id, 'bu_id', r.bu_id, 'attributes', jsonb_build_object('scenario', r.scenario_id)));
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

-- The leader's reminder job: once per estimator and request, lead before
-- the due date, to estimators who have not finished.
CREATE FUNCTION estimate.queue_reminders(lead interval) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n integer;
BEGIN
  INSERT INTO estimate.notice_outbox (kind, user_id, request_id)
  SELECT 'reminder', e.user_id, q.id
  FROM estimate.request q JOIN estimate.request_estimator e ON e.request_id = q.id
  WHERE q.status = 'open' AND q.due_at - lead <= now() AND q.due_at > now()
    AND e.removed_at IS NULL AND e.finished_at IS NULL
    AND NOT EXISTS (SELECT 1 FROM estimate.notice_outbox o WHERE o.request_id = q.id AND o.user_id = e.user_id AND o.kind = 'reminder');
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION estimate.addressed(uuid), estimate.my_requests(), estimate.request_for_estimator(uuid),
  estimate.save_answer(uuid, text, jsonb, text, boolean), estimate.close_due(), estimate.queue_reminders(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.my_requests(), estimate.request_for_estimator(uuid), estimate.save_answer(uuid, text, jsonb, text, boolean),
  estimate.close_due(), estimate.queue_reminders(interval) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;
CREATE INDEX notice_outbox_request ON estimate.notice_outbox (request_id, user_id, kind);
CREATE INDEX request_due ON estimate.request (due_at) WHERE status IN ('open', 'complete');

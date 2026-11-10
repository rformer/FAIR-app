-- F-004 T-06 (F-004-AC-01 to AC-06; design §5, §6.1, §6.4): changing and
-- cancelling requests, notices, and marking requests affected by changes to
-- their scenario.
--
-- Analysts create requests as app_rw (0094). Changing a due date, removing
-- an estimator and cancelling go through estimate_definer's functions,
-- which take the caller from the signed context and require write scope at
-- the request's BU (the API checks estimate.request too). Adding an
-- estimator is an insert as app_rw, as at creation.
--
-- Every estimator added to a request is sent an "assigned" notice; a
-- cancelled request's estimators a "closed" notice (F-009 delivers them).
--
-- A request is marked affected, once, when its scenario moves to another
-- BU, is archived, or gains a version in which one of the request's factors
-- is no longer estimated (its level changed): nothing is re-pointed
-- (AC-06). The mark is recorded in the trail (estimate.request_affected).

GRANT INSERT ON iam.event_outbox TO estimate_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO estimate_definer;
GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- The caller may change the request: write scope at its BU, from the
-- signed context.
CREATE FUNCTION estimate.writable_request(id uuid) RETURNS estimate.request
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r estimate.request;
BEGIN
  PERFORM estimate.actor();
  SELECT * INTO r FROM estimate.request q WHERE q.id = writable_request.id;
  IF NOT FOUND OR NOT r.bu_id = ANY (coalesce(authz.visible_bus('scenario', 'read'), '{}')) THEN
    RAISE EXCEPTION 'estimate: no such request %', id USING ERRCODE = 'P0002';
  END IF;
  IF NOT r.bu_id = ANY (coalesce(authz.visible_bus('scenario', 'write'), '{}')) THEN
    RAISE EXCEPTION 'estimate: changing a request needs write scope at its business unit' USING ERRCODE = '42501';
  END IF;
  IF r.status <> 'open' THEN
    RAISE EXCEPTION 'estimate: the request is %', r.status USING ERRCODE = 'PF022';
  END IF;
  RETURN r;
END $$;

-- A new due date (ahead), and estimators removed (their answers are kept).
CREATE FUNCTION estimate.change_request(id uuid, due timestamptz, remove uuid[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r estimate.request := estimate.writable_request(id); n integer := 0;
BEGIN
  IF due IS NOT NULL THEN
    IF due <= now() THEN
      RAISE EXCEPTION 'estimate: the due date must be ahead' USING ERRCODE = 'PF022';
    END IF;
    UPDATE estimate.request q SET due_at = due WHERE q.id = r.id;
  END IF;
  IF remove IS NOT NULL THEN
    UPDATE estimate.request_estimator e SET removed_at = now()
    WHERE e.request_id = r.id AND e.user_id = ANY (remove) AND e.removed_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
  END IF;
  RETURN n;
END $$;

-- Cancel with a reason; the estimators are told.
CREATE FUNCTION estimate.cancel_request(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r estimate.request := estimate.writable_request(id);
BEGIN
  UPDATE estimate.request q SET status = 'cancelled', cancel_reason = btrim(reason), ended_at = now() WHERE q.id = r.id;
  INSERT INTO estimate.notice_outbox (kind, user_id, request_id)
  SELECT 'closed', e.user_id, r.id FROM estimate.request_estimator e WHERE e.request_id = r.id AND e.removed_at IS NULL;
END $$;

-- Every estimator added is told (design §6.1).
CREATE FUNCTION estimate.estimator_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO estimate.notice_outbox (kind, user_id, request_id) VALUES ('assigned', NEW.user_id, NEW.request_id);
  RETURN NULL;
END $$;

-- Mark the open requests of a scenario affected (once), and record it.
CREATE FUNCTION estimate.mark_affected(scenario uuid, cause text, only_ids uuid[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; actor text := coalesce(((authz.ctx_scope()).user_id)::text, 'system:risk');
BEGIN
  FOR r IN UPDATE estimate.request q SET affected = cause
           WHERE q.scenario_id = scenario AND q.status = 'open' AND q.affected IS NULL AND (only_ids IS NULL OR q.id = ANY (only_ids))
           RETURNING q.id, q.bu_id LOOP
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'estimate.request_affected', 'severity', 'low', 'actor', actor,
      'target', 'estimate_request:' || r.id, 'bu_id', r.bu_id,
      'attributes', jsonb_build_object('cause', cause, 'scenario', scenario)));
  END LOOP;
END $$;

-- The scenario moved or was archived.
CREATE FUNCTION estimate.scenario_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    PERFORM estimate.mark_affected(NEW.id, 'moved', NULL);
  END IF;
  IF NEW.archived_at IS NOT NULL AND OLD.archived_at IS NULL THEN
    PERFORM estimate.mark_affected(NEW.id, 'archived', NULL);
  END IF;
  RETURN NULL;
END $$;

-- A new version no longer estimates one of a request's factors: a document
-- holds an estimate exactly where its levels require one (F-003 AC-03).
CREATE FUNCTION estimate.version_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE d jsonb := convert_from(NEW.document, 'UTF8')::jsonb; ids uuid[];
BEGIN
  SELECT array_agg(DISTINCT f.request_id) INTO ids
  FROM estimate.request q JOIN estimate.request_factor f ON f.request_id = q.id
  WHERE q.scenario_id = NEW.scenario_id AND q.status = 'open' AND q.affected IS NULL
    AND jsonb_typeof(d #> string_to_array(ltrim(f.pointer, '/'), '/')) IS DISTINCT FROM 'object';
  IF ids IS NOT NULL THEN
    PERFORM estimate.mark_affected(NEW.scenario_id, 'factor_changed', ids);
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION estimate.writable_request(uuid), estimate.change_request(uuid, timestamptz, uuid[]), estimate.cancel_request(uuid, text),
  estimate.estimator_after_insert(), estimate.mark_affected(uuid, text, uuid[]), estimate.scenario_after_update(), estimate.version_after_insert() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.change_request(uuid, timestamptz, uuid[]), estimate.cancel_request(uuid, text) TO app_rw;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION estimate.estimator_after_insert(), estimate.scenario_after_update(), estimate.version_after_insert() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;

CREATE TRIGGER estimator_after_insert AFTER INSERT ON estimate.request_estimator FOR EACH ROW EXECUTE FUNCTION estimate.estimator_after_insert();
CREATE TRIGGER estimate_affected AFTER UPDATE OF bu_id, archived_at ON risk.scenario FOR EACH ROW EXECUTE FUNCTION estimate.scenario_after_update();
CREATE TRIGGER estimate_affected AFTER INSERT ON risk.scenario_version FOR EACH ROW EXECUTE FUNCTION estimate.version_after_insert();

-- F-011 T-08 (F-011-AC-02, AC-06 to AC-09; design §3.2): batches in the
-- risk service (app_rw), for the user named by the signed DB context: a
-- service account holding integration.push, or an administrator holding
-- integration.manage, at the integration's BU.
--
--   * integration.batch_target(id): the integration a batch goes to (kind,
--     mapping); P0002 unless the caller holds integration.push, manage or
--     view at its BU, 42501 with view only; a paused integration refuses
--     batches (PF031 invalid_state), a deleted one too.
--   * integration.resolve_bus(id, refs): the records' business units (by
--     code or id) that are live and inside the integration's subtree on an
--     unblocked path (AC-02).
--   * integration.match(id, external_ids): the links (AC-07).
--   * integration.begin_run(id, trigger, complete): a run, at most 12 an
--     hour per integration (PF032 too_many_runs), one at a time (the
--     integration's row is locked); the trigger is push or upload by the
--     caller's permission, or schedule and manual for the integration's own
--     service account (its connector).
--   * integration.stage(run, records), integration.finish_run(run, counts,
--     refusals): the run's records and its outcome, with integration.run
--     (low) in the same transaction. A dry run calls none of these.
--   * integration.run_get(id): a run, to the holders of view or manage at
--     its integration's BU and to its actor.

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

-- The integration a caller may send batches to, locked.
CREATE FUNCTION integration.pushable(id uuid) RETURNS integration.integration
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = pushable.id FOR UPDATE;
  IF i.id IS NULL OR NOT (iam.holds_permission(u, 'integration.push', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)
                          OR iam.holds_permission(u, 'integration.view', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: no such integration %', id USING ERRCODE = 'P0002';
  END IF;
  IF NOT (iam.holds_permission(u, 'integration.push', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: sending a batch needs integration.push or integration.manage at the integration''s business unit'
      USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF i.state = 'deleted' THEN
    RAISE EXCEPTION 'integration: the integration was deleted' USING ERRCODE = 'PF031', HINT = 'integration_deleted';
  ELSIF i.state = 'paused' THEN
    RAISE EXCEPTION 'integration: the integration is paused; resume it to send batches' USING ERRCODE = 'PF031', HINT = 'invalid_state';
  END IF;
  RETURN i;
END $$;

CREATE FUNCTION integration.batch_target(id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.pushable(id);
BEGIN
  RETURN jsonb_build_object('id', i.id, 'bu_id', i.bu_id, 'kind', i.kind, 'delivery', i.delivery, 'mapping', i.mapping, 'auto_accept', i.auto_accept);
END $$;

CREATE FUNCTION integration.resolve_bus(id uuid, refs text[]) RETURNS TABLE (ref text, bu_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.pushable(id);
BEGIN
  RETURN QUERY SELECT r.ref, b.id FROM unnest(refs) r(ref)
    JOIN iam.bu b ON (b.code = r.ref OR b.id::text = lower(r.ref)) AND b.archived_at IS NULL
    JOIN iam.bu_closure c ON c.ancestor_id = i.bu_id AND c.descendant_id = b.id AND NOT c.blocked;
END $$;

CREATE FUNCTION integration.match(id uuid, external_ids text[])
RETURNS TABLE (external_id text, target_type text, target_id uuid, last_digest text, rejected_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.pushable(id);
BEGIN
  RETURN QUERY SELECT l.external_id, l.target_type, l.target_id, l.last_digest, l.rejected_digest FROM integration.link l
    WHERE l.integration_id = i.id AND l.external_id = ANY (external_ids);
END $$;

CREATE FUNCTION integration.begin_run(id uuid, trigger text, complete boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.pushable(id); t text; r uuid;
BEGIN
  IF trigger IN ('schedule', 'manual') THEN
    IF u IS DISTINCT FROM i.service_account_id THEN
      RAISE EXCEPTION 'integration: only the integration''s own service account sends % runs', trigger USING ERRCODE = 'PF031', HINT = 'invalid_trigger';
    END IF;
    t := trigger;
  ELSIF trigger IS NOT NULL THEN
    RAISE EXCEPTION 'integration: % is not a trigger', trigger USING ERRCODE = 'PF031', HINT = 'invalid_trigger';
  ELSIF iam.holds_permission(u, 'integration.push', i.bu_id) THEN
    t := 'push';
  ELSE
    t := 'upload';
  END IF;
  IF EXISTS (SELECT 1 FROM integration.run x WHERE x.integration_id = i.id AND x.state = 'running') THEN
    RAISE EXCEPTION 'integration: another batch of this integration is being received' USING ERRCODE = 'PF031', HINT = 'run_in_progress';
  END IF;
  IF (SELECT count(*) FROM integration.run x WHERE x.integration_id = i.id AND NOT x.dry_run AND x.started_at > now() - interval '1 hour') >= 12 THEN
    RAISE EXCEPTION 'integration: at most 12 batches an hour per integration' USING ERRCODE = 'PF032', HINT = 'too_many_runs';
  END IF;
  INSERT INTO integration.run (integration_id, trigger, actor, complete) VALUES (i.id, t, u, coalesce(complete, false)) RETURNING run.id INTO r;
  RETURN r;
END $$;

-- The caller's running run.
CREATE FUNCTION integration.my_run(id uuid) RETURNS integration.run
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); r integration.run;
BEGIN
  SELECT * INTO r FROM integration.run x WHERE x.id = my_run.id FOR UPDATE;
  IF r.id IS NULL OR r.actor IS DISTINCT FROM u THEN
    RAISE EXCEPTION 'integration: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  IF r.state <> 'running' THEN
    RAISE EXCEPTION 'integration: the run is finished' USING ERRCODE = 'PF031', HINT = 'run_finished';
  END IF;
  RETURN r;
END $$;

CREATE FUNCTION integration.stage(run uuid, records jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run); n integer;
BEGIN
  IF jsonb_typeof(records) <> 'array' OR jsonb_array_length(records) > 10000 THEN
    RAISE EXCEPTION 'integration: at most 10,000 records in a run' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  INSERT INTO integration.record (run_id, n, kind, external_id, data, digest)
  SELECT r.id, (x ->> 'n')::integer, x ->> 'kind', x ->> 'external_id', x -> 'data', x ->> 'digest' FROM jsonb_array_elements(records) x;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

CREATE FUNCTION integration.run_json(r integration.run) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', r.id, 'integration_id', r.integration_id, 'integration_name', i.name, 'bu_id', i.bu_id, 'trigger', r.trigger,
    'actor', r.actor, 'actor_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = r.actor), 'complete', r.complete, 'state', r.state,
    'counts', r.counts, 'refusals', r.refusals, 'failure', r.failure, 'started_at', r.started_at, 'finished_at', r.finished_at)
  FROM integration.integration i WHERE i.id = r.integration_id;
$$;

CREATE FUNCTION integration.finish_run(run uuid, counts jsonb, refusals jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run); i integration.integration;
BEGIN
  UPDATE integration.run x SET state = 'succeeded', counts = finish_run.counts, refusals = coalesce(finish_run.refusals, '[]'), finished_at = now()
  WHERE x.id = r.id RETURNING * INTO r;
  UPDATE integration.integration x SET last_run_at = now(), failures = 0 WHERE x.id = r.integration_id RETURNING * INTO i;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'integration.run', 'severity', 'low', 'actor', r.actor::text, 'target', 'integration:' || i.id,
    'bu_id', i.bu_id, 'attributes', jsonb_build_object('integration', i.id::text, 'name', i.name, 'run', r.id::text, 'trigger', r.trigger,
      'complete', r.complete::text, 'received', coalesce(counts ->> 'received', '0'), 'valid', coalesce(counts ->> 'valid', '0'),
      'refused', coalesce(counts ->> 'refused', '0'), 'new', coalesce(counts ->> 'new', '0'), 'changed', coalesce(counts ->> 'changed', '0'),
      'unchanged', coalesce(counts ->> 'unchanged', '0'), 'proposed', coalesce(counts ->> 'proposed', '0'))));
  RETURN integration.run_json(r);
END $$;

CREATE FUNCTION integration.run_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); r integration.run; b uuid;
BEGIN
  SELECT * INTO r FROM integration.run x WHERE x.id = run_get.id;
  SELECT i.bu_id INTO b FROM integration.integration i WHERE i.id = r.integration_id;
  IF r.id IS NULL OR NOT (r.actor = u OR iam.holds_permission(u, 'integration.view', b) OR iam.holds_permission(u, 'integration.manage', b)) THEN
    RAISE EXCEPTION 'integration: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN integration.run_json(r);
END $$;

REVOKE ALL ON FUNCTION integration.pushable(uuid), integration.batch_target(uuid), integration.resolve_bus(uuid, text[]),
  integration.match(uuid, text[]), integration.begin_run(uuid, text, boolean), integration.my_run(uuid), integration.stage(uuid, jsonb),
  integration.run_json(integration.run), integration.finish_run(uuid, jsonb, jsonb), integration.run_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.batch_target(uuid), integration.resolve_bus(uuid, text[]), integration.match(uuid, text[]),
  integration.begin_run(uuid, text, boolean), integration.stage(uuid, jsonb), integration.finish_run(uuid, jsonb, jsonb),
  integration.run_get(uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION integration.run_get(uuid) TO app_integrate;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

-- F-011 T-16 (F-011-AC-01 to AC-05, AC-08; design §3.1, §6.1): what the
-- integrations API (internal/integrateapi, the integrate service) needs
-- beyond migration 0147's functions.
--
--   * app_integrate takes the platform's idempotency store
--     (iam.idempotency_*), as every API.
--   * integration.run_now(id): a holder of integration.manage asks for a
--     connector run now. The integration becomes due at once and remembers
--     who asked (run_requested_by, _at), so the runner (T-17) sends the run
--     as trigger 'manual'; recorded as integration.changed (changes
--     run_requested) in the request's transaction. Active connector
--     integrations only (PF031 invalid_integration, invalid_state).
--   * integration.for_test(id): the integration for a connector test, to a
--     holder of integration.manage only (as integration.managed).
--   * integration.runs(id, before, lim): an integration's runs, newest
--     first, without their refusals (integration.run_get has them), to
--     holders of integration.view or manage at its BU, deleted integrations
--     included (AC-05: runs are kept).
--   * integration.destination_refused(bu, id, host, detail, during): records
--     a refused source (AC-04) in its own transaction, the save or test
--     having been refused. Only a holder of integration.manage at the BU
--     (or the integration's) records one, so the event cannot be forged by
--     anyone else.
--   * integration.json shows run_requested_at.

GRANT USAGE ON SCHEMA iam TO app_integrate;
GRANT EXECUTE ON FUNCTION iam.idempotency_begin(uuid, text, text), iam.idempotency_complete(uuid, text, integer, text, bytea),
  iam.idempotency_abandon(uuid, text) TO app_integrate;

ALTER TABLE integration.integration ADD COLUMN run_requested_by uuid REFERENCES iam.app_user (id);
ALTER TABLE integration.integration ADD COLUMN run_requested_at timestamptz;
ALTER TABLE integration.integration ADD CONSTRAINT integration_run_requested CHECK (
  (run_requested_by IS NULL) = (run_requested_at IS NULL) AND (run_requested_at IS NULL OR delivery = 'connector'));

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE OR REPLACE FUNCTION integration.json(i integration.integration) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', i.id, 'bu_id', i.bu_id, 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = i.bu_id), 'name', i.name,
    'kind', i.kind, 'delivery', i.delivery, 'mapping', i.mapping, 'connector', i.connector, 'service_account_id', i.service_account_id,
    'service_account_name', (SELECT s.name FROM iam.service_account s WHERE s.id = i.service_account_id), 'auto_accept', i.auto_accept,
    'state', i.state, 'version', i.version, 'created_at', i.created_at, 'changed_at', i.changed_at, 'deleted_at', i.deleted_at,
    'next_run_at', i.next_run_at, 'last_run_at', i.last_run_at, 'failures', i.failures, 'run_requested_at', i.run_requested_at,
    'credentials', coalesce((SELECT jsonb_agg(jsonb_build_object('purpose', s.purpose, 'set_at', s.set_at) ORDER BY s.purpose)
                             FROM integration.secret s WHERE s.integration_id = i.id), '[]'));
$$;

CREATE FUNCTION integration.run_now(id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  IF i.delivery <> 'connector' THEN
    RAISE EXCEPTION 'integration: only a connector integration runs on request' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
  END IF;
  IF i.state <> 'active' THEN
    RAISE EXCEPTION 'integration: the integration is paused; resume it first' USING ERRCODE = 'PF031', HINT = 'invalid_state';
  END IF;
  UPDATE integration.integration x SET next_run_at = now(), run_requested_by = u, run_requested_at = now()
  WHERE x.id = i.id RETURNING * INTO i;
  PERFORM integration.emit('integration.changed', u, i, jsonb_build_object('changes', 'run_requested', 'version', i.version::text,
    'auto_accept', i.auto_accept::text));
  RETURN integration.json(i);
END $$;

CREATE FUNCTION integration.for_test(id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.managed(id);
BEGIN
  IF i.delivery <> 'connector' THEN
    RAISE EXCEPTION 'integration: only a connector integration has a source to test' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
  END IF;
  RETURN integration.json(i);
END $$;

CREATE FUNCTION integration.runs(id uuid, before uuid, lim integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration; b integration.run;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = runs.id;
  IF i.id IS NULL OR NOT (iam.holds_permission(u, 'integration.view', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: no such integration %', id USING ERRCODE = 'P0002';
  END IF;
  IF lim IS NULL OR lim NOT BETWEEN 1 AND 201 THEN
    RAISE EXCEPTION 'integration: at most 200 runs a page' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  IF before IS NOT NULL THEN
    SELECT * INTO b FROM integration.run r WHERE r.id = runs.before AND r.integration_id = i.id;
    IF b.id IS NULL THEN
      RAISE EXCEPTION 'integration: no such run %', before USING ERRCODE = 'PF031', HINT = 'invalid_value';
    END IF;
  END IF;
  RETURN coalesce((SELECT jsonb_agg(integration.run_json(r) - 'refusals' ORDER BY r.started_at DESC, r.id DESC)
    FROM (SELECT * FROM integration.run r WHERE r.integration_id = i.id AND NOT r.dry_run
            AND (b.id IS NULL OR (r.started_at, r.id) < (b.started_at, b.id))
          ORDER BY r.started_at DESC, r.id DESC LIMIT lim) r), '[]');
END $$;

CREATE FUNCTION integration.destination_refused(bu uuid, id uuid, host text, detail text, during text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration; b uuid := bu;
BEGIN
  IF during IS NULL OR during NOT IN ('save', 'test') OR host IS NULL OR char_length(host) NOT BETWEEN 1 AND 255 THEN
    RAISE EXCEPTION 'integration: a refusal names its host and when it happened' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  IF id IS NOT NULL THEN
    i := integration.managed(id);
    b := i.bu_id;
  ELSIF NOT EXISTS (SELECT 1 FROM iam.bu x WHERE x.id = b AND x.archived_at IS NULL)
     OR NOT (iam.holds_permission(u, 'integration.manage', b) OR iam.holds_permission(u, 'integration.view', b)) THEN
    RAISE EXCEPTION 'integration: no such business unit %', b USING ERRCODE = 'P0002';
  ELSIF NOT iam.holds_permission(u, 'integration.manage', b) THEN
    RAISE EXCEPTION 'integration: creating an integration needs integration.manage at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'integration.destination_refused', 'severity', 'high', 'actor', u::text,
    'target', CASE WHEN i.id IS NULL THEN 'bu:' || b ELSE 'integration:' || i.id END, 'bu_id', b,
    'attributes', jsonb_build_object('integration', coalesce(i.id::text, ''), 'name', coalesce(i.name, ''), 'host', lower(host),
      'detail', left(coalesce(detail, ''), 500), 'during', during)));
END $$;

REVOKE ALL ON FUNCTION integration.run_now(uuid), integration.for_test(uuid), integration.runs(uuid, uuid, integer),
  integration.destination_refused(uuid, uuid, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.run_now(uuid), integration.for_test(uuid), integration.runs(uuid, uuid, integer),
  integration.destination_refused(uuid, uuid, text, text, text) TO app_integrate;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

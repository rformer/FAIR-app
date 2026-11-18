-- F-011 T-07 (F-011-AC-01 to AC-03, AC-05, AC-26; design §3.1, §5):
-- integrations in the database, for the integrate service (app_integrate)
-- acting for the user named by the signed DB context.
--
--   * integration.add / change / pause / resume / remove: need
--     integration.manage at the integration's BU (iam.holds_permission:
--     grants above a restricted BU do not reach it, F-011-AC-02); a caller
--     who holds only integration.view there is refused 42501, anyone else
--     sees no such integration (P0002). Kind, BU and delivery are fixed; the
--     name, mapping, connector, service account and auto_accept change with
--     expected_version (PF031 stale_version).
--   * A connector names its type (http_json, servicenow_cmdb), an https
--     source, a schedule (15 to 1,440 minutes) and the integration's service
--     account, at the integration's BU or above it on an unblocked path
--     (design §3.3); the host's allow-list check is the service's (Go,
--     with DNS). Other deliveries have no connector.
--   * integration.set_secret / remove_secret: a connector's sealed
--     credentials (sealed and opened in the integrate service; the database
--     never sees them in clear), purposes source and client; never
--     returned by get or list, which say only which are set (AC-03).
--     integration.secret_for_run, for app_integrate's runner, takes no
--     context and is granted to no other role.
--   * integration.get / list: holders of integration.view or manage at the
--     integration's BU.
--   * Events (AC-26) in the change's transaction through integration.emit.

GRANT USAGE ON SCHEMA iam, authz TO integration_definer;
GRANT SELECT (id, parent_id, archived_at, code, name) ON iam.bu TO integration_definer;
GRANT SELECT ON iam.bu_closure TO integration_definer;
GRANT SELECT (id, bu_id, name) ON iam.service_account TO integration_definer;
GRANT SELECT (id, status, display_name) ON iam.app_user TO integration_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO integration_definer;
GRANT INSERT ON iam.event_outbox TO integration_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO integration_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope() TO integration_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'integrations need a valid signed database context' USING ERRCODE = 'PF031', HINT = 'no_context';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION integration.emit(type text, actor uuid, i integration.integration, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'high', 'actor', actor::text, 'target', 'integration:' || i.id, 'bu_id', i.bu_id,
    'attributes', attrs || jsonb_build_object('integration', i.id::text, 'name', i.name)));
$$;

-- The integration id for a manager: P0002 unless the caller holds
-- integration.view or manage at its BU; 42501 with view only.
CREATE FUNCTION integration.managed(id uuid) RETURNS integration.integration
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = managed.id FOR UPDATE;
  IF i.id IS NULL OR NOT (iam.holds_permission(u, 'integration.manage', i.bu_id) OR iam.holds_permission(u, 'integration.view', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: no such integration %', id USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.holds_permission(u, 'integration.manage', i.bu_id) THEN
    RAISE EXCEPTION 'integration: changing an integration needs integration.manage at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF i.state = 'deleted' THEN
    RAISE EXCEPTION 'integration: the integration was deleted' USING ERRCODE = 'PF031', HINT = 'integration_deleted';
  END IF;
  RETURN i;
END $$;

-- A connector's settings and the service account it pushes as.
CREATE FUNCTION integration.check_connector(delivery text, connector jsonb, sa uuid, bu uuid) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE k text; m integer;
BEGIN
  IF delivery <> 'connector' THEN
    IF connector IS NOT NULL THEN
      RAISE EXCEPTION 'integration: only a connector integration has connector settings' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
  ELSE
    IF jsonb_typeof(connector) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'integration: a connector integration needs its connector settings' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    FOR k IN SELECT jsonb_object_keys(connector) LOOP
      IF k NOT IN ('schedule_minutes', 'settings', 'source', 'type') THEN
        RAISE EXCEPTION 'integration: % is not a connector setting', k USING ERRCODE = 'PF031', HINT = 'invalid_integration';
      END IF;
    END LOOP;
    IF NOT (connector ->> 'type') IN ('http_json', 'servicenow_cmdb') OR connector ->> 'type' IS NULL THEN
      RAISE EXCEPTION 'integration: the connector type is http_json or servicenow_cmdb' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    IF jsonb_typeof(connector -> 'source') IS DISTINCT FROM 'string' OR NOT (connector ->> 'source') ~ '^https://[^\s/?#@]+(/[^\s]*)?$'
       OR char_length(connector ->> 'source') > 2048 THEN
      RAISE EXCEPTION 'integration: the source is an https URL of at most 2,048 characters, with no user in it' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    IF jsonb_typeof(connector -> 'schedule_minutes') IS DISTINCT FROM 'number' THEN
      RAISE EXCEPTION 'integration: the schedule is 15 to 1,440 minutes' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    m := (connector ->> 'schedule_minutes')::numeric;
    IF m::numeric <> (connector ->> 'schedule_minutes')::numeric OR m < 15 OR m > 1440 THEN
      RAISE EXCEPTION 'integration: the schedule is 15 to 1,440 minutes' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    IF connector ? 'settings' AND jsonb_typeof(connector -> 'settings') <> 'object' THEN
      RAISE EXCEPTION 'integration: the connector''s settings are an object' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
    IF sa IS NULL THEN
      RAISE EXCEPTION 'integration: a connector pushes as a service account; name one' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
    END IF;
  END IF;
  IF sa IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.service_account s JOIN iam.app_user a ON a.id = s.id AND a.status = 'active'
    JOIN iam.bu_closure c ON c.ancestor_id = s.bu_id AND c.descendant_id = check_connector.bu AND NOT c.blocked
    WHERE s.id = sa) THEN
    RAISE EXCEPTION 'integration: the service account is not an active service account at this business unit or above it' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
  END IF;
END $$;

CREATE FUNCTION integration.add(bu uuid, name text, kind text, delivery text, mapping jsonb, connector jsonb, service_account uuid, auto_accept boolean)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = add.bu AND b.archived_at IS NULL)
     OR NOT (iam.holds_permission(u, 'integration.manage', bu) OR iam.holds_permission(u, 'integration.view', bu)) THEN
    RAISE EXCEPTION 'integration: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.holds_permission(u, 'integration.manage', bu) THEN
    RAISE EXCEPTION 'integration: creating an integration needs integration.manage at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  PERFORM integration.check_connector(delivery, connector, service_account, bu);
  INSERT INTO integration.integration (bu_id, name, kind, delivery, mapping, connector, service_account_id, auto_accept, created_by, next_run_at)
  VALUES (bu, btrim(name), kind, delivery, coalesce(mapping, '{}'), connector, service_account, coalesce(auto_accept, false), u,
          CASE WHEN delivery = 'connector' THEN now() END)
  RETURNING * INTO i;
  PERFORM integration.emit('integration.created', u, i, jsonb_build_object('kind', kind, 'delivery', delivery,
    'auto_accept', i.auto_accept::text, 'service_account', service_account::text));
  RETURN i.id;
END $$;

CREATE FUNCTION integration.change(id uuid, expected_version integer, name text, mapping jsonb, connector jsonb, service_account uuid, auto_accept boolean)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id); changed text[] := '{}';
BEGIN
  IF i.version <> expected_version THEN
    RAISE EXCEPTION 'integration: the integration changed since version %', expected_version USING ERRCODE = 'PF031', HINT = 'stale_version';
  END IF;
  PERFORM integration.check_connector(i.delivery, connector, service_account, i.bu_id);
  IF btrim(name) IS DISTINCT FROM i.name THEN changed := array_append(changed, 'name'); END IF;
  IF coalesce(mapping, '{}') IS DISTINCT FROM i.mapping THEN changed := array_append(changed, 'mapping'); END IF;
  IF connector IS DISTINCT FROM i.connector THEN changed := array_append(changed, 'connector'); END IF;
  IF service_account IS DISTINCT FROM i.service_account_id THEN changed := array_append(changed, 'service_account'); END IF;
  IF coalesce(auto_accept, false) IS DISTINCT FROM i.auto_accept THEN changed := array_append(changed, 'auto_accept'); END IF;
  IF cardinality(changed) = 0 THEN
    RETURN i.version;
  END IF;
  UPDATE integration.integration x SET name = btrim(change.name), mapping = coalesce(change.mapping, '{}'), connector = change.connector,
    service_account_id = change.service_account, auto_accept = coalesce(change.auto_accept, false), version = x.version + 1,
    changed_by = u, changed_at = now(),
    next_run_at = CASE WHEN x.delivery = 'connector' AND x.state = 'active' AND 'connector' = ANY (changed) THEN now() ELSE x.next_run_at END
  WHERE x.id = i.id RETURNING * INTO i;
  PERFORM integration.emit('integration.changed', u, i, jsonb_build_object('changes', array_to_string(changed, ','), 'version', i.version::text,
    'auto_accept', i.auto_accept::text));
  RETURN i.version;
END $$;

CREATE FUNCTION integration.pause(id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  IF i.state <> 'active' THEN
    RAISE EXCEPTION 'integration: the integration is not active' USING ERRCODE = 'PF031', HINT = 'invalid_state';
  END IF;
  UPDATE integration.integration x SET state = 'paused', next_run_at = NULL, version = x.version + 1, changed_by = u, changed_at = now()
  WHERE x.id = i.id RETURNING * INTO i;
  PERFORM integration.emit('integration.paused', u, i, '{}');
END $$;

CREATE FUNCTION integration.resume(id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  IF i.state <> 'paused' THEN
    RAISE EXCEPTION 'integration: the integration is not paused' USING ERRCODE = 'PF031', HINT = 'invalid_state';
  END IF;
  UPDATE integration.integration x SET state = 'active', failures = 0, version = x.version + 1, changed_by = u, changed_at = now(),
    next_run_at = CASE WHEN x.delivery = 'connector' THEN now() END
  WHERE x.id = i.id RETURNING * INTO i;
  PERFORM integration.emit('integration.resumed', u, i, '{}');
END $$;

CREATE FUNCTION integration.remove(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'integration: deleting an integration needs a reason (at most 500 characters)' USING ERRCODE = 'PF031', HINT = 'reason_required';
  END IF;
  DELETE FROM integration.secret s WHERE s.integration_id = i.id;
  UPDATE integration.integration x SET state = 'deleted', deleted_at = now(), next_run_at = NULL, changed_by = u, changed_at = now()
  WHERE x.id = i.id RETURNING * INTO i;
  PERFORM integration.emit('integration.deleted', u, i, jsonb_build_object('reason', btrim(reason)));
END $$;

CREATE FUNCTION integration.set_secret(id uuid, purpose text, key_id text, nonce bytea, ciphertext bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  IF i.delivery <> 'connector' THEN
    RAISE EXCEPTION 'integration: only a connector integration has credentials' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
  END IF;
  INSERT INTO integration.secret (integration_id, purpose, key_id, nonce, ciphertext, set_by)
  VALUES (i.id, purpose, key_id, nonce, ciphertext, u)
  ON CONFLICT ON CONSTRAINT secret_pkey DO UPDATE SET key_id = EXCLUDED.key_id, nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext,
    set_by = EXCLUDED.set_by, set_at = now();
  PERFORM integration.emit('integration.credential_set', u, i, jsonb_build_object('purpose', purpose));
END $$;

CREATE FUNCTION integration.remove_secret(id uuid, purpose text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration := integration.managed(id);
BEGIN
  DELETE FROM integration.secret s WHERE s.integration_id = i.id AND s.purpose = remove_secret.purpose;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'integration: no % credential is set', purpose USING ERRCODE = 'P0002';
  END IF;
  PERFORM integration.emit('integration.credential_removed', u, i, jsonb_build_object('purpose', purpose));
END $$;

CREATE FUNCTION integration.json(i integration.integration) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', i.id, 'bu_id', i.bu_id, 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = i.bu_id), 'name', i.name,
    'kind', i.kind, 'delivery', i.delivery, 'mapping', i.mapping, 'connector', i.connector, 'service_account_id', i.service_account_id,
    'service_account_name', (SELECT s.name FROM iam.service_account s WHERE s.id = i.service_account_id), 'auto_accept', i.auto_accept,
    'state', i.state, 'version', i.version, 'created_at', i.created_at, 'changed_at', i.changed_at, 'deleted_at', i.deleted_at,
    'next_run_at', i.next_run_at, 'last_run_at', i.last_run_at, 'failures', i.failures,
    'credentials', coalesce((SELECT jsonb_agg(jsonb_build_object('purpose', s.purpose, 'set_at', s.set_at) ORDER BY s.purpose)
                             FROM integration.secret s WHERE s.integration_id = i.id), '[]'));
$$;

CREATE FUNCTION integration.get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = get.id;
  IF i.id IS NULL OR NOT (iam.holds_permission(u, 'integration.view', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: no such integration %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN integration.json(i);
END $$;

CREATE FUNCTION integration.list(include_deleted boolean) RETURNS SETOF jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor();
BEGIN
  RETURN QUERY SELECT integration.json(i) FROM integration.integration i
    WHERE (include_deleted OR i.state <> 'deleted')
      AND (iam.holds_permission(u, 'integration.view', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id))
    ORDER BY lower(i.name), i.id;
END $$;

-- The runner's sealed credential (no context: the integrate service opens
-- it with integrate/secrets to run the connector).
CREATE FUNCTION integration.secret_for_run(id uuid, purpose text) RETURNS TABLE (key_id text, nonce bytea, ciphertext bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.key_id, s.nonce, s.ciphertext FROM integration.secret s JOIN integration.integration i ON i.id = s.integration_id
  WHERE s.integration_id = secret_for_run.id AND s.purpose = secret_for_run.purpose AND i.state = 'active';
$$;

REVOKE ALL ON FUNCTION integration.actor(), integration.emit(text, uuid, integration.integration, jsonb), integration.managed(uuid),
  integration.check_connector(text, jsonb, uuid, uuid), integration.add(uuid, text, text, text, jsonb, jsonb, uuid, boolean),
  integration.change(uuid, integer, text, jsonb, jsonb, uuid, boolean), integration.pause(uuid), integration.resume(uuid),
  integration.remove(uuid, text), integration.set_secret(uuid, text, text, bytea, bytea), integration.remove_secret(uuid, text),
  integration.json(integration.integration), integration.get(uuid), integration.list(boolean), integration.secret_for_run(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.add(uuid, text, text, text, jsonb, jsonb, uuid, boolean),
  integration.change(uuid, integer, text, jsonb, jsonb, uuid, boolean), integration.pause(uuid), integration.resume(uuid),
  integration.remove(uuid, text), integration.set_secret(uuid, text, text, bytea, bytea), integration.remove_secret(uuid, text),
  integration.get(uuid), integration.list(boolean), integration.secret_for_run(uuid, text) TO app_integrate;
-- The risk service reads integrations (batches, T-08) as their viewers do.
GRANT EXECUTE ON FUNCTION integration.get(uuid), integration.list(boolean) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

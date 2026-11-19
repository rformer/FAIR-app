-- F-011 T-17c (design §3.3 as amended 2026-11-18): a connector pushes as a
-- service account that authenticates with a client secret; the runner
-- holds no client certificate, so a service account that requires mTLS is
-- refused when a connector integration is saved (PF031
-- invalid_integration), and the form's options leave such accounts out.

GRANT SELECT (auth_method) ON iam.service_account TO integration_definer;

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE OR REPLACE FUNCTION integration.check_connector(delivery text, connector jsonb, sa uuid, bu uuid) RETURNS void
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
    IF EXISTS (SELECT 1 FROM iam.service_account s WHERE s.id = sa AND s.auth_method <> 'client_credentials') THEN
      RAISE EXCEPTION 'integration: a connector''s service account authenticates with a client secret; this one requires mTLS' USING ERRCODE = 'PF031',
        HINT = 'invalid_integration';
    END IF;
  END IF;
  IF sa IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM iam.service_account s JOIN iam.app_user a ON a.id = s.id AND a.status = 'active'
    JOIN iam.bu_closure c ON c.ancestor_id = s.bu_id AND c.descendant_id = check_connector.bu AND NOT c.blocked
    WHERE s.id = sa) THEN
    RAISE EXCEPTION 'integration: the service account is not an active service account at this business unit or above it' USING ERRCODE = 'PF031', HINT = 'invalid_integration';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION integration.options() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); bus uuid[];
BEGIN
  SELECT coalesce(array_agg(b.id), '{}') INTO bus FROM iam.bu b
  WHERE b.archived_at IS NULL AND iam.holds_permission(u, 'integration.manage', b.id);
  RETURN jsonb_build_object(
    'bus', coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.id, 'code', b.code, 'name', b.name) ORDER BY lower(b.name), b.id)
                     FROM iam.bu b WHERE b.id = ANY (bus)), '[]'),
    'service_accounts', coalesce((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'name', s.name, 'bu_id', s.bu_id,
                                    'bu_name', (SELECT x.name FROM iam.bu x WHERE x.id = s.bu_id)) ORDER BY lower(s.name), s.id)
                                  FROM iam.service_account s JOIN iam.app_user a ON a.id = s.id AND a.status = 'active'
                                  AND s.auth_method = 'client_credentials'
                                  WHERE EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = s.bu_id AND c.descendant_id = ANY (bus) AND NOT c.blocked)),
                                 '[]'));
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

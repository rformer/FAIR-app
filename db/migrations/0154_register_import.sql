-- F-011 T-14 (F-011-AC-20 to AC-22; design §3.6): the register import.
--
--   * integration.register_import(bu, label): the BU's file integration of
--     risks for a source label ("Register import: <label>", delivery file),
--     created on first use by a holder of register.edit at the BU (event
--     integration.created), so runs, links, proposals and provenance are
--     an integration's like any other.
--   * integration.pushable admits holders of register.edit at a file
--     integration of risks: their batches are uploads (begin_run).
--   * integration.import_owner(bu, email): the active user with that email
--     who reads the register at the BU (who may own a risk there), for a
--     holder of register.edit at the BU.

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE OR REPLACE FUNCTION integration.pushable(id uuid) RETURNS integration.integration
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration; importer boolean;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = pushable.id FOR UPDATE;
  importer := i.id IS NOT NULL AND i.delivery = 'file' AND i.kind = 'risks' AND iam.holds_permission(u, 'register.edit', i.bu_id);
  IF i.id IS NULL OR NOT (importer OR iam.holds_permission(u, 'integration.push', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)
                          OR iam.holds_permission(u, 'integration.view', i.bu_id)) THEN
    RAISE EXCEPTION 'integration: no such integration %', id USING ERRCODE = 'P0002';
  END IF;
  IF NOT (importer OR iam.holds_permission(u, 'integration.push', i.bu_id) OR iam.holds_permission(u, 'integration.manage', i.bu_id)) THEN
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

CREATE FUNCTION integration.register_import(bu uuid, label text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); i integration.integration; nm text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = register_import.bu AND b.archived_at IS NULL)
     OR NOT iam.holds_permission(u, 'register.edit', bu) THEN
    RAISE EXCEPTION 'integration: importing a register needs register.edit at the business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF label IS NULL OR char_length(btrim(label)) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'integration: the source label is 1 to 100 characters' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  nm := 'Register import: ' || btrim(label);
  SELECT * INTO i FROM integration.integration x
    WHERE x.bu_id = register_import.bu AND x.name = nm AND x.kind = 'risks' AND x.delivery = 'file' AND x.state <> 'deleted'
    ORDER BY x.created_at LIMIT 1;
  IF i.id IS NOT NULL THEN
    RETURN i.id;
  END IF;
  INSERT INTO integration.integration (bu_id, name, kind, delivery, mapping, created_by)
  VALUES (bu, nm, 'risks', 'file', '{}', u) RETURNING * INTO i;
  PERFORM integration.emit('integration.created', u, i, jsonb_build_object('kind', 'risks', 'delivery', 'file',
    'auto_accept', i.auto_accept::text, 'service_account', ''));
  RETURN i.id;
END $$;

CREATE FUNCTION integration.import_owner(bu uuid, email text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor();
BEGIN
  IF NOT iam.holds_permission(u, 'register.edit', bu) THEN
    RAISE EXCEPTION 'integration: importing a register needs register.edit at the business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  RETURN (SELECT a.id FROM iam.app_user a JOIN authz.user_scope s ON s.user_id = a.id
          WHERE lower(a.email) = lower(btrim(import_owner.email)) AND a.status = 'active' AND coalesce((s.read_bus -> 'register') ? bu::text, false)
          LIMIT 1);
END $$;

-- The caller's running run's pending create proposals (the import accepts
-- them in its transaction: new risks are created, not proposed).
CREATE FUNCTION integration.run_creates(run uuid) RETURNS SETOF uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run);
BEGIN
  RETURN QUERY SELECT p.id FROM integration.proposal p WHERE p.run_id = r.id AND p.state = 'pending' AND p.action = 'create' ORDER BY p.seq;
END $$;

-- register.imported, in the import's transaction.
CREATE FUNCTION integration.register_imported(run uuid, label text, counts jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run); i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = r.integration_id;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'register.imported', 'severity', 'low', 'actor', r.actor::text, 'target', 'integration:' || i.id,
    'bu_id', i.bu_id, 'attributes', jsonb_build_object('integration', i.id::text, 'run', r.id::text, 'label', label,
      'rows', coalesce(counts ->> 'valid', '0'), 'created', coalesce(counts ->> 'applied', '0'),
      'proposed', (coalesce((counts ->> 'proposed')::integer, 0) - coalesce((counts ->> 'applied')::integer, 0))::text,
      'unchanged', coalesce(counts ->> 'unchanged', '0'))));
END $$;

REVOKE ALL ON FUNCTION integration.register_import(uuid, text), integration.import_owner(uuid, text), integration.run_creates(uuid),
  integration.register_imported(uuid, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.register_import(uuid, text), integration.import_owner(uuid, text), integration.run_creates(uuid),
  integration.register_imported(uuid, text, jsonb) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

-- F-001 T-29 (AC-57, AC-58; D-OQ5): catalog upgrades and role export/import.
--
--   * New permissions go only to the built-in roles that define them (as
--     before, AC-57), and each one now leaves an admin notice
--     (iam.catalog_notice) until a role.manage holder acknowledges it.
--   * D-OQ5, decided by Robert Former 2026-10-29:
--     - A permission missing from a release is retired, never deleted: it
--       grants nothing, cannot be added to roles, and custom roles holding it
--       get a version without it (audited high, noticed). A later release
--       naming it again restores it.
--     - A release may reclassify a permission (action, privileged,
--       risk_data; the loader still requires approve/admin/export to be
--       privileged): audited high and noticed, with the number of users the
--       change puts in AC-30 conflict. Resource type and introduced_in stay
--       fixed.
--   * Custom role definitions are exported as JSON (format fair.roles.v1)
--     and imported, created or updated as new versions under every rule of
--     T-27 and T-28; the iam API offers a dry run and applies all or nothing.

ALTER TABLE iam.permission ADD COLUMN retired_at timestamptz,
                           ADD COLUMN retired_in_version integer;

-- Permission rows change only in a release sync (reclassification,
-- retirement); they are still never deleted.
DROP TRIGGER permission_immutable ON iam.permission;
CREATE TRIGGER permission_release_update BEFORE UPDATE ON iam.permission
  FOR EACH ROW EXECUTE FUNCTION iam.release_only();
CREATE TRIGGER permission_no_delete BEFORE DELETE ON iam.permission
  FOR EACH ROW EXECUTE FUNCTION iam.append_only();

CREATE TABLE iam.catalog_notice (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  catalog_version  integer     NOT NULL,
  kind             text        NOT NULL CHECK (kind IN ('added', 'retired', 'restored', 'reclassified', 'role_changed')),
  subject          text        NOT NULL,  -- a permission key or a role name
  detail           jsonb       NOT NULL DEFAULT '{}',
  created_at       timestamptz NOT NULL DEFAULT now(),
  acknowledged_at  timestamptz,
  acknowledged_by  uuid        REFERENCES iam.app_user (id)
);
CREATE INDEX catalog_notice_pending ON iam.catalog_notice (created_at) WHERE acknowledged_at IS NULL;
REVOKE ALL ON iam.catalog_notice FROM PUBLIC;

-- Role versions may not use retired permissions (0004's check, extended).
CREATE OR REPLACE FUNCTION iam.role_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.role;
  unknown text;
BEGIN
  SELECT * INTO r FROM iam.role WHERE id = NEW.role_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NEW;  -- the foreign key reports it
  END IF;
  IF r.builtin AND NOT iam.in_release_sync() THEN
    RAISE EXCEPTION 'role: built-in role "%" cannot be edited (clone it instead)', r.name USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.version <> r.current_version + 1 THEN
    RAISE EXCEPTION 'role_version: next version of "%" is %, got %', r.name, r.current_version + 1, NEW.version USING ERRCODE = 'check_violation';
  END IF;
  IF array_position(NEW.permissions, NULL) IS NOT NULL
     OR cardinality(NEW.permissions) <> (SELECT count(DISTINCT p) FROM unnest(NEW.permissions) p) THEN
    RAISE EXCEPTION 'role_version: permissions must be distinct and non-null' USING ERRCODE = 'check_violation';
  END IF;
  SELECT p INTO unknown FROM unnest(NEW.permissions) p
  WHERE NOT EXISTS (SELECT 1 FROM iam.permission WHERE key = p) LIMIT 1;
  IF unknown IS NOT NULL THEN
    RAISE EXCEPTION 'role_version: unknown permission %', unknown USING ERRCODE = 'foreign_key_violation';
  END IF;
  SELECT p INTO unknown FROM unnest(NEW.permissions) p
  WHERE EXISTS (SELECT 1 FROM iam.permission WHERE key = p AND retired_at IS NOT NULL) LIMIT 1;
  IF unknown IS NOT NULL THEN
    RAISE EXCEPTION 'role_version: permission % is retired', unknown USING ERRCODE = 'foreign_key_violation';
  END IF;
  NEW.permissions := ARRAY(SELECT p FROM unnest(NEW.permissions) p ORDER BY p COLLATE "C");
  RETURN NEW;
END $$;

CREATE FUNCTION iam.catalog_audit(event text, subject text, version integer, detail jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', 'system:release', 'target', subject,
    'attributes', jsonb_build_object('catalog_version', version) || coalesce(detail, '{}')));
$$;

-- Applies a release catalog and its built-in roles (payload from
-- catalog.SyncPayload). Idempotent. Returns what changed.
CREATE OR REPLACE FUNCTION iam.sync_release(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  new_version integer := (payload->>'version')::integer;
  old_version integer;
  p jsonb;
  existing iam.permission;
  rl jsonb;
  r iam.role;
  perms text[];
  cur text[];
  missing text;
  conflicts integer;
  added text[] := '{}';
  created text[] := '{}';
  versioned text[] := '{}';
  retired text[] := '{}';
  restored text[] := '{}';
  reclassified text[] := '{}';
  stripped text[] := '{}';
BEGIN
  IF new_version IS NULL OR new_version < 1 THEN
    RAISE EXCEPTION 'sync_release: payload has no valid version' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM set_config('iam.release_sync', 'on', true);
  LOCK TABLE iam.permission_catalog IN EXCLUSIVE MODE;

  SELECT version INTO old_version FROM iam.permission_catalog;
  old_version := coalesce(old_version, 0);
  IF new_version < old_version THEN
    RAISE EXCEPTION 'sync_release: catalog version % is older than installed %', new_version, old_version USING ERRCODE = 'check_violation';
  END IF;

  FOR p IN SELECT * FROM jsonb_array_elements(payload->'permissions') LOOP
    SELECT * INTO existing FROM iam.permission WHERE key = p->>'key';
    IF FOUND THEN
      IF existing.resource_type <> p->>'resource_type' OR existing.introduced_in_version <> (p->>'introduced_in')::integer THEN
        RAISE EXCEPTION 'sync_release: permission % changed its resource type or introduction version', existing.key
          USING ERRCODE = 'check_violation';
      END IF;
      IF existing.retired_at IS NOT NULL THEN
        UPDATE iam.permission SET retired_at = NULL, retired_in_version = NULL WHERE key = existing.key;
        restored := restored || existing.key;
        INSERT INTO iam.catalog_notice (catalog_version, kind, subject) VALUES (new_version, 'restored', existing.key);
        PERFORM iam.catalog_audit('catalog.permission_restored', 'permission:' || existing.key, new_version, NULL);
      END IF;
      -- D-OQ5: reclassification is allowed, audited and noticed.
      IF existing.action::text <> p->>'action' OR existing.privileged <> (p->>'privileged')::boolean
         OR existing.risk_data <> (p->>'risk_data')::boolean THEN
        UPDATE iam.permission SET action = (p->>'action')::iam.permission_action, privileged = (p->>'privileged')::boolean,
          risk_data = (p->>'risk_data')::boolean WHERE key = existing.key;
        -- Holders the new classification puts in AC-30 conflict.
        SELECT count(*) INTO conflicts FROM iam.app_user u
        WHERE u.status = 'active'
          AND EXISTS (SELECT 1 FROM iam.permission k WHERE k.action = 'admin' AND k.key IN (SELECT iam.user_permissions(u.id)))
          AND EXISTS (SELECT 1 FROM iam.permission k WHERE k.risk_data AND k.key IN (SELECT iam.user_permissions(u.id)));
        reclassified := reclassified || existing.key;
        INSERT INTO iam.catalog_notice (catalog_version, kind, subject, detail)
        VALUES (new_version, 'reclassified', existing.key, jsonb_build_object(
          'before', jsonb_build_object('action', existing.action, 'privileged', existing.privileged, 'risk_data', existing.risk_data),
          'after', jsonb_build_object('action', p->>'action', 'privileged', (p->>'privileged')::boolean, 'risk_data', (p->>'risk_data')::boolean),
          'admin_risk_users', conflicts));
        PERFORM iam.catalog_audit('catalog.permission_reclassified', 'permission:' || existing.key, new_version,
          jsonb_build_object('action', p->>'action', 'privileged', (p->>'privileged')::boolean, 'risk_data', (p->>'risk_data')::boolean,
                             'admin_risk_users', conflicts));
      END IF;
    ELSE
      -- A new key belongs to a newer catalog than the installed one, so a
      -- changed catalog always carries a bumped version.
      IF (p->>'introduced_in')::integer > new_version
         OR (old_version > 0 AND (p->>'introduced_in')::integer <= old_version) THEN
        RAISE EXCEPTION 'sync_release: new permission % must be introduced in (%, %]', p->>'key', old_version, new_version USING ERRCODE = 'check_violation';
      END IF;
      INSERT INTO iam.permission (key, resource_type, action, privileged, risk_data, introduced_in_version)
      VALUES (p->>'key', p->>'resource_type', (p->>'action')::iam.permission_action,
              (p->>'privileged')::boolean, (p->>'risk_data')::boolean, (p->>'introduced_in')::integer);
      added := added || (p->>'key');
      IF old_version > 0 THEN
        INSERT INTO iam.catalog_notice (catalog_version, kind, subject, detail)
        VALUES (new_version, 'added', p->>'key', jsonb_build_object('privileged', (p->>'privileged')::boolean,
                'risk_data', (p->>'risk_data')::boolean, 'note', 'not added to custom roles (AC-57)'));
      END IF;
    END IF;
  END LOOP;

  -- D-OQ5: permissions the release no longer has are retired.
  FOR missing IN SELECT k.key FROM iam.permission k
                 WHERE k.retired_at IS NULL AND k.key NOT IN (SELECT e->>'key' FROM jsonb_array_elements(payload->'permissions') e)
                 ORDER BY k.key LOOP
    UPDATE iam.permission SET retired_at = now(), retired_in_version = new_version WHERE key = missing;
    retired := retired || missing;
    INSERT INTO iam.catalog_notice (catalog_version, kind, subject) VALUES (new_version, 'retired', missing);
    PERFORM iam.catalog_audit('catalog.permission_retired', 'permission:' || missing, new_version, NULL);
  END LOOP;

  INSERT INTO iam.permission_catalog (version) VALUES (new_version)
  ON CONFLICT (singleton) DO UPDATE SET version = EXCLUDED.version, synced_at = now();

  FOR rl IN SELECT * FROM jsonb_array_elements(payload->'roles') LOOP
    perms := ARRAY(SELECT x FROM jsonb_array_elements_text(rl->'permissions') x ORDER BY x COLLATE "C");
    SELECT * INTO r FROM iam.role WHERE name = rl->>'name';
    IF NOT FOUND THEN
      INSERT INTO iam.role (name, builtin) VALUES (rl->>'name', true) RETURNING * INTO r;
      created := created || r.name;
    ELSIF NOT r.builtin THEN
      RAISE EXCEPTION 'sync_release: built-in role name "%" is taken by a custom role', r.name USING ERRCODE = 'unique_violation';
    END IF;
    SELECT permissions INTO cur FROM iam.role_version WHERE role_id = r.id AND version = r.current_version;
    IF r.current_version = 0 OR cur IS DISTINCT FROM perms THEN
      INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
      VALUES (r.id, r.current_version + 1, perms, format('release catalog v%s', new_version));
      IF r.current_version > 0 THEN
        versioned := versioned || r.name;
      END IF;
    END IF;
  END LOOP;

  SELECT min(name) INTO missing FROM iam.role
  WHERE builtin AND name NOT IN (SELECT e->>'name' FROM jsonb_array_elements(payload->'roles') e);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'sync_release: built-in role "%" is missing from the release; removal is not supported', missing
      USING ERRCODE = 'feature_not_supported';
  END IF;

  -- Custom roles holding a retired permission get a version without it.
  FOR r IN SELECT x.* FROM iam.role x JOIN iam.role_version v ON v.role_id = x.id AND v.version = x.current_version
           WHERE NOT x.builtin AND x.status <> 'retired'
             AND EXISTS (SELECT 1 FROM unnest(v.permissions) k JOIN iam.permission pk ON pk.key = k AND pk.retired_at IS NOT NULL)
           ORDER BY x.name LOOP
    cur := iam.role_permissions(r.id);
    perms := ARRAY(SELECT k FROM unnest(cur) k WHERE NOT EXISTS (
               SELECT 1 FROM iam.permission pk WHERE pk.key = k AND pk.retired_at IS NOT NULL) ORDER BY k COLLATE "C");
    INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
    VALUES (r.id, r.current_version + 1, perms, format('retired permissions removed by release catalog v%s', new_version));
    stripped := stripped || r.name;
    INSERT INTO iam.catalog_notice (catalog_version, kind, subject, detail)
    VALUES (new_version, 'role_changed', r.name, jsonb_build_object('removed',
      to_jsonb(ARRAY(SELECT k FROM unnest(cur) k WHERE k <> ALL (perms))), 'empty', cardinality(perms) = 0));
    PERFORM iam.catalog_audit('role.updated', 'role:' || r.id, new_version,
      jsonb_build_object('name', r.name, 'removed', to_jsonb(ARRAY(SELECT k FROM unnest(cur) k WHERE k <> ALL (perms)))));
  END LOOP;

  PERFORM set_config('iam.release_sync', 'off', true);
  RETURN jsonb_build_object('version', new_version, 'previous_version', old_version,
    'added_permissions', to_jsonb(added), 'created_roles', to_jsonb(created), 'versioned_roles', to_jsonb(versioned),
    'retired_permissions', to_jsonb(retired), 'restored_permissions', to_jsonb(restored),
    'reclassified_permissions', to_jsonb(reclassified), 'custom_roles_changed', to_jsonb(stripped));
END $$;

-- Notices (the API) -------------------------------------------------------

CREATE FUNCTION iam.catalog_notice_list(pending boolean)
RETURNS TABLE (id uuid, catalog_version integer, kind text, subject text, detail jsonb, created_at timestamptz,
               acknowledged_at timestamptz, acknowledged_by uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY SELECT n.id, n.catalog_version, n.kind, n.subject, n.detail, n.created_at, n.acknowledged_at, n.acknowledged_by
  FROM iam.catalog_notice n WHERE NOT pending OR n.acknowledged_at IS NULL
  ORDER BY n.created_at DESC, n.kind, n.subject LIMIT 1000;
END $$;

CREATE FUNCTION iam.catalog_notice_acknowledge(ids uuid[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.role_actor('role.manage');
  n     integer;
BEGIN
  UPDATE iam.catalog_notice x SET acknowledged_at = now(), acknowledged_by = actor
  WHERE x.id = ANY (ids) AND x.acknowledged_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n > 0 THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'catalog.notices_acknowledged', 'severity', 'info', 'actor', actor::text,
      'target', 'catalog', 'attributes', jsonb_build_object('count', n)));
  END IF;
  RETURN n;
END $$;

-- Export and import (AC-58) -------------------------------------------------

-- Custom roles as a portable document (all when ids is NULL).
CREATE FUNCTION iam.role_export(ids uuid[]) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN jsonb_build_object('format', 'fair.roles.v1', 'catalog_version', (SELECT c.version FROM iam.permission_catalog c),
    'exported_at', now(),
    'roles', coalesce((SELECT jsonb_agg(jsonb_build_object('name', r.name, 'permissions', to_jsonb(v.permissions)) ORDER BY r.name)
                       FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
                       WHERE NOT r.builtin AND r.status <> 'retired' AND (ids IS NULL OR r.id = ANY (ids))), '[]'));
END $$;

-- Imports a document: each role is created, updated (a new version) or
-- left unchanged, under every rule; errors are reported per role. The
-- caller rolls back when it is a dry run or any role failed.
CREATE FUNCTION iam.role_import(doc jsonb, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor  uuid := iam.role_actor('role.manage');
  rl     jsonb;
  rname  text;
  perms  text[];
  r      iam.role;
  diff   jsonb;
  report jsonb := '[]';
  errors integer := 0;
  outcome text;
BEGIN
  IF doc->>'format' IS DISTINCT FROM 'fair.roles.v1' OR jsonb_typeof(doc->'roles') <> 'array' THEN
    RAISE EXCEPTION 'not a fair.roles.v1 document' USING ERRCODE = 'PF004';
  END IF;
  IF jsonb_array_length(doc->'roles') > 500 THEN
    RAISE EXCEPTION 'at most 500 roles per import' USING ERRCODE = 'PF004';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  FOR rl IN SELECT * FROM jsonb_array_elements(doc->'roles') LOOP
    rname := btrim(coalesce(rl->>'name', ''));
    diff := NULL;
    BEGIN
      IF rname = '' OR jsonb_typeof(rl->'permissions') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'each role needs a name and a permissions list' USING ERRCODE = 'PF004';
      END IF;
      perms := ARRAY(SELECT DISTINCT x COLLATE "C" FROM jsonb_array_elements_text(rl->'permissions') x ORDER BY 1);
      SELECT * INTO r FROM iam.role x WHERE x.name = rname;
      IF FOUND AND r.builtin THEN
        RAISE EXCEPTION '"%" is a built-in role', rname USING ERRCODE = 'PF003';
      ELSIF FOUND AND r.status = 'retired' THEN
        RAISE EXCEPTION 'role "%" is retired here', rname USING ERRCODE = 'PF003';
      ELSIF FOUND THEN
        diff := iam.role_diff(r.id, perms);
        IF perms = iam.role_permissions(r.id) THEN
          outcome := 'unchanged';
        ELSE
          PERFORM iam.role_write_version(actor, r.id, perms, reason, 'role.imported');
          outcome := 'updated';
        END IF;
      ELSE
        INSERT INTO iam.role (name, created_by) VALUES (rname, actor) RETURNING * INTO r;
        diff := iam.role_diff(r.id, perms);
        PERFORM iam.role_write_version(actor, r.id, perms, reason, 'role.imported');
        outcome := 'created';
      END IF;
      report := report || jsonb_build_array(jsonb_build_object('name', rname, 'outcome', outcome, 'diff', diff));
    EXCEPTION WHEN OTHERS THEN
      errors := errors + 1;
      report := report || jsonb_build_array(jsonb_build_object('name', rname, 'outcome', 'error', 'error', SQLERRM, 'diff', diff));
    END;
  END LOOP;
  RETURN jsonb_build_object('roles', report, 'errors', errors, 'source_catalog_version', doc->'catalog_version',
    'catalog_version', (SELECT c.version FROM iam.permission_catalog c));
END $$;

-- The role and permission reads show retirement.
DROP FUNCTION iam.permission_list();
CREATE FUNCTION iam.permission_list()
RETURNS TABLE (key text, resource_type text, action text, privileged boolean, risk_data boolean, retired boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY SELECT p.key, p.resource_type, p.action::text, p.privileged, p.risk_data, p.retired_at IS NOT NULL
  FROM iam.permission p ORDER BY p.key;
END $$;

REVOKE ALL ON FUNCTION iam.catalog_audit(text, text, integer, jsonb), iam.catalog_notice_list(boolean),
  iam.catalog_notice_acknowledge(uuid[]), iam.role_export(uuid[]), iam.role_import(jsonb, text), iam.permission_list() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.catalog_notice_list(boolean), iam.catalog_notice_acknowledge(uuid[]), iam.role_export(uuid[]),
  iam.role_import(jsonb, text), iam.permission_list() TO app_rw;

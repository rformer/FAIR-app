-- F-001 T-28 (AC-51, AC-52, AC-54, AC-55, AC-56; design §5.6, §6 /roles,
-- /permissions): custom role administration.
--
--   * role.manage at the root creates, clones (from built-in or custom
--     roles), edits and retires custom roles; built-in roles stay read-only
--     (0004's triggers) and clonable (AC-52).
--   * Every edit is a new role_version (AC-55) against the version the
--     editor saw (expected_version; a stale one is refused). iam.role_diff
--     previews it: permissions added and removed, privileged ones added,
--     the users affected, separation-of-duties conflicts (T-27 blocks them
--     at save) and users who would combine admin with risk-data permissions
--     (AC-30, re-checked here as T-07 asked; refused, as for assignments).
--   * Adding a privileged permission emits a high-severity audit event
--     (AC-54); every change is audited.
--   * A role with live assignments (direct, group or mapped) or live group
--     mappings cannot be retired (AC-56); a retired role takes no versions.

CREATE FUNCTION iam.role_actor(perm text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'role administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF perm IS NOT NULL AND NOT iam.holds_permission(u, perm, NULL) THEN
    RAISE EXCEPTION '% is required', perm USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- Active users holding a live assignment of the role, directly or through a
-- group (mapped assignments are direct).
CREATE FUNCTION iam.role_affected_users(role uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT u.id FROM iam.assignment a
  JOIN iam.app_user u ON (a.principal_kind = 'user' AND u.id = a.principal_id)
                      OR (a.principal_kind = 'group' AND u.id IN (SELECT m.user_id FROM iam.grp_member m WHERE m.grp_id = a.principal_id))
  WHERE a.role_id = role AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now()) AND u.status = 'active';
$$;

-- A user's permissions from roles other than role.
CREATE FUNCTION iam.user_permissions_except(u uuid, role uuid) RETURNS SETOF text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT unnest(v.permissions) FROM iam.assignment a
  JOIN iam.role r ON r.id = a.role_id AND r.status = 'active' AND r.id <> role
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
    AND ((a.principal_kind = 'user' AND a.principal_id = u)
      OR (a.principal_kind = 'group' AND EXISTS (SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = u)));
$$;

-- Users of the role who would hold admin and risk-data permissions if the
-- role had perms (their other roles count too).
CREATE FUNCTION iam.role_ac30_users(role uuid, perms text[]) RETURNS SETOF uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT u FROM iam.role_affected_users(role) u
  WHERE EXISTS (SELECT 1 FROM iam.permission p WHERE p.action = 'admin'
                AND (p.key = ANY (perms) OR p.key IN (SELECT k FROM iam.user_permissions_except(u, role) k)))
    AND EXISTS (SELECT 1 FROM iam.permission p WHERE p.risk_data
                AND (p.key = ANY (perms) OR p.key IN (SELECT k FROM iam.user_permissions_except(u, role) k)));
$$;

-- What saving perms as the role's next version would change (AC-55).
CREATE FUNCTION iam.role_diff(role uuid, perms text[]) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cur  text[];
  new  text[] := ARRAY(SELECT DISTINCT p COLLATE "C" FROM unnest(coalesce(perms, '{}')) p ORDER BY 1);
  unknown text;
BEGIN
  PERFORM iam.role_actor(NULL);
  IF NOT EXISTS (SELECT 1 FROM iam.role r WHERE r.id = role) THEN
    RAISE EXCEPTION 'no role %', role USING ERRCODE = 'P0002';
  END IF;
  SELECT p INTO unknown FROM unnest(new) p WHERE NOT EXISTS (SELECT 1 FROM iam.permission k WHERE k.key = p) LIMIT 1;
  IF unknown IS NOT NULL THEN
    RAISE EXCEPTION 'unknown permission %', unknown USING ERRCODE = 'PF004';
  END IF;
  cur := coalesce(iam.role_permissions(role), '{}');
  RETURN jsonb_build_object(
    'current_version', (SELECT r.current_version FROM iam.role r WHERE r.id = role),
    'added', to_jsonb(ARRAY(SELECT p FROM unnest(new) p WHERE p <> ALL (cur) ORDER BY p COLLATE "C")),
    'removed', to_jsonb(ARRAY(SELECT p FROM unnest(cur) p WHERE p <> ALL (new) ORDER BY p COLLATE "C")),
    'privileged_added', to_jsonb(ARRAY(SELECT p FROM unnest(new) p JOIN iam.permission k ON k.key = p AND k.privileged
                                       WHERE p <> ALL (cur) ORDER BY p COLLATE "C")),
    'affected_users', (SELECT count(*) FROM iam.role_affected_users(role)),
    'sod_conflicts', coalesce((SELECT jsonb_agg(jsonb_build_object('rule_id', v.rule_id, 'permission_a', v.permission_a,
                                                                   'permission_b', v.permission_b))
                               FROM iam.sod_violations(role, new) v
                               WHERE NOT (SELECT r.builtin FROM iam.role r WHERE r.id = role)), '[]'),
    'admin_risk_users', (SELECT count(*) FROM iam.role_ac30_users(role, new)));
END $$;

CREATE FUNCTION iam.role_event(event text, severity text, actor uuid, role uuid, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor::text, 'target', 'role:' || role,
    'reason', reason, 'attributes', jsonb_build_object('name', (SELECT r.name FROM iam.role r WHERE r.id = role)) || coalesce(attrs, '{}')));
$$;

-- Writes version perms of a custom role and audits it (AC-54, AC-55).
CREATE FUNCTION iam.role_write_version(actor uuid, role uuid, perms text[], reason text, event text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     jsonb := iam.role_diff(role, perms);
  r     iam.role;
  users integer;
BEGIN
  SELECT * INTO r FROM iam.role x WHERE x.id = role FOR UPDATE;
  IF r.status = 'retired' THEN
    RAISE EXCEPTION 'role "%" is retired', r.name USING ERRCODE = 'PF003';
  END IF;
  IF cardinality(perms) = 0 THEN
    RAISE EXCEPTION 'a role needs at least one permission' USING ERRCODE = 'PF004';
  END IF;
  users := (d->>'admin_risk_users')::integer;
  IF users > 0 THEN
    RAISE EXCEPTION '% user(s) of role "%" would hold both admin and risk-data permissions; this needs dual approval (AC-30)', users, r.name
      USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.role_version (role_id, version, permissions, changed_by, change_reason)
  VALUES (role, r.current_version + 1, perms, actor, btrim(reason));
  PERFORM iam.role_event(event, 'info', actor, role, btrim(reason),
    jsonb_build_object('version', r.current_version + 1, 'added', d->'added', 'removed', d->'removed', 'affected_users', d->'affected_users'));
  IF jsonb_array_length(d->'privileged_added') > 0 THEN
    PERFORM iam.role_event('role.privileged_added', 'high', actor, role, btrim(reason),
      jsonb_build_object('version', r.current_version + 1, 'permissions', d->'privileged_added'));
  END IF;
  RETURN r.current_version + 1;
END $$;

CREATE FUNCTION iam.role_create(role_name text, perms text[], reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.role_actor('role.manage');
  id    uuid;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.role (name, created_by) VALUES (btrim(role_name), actor) RETURNING iam.role.id INTO id;
  PERFORM iam.role_write_version(actor, id, perms, reason, 'role.created');
  RETURN id;
END $$;

-- Clones a built-in or custom role (its current permissions) under a new name.
CREATE FUNCTION iam.role_clone(source uuid, role_name text, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.role_actor('role.manage');
  perms text[];
  id    uuid;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  perms := iam.role_permissions(source);
  IF perms IS NULL THEN
    RAISE EXCEPTION 'no role %', source USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO iam.role (name, created_by) VALUES (btrim(role_name), actor) RETURNING iam.role.id INTO id;
  PERFORM iam.role_write_version(actor, id, perms, reason, 'role.cloned');
  PERFORM iam.role_event('role.cloned_from', 'info', actor, id, btrim(reason), jsonb_build_object('source', source));
  RETURN id;
END $$;

CREATE FUNCTION iam.role_update(role uuid, perms text[], expected_version integer, reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.role_actor('role.manage');
  r     iam.role;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO r FROM iam.role x WHERE x.id = role FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no role %', role USING ERRCODE = 'P0002';
  END IF;
  IF r.builtin THEN
    RAISE EXCEPTION 'built-in role "%" cannot be edited (clone it instead)', r.name USING ERRCODE = 'PF003';
  END IF;
  IF expected_version IS DISTINCT FROM r.current_version THEN
    RAISE EXCEPTION 'role "%" is at version %, not %; review the change again', r.name, r.current_version, expected_version
      USING ERRCODE = 'PF010';
  END IF;
  IF ARRAY(SELECT DISTINCT p COLLATE "C" FROM unnest(perms) p ORDER BY 1) = iam.role_permissions(role) THEN
    RAISE EXCEPTION 'no change' USING ERRCODE = 'PF003';
  END IF;
  RETURN iam.role_write_version(actor, role, perms, reason, 'role.updated');
END $$;

-- AC-56: only a role nobody holds and no mapping grants can be retired.
CREATE FUNCTION iam.role_retire(role uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.role_actor('role.manage');
  r     iam.role;
  held  integer;
  maps  integer;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO r FROM iam.role x WHERE x.id = role FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no role %', role USING ERRCODE = 'P0002';
  END IF;
  IF r.builtin THEN
    RAISE EXCEPTION 'built-in role "%" cannot be retired', r.name USING ERRCODE = 'PF003';
  END IF;
  IF r.status = 'retired' THEN
    RAISE EXCEPTION 'role "%" is retired already', r.name USING ERRCODE = 'PF003';
  END IF;
  SELECT count(*) INTO held FROM iam.assignment a
  WHERE a.role_id = role AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now());
  SELECT count(*) INTO maps FROM iam.group_role_mapping m WHERE m.role_id = role AND m.removed_at IS NULL;
  IF held > 0 OR maps > 0 THEN
    RAISE EXCEPTION 'role "%" has % live assignment(s) and % group mapping(s); move them to another role first (AC-56)', r.name, held, maps
      USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.role x SET status = 'retired' WHERE x.id = role;
  PERFORM iam.role_event('role.retired', 'high', actor, role, btrim(reason), NULL);
END $$;

-- Reads (any signed-in caller; the API requires role.view somewhere).
CREATE FUNCTION iam.permission_list()
RETURNS TABLE (key text, resource_type text, action text, privileged boolean, risk_data boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY SELECT p.key, p.resource_type, p.action::text, p.privileged, p.risk_data
  FROM iam.permission p ORDER BY p.key;
END $$;

CREATE FUNCTION iam.role_list(only_role uuid)
RETURNS TABLE (id uuid, name text, builtin boolean, status text, current_version integer, permissions text[], privileged text[],
               created_at timestamptz, assignments bigint, users bigint, mappings bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY
  SELECT r.id, r.name, r.builtin, r.status::text, r.current_version, coalesce(v.permissions, '{}'),
    ARRAY(SELECT k.key FROM iam.permission k WHERE k.privileged AND k.key = ANY (coalesce(v.permissions, '{}')) ORDER BY k.key),
    r.created_at,
    (SELECT count(*) FROM iam.assignment a WHERE a.role_id = r.id AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())),
    (SELECT count(*) FROM iam.role_affected_users(r.id)),
    (SELECT count(*) FROM iam.group_role_mapping m WHERE m.role_id = r.id AND m.removed_at IS NULL)
  FROM iam.role r LEFT JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  WHERE only_role IS NULL OR r.id = only_role
  ORDER BY r.builtin DESC, lower(r.name);
END $$;

CREATE FUNCTION iam.role_versions(role uuid)
RETURNS TABLE (version integer, permissions text[], changed_by uuid, change_reason text, created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY SELECT v.version, v.permissions, v.changed_by, v.change_reason, v.created_at
  FROM iam.role_version v WHERE v.role_id = role ORDER BY v.version DESC;
END $$;

REVOKE ALL ON FUNCTION iam.role_actor(text), iam.role_affected_users(uuid), iam.role_ac30_users(uuid, text[]),
  iam.user_permissions_except(uuid, uuid), iam.role_diff(uuid, text[]), iam.role_event(text, text, uuid, uuid, text, jsonb),
  iam.role_write_version(uuid, uuid, text[], text, text), iam.role_create(text, text[], text), iam.role_clone(uuid, text, text),
  iam.role_update(uuid, text[], integer, text), iam.role_retire(uuid, text), iam.permission_list(), iam.role_list(uuid),
  iam.role_versions(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.role_diff(uuid, text[]), iam.role_create(text, text[], text), iam.role_clone(uuid, text, text),
  iam.role_update(uuid, text[], integer, text), iam.role_retire(uuid, text), iam.permission_list(), iam.role_list(uuid),
  iam.role_versions(uuid) TO app_rw;

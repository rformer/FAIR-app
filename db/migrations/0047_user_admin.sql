-- F-001 T-23b (AC-11, AC-25, AC-47, AC-54; design §6 /users, /groups):
-- user administration.
--
--   * Visibility (user.view): at the root, every user and group; at a BU,
--     the users and groups holding an assignment in that BU's subtree
--     (restricted BUs as usual, iam.user_has_permission). Others do not
--     exist for the caller.
--   * iam.user_admin_action: disable, enable, unlock, with user.manage at
--     the root and a reason, audited high. Never on one's own account, never
--     the last active root grantor. enable refuses what SCIM disabled (the
--     IdP re-enables) and locked accounts (unlock). enable and unlock record
--     reactivated_at, which the inactivity sweep counts as activity.

ALTER TABLE iam.app_user ADD COLUMN reactivated_at timestamptz;

-- The signed-context user (PF007 without one).
CREATE FUNCTION iam.user_admin_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'user administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

-- The BUs where actor holds user.view.
CREATE FUNCTION iam.user_view_bus(actor uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.id FROM iam.bu b WHERE iam.user_has_permission(actor, 'user.view', b.id);
$$;

-- Principals (users, groups) holding a live assignment in one of bus.
CREATE FUNCTION iam.assigned_in(bus uuid[]) RETURNS TABLE (kind text, id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT a.principal_kind, a.principal_id FROM iam.assignment a
  WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now()) AND a.bu_id = ANY (bus);
$$;

CREATE FUNCTION iam.user_admin_list(only_user uuid, status_filter text, source_filter text, idp_filter uuid, q text,
  lim integer, skip integer)
RETURNS TABLE (id uuid, email text, display_name text, status text, disabled_reason text, source text, idp_id uuid,
               external_id text, user_name text, last_login_at timestamptz, created_at timestamptz, reactivated_at timestamptz,
               live_sessions integer, groups jsonb, assignments jsonb, total bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.user_admin_actor();
  bus   uuid[] := ARRAY(SELECT iam.user_view_bus(actor));
  root  boolean := iam.holds_permission(actor, 'user.view', NULL);
BEGIN
  RETURN QUERY
  WITH principals AS (SELECT * FROM iam.assigned_in(bus)),
  visible AS (
    SELECT u.* FROM iam.app_user u
    WHERE (root OR u.id IN (SELECT p.id FROM principals p WHERE p.kind = 'user')
               OR EXISTS (SELECT 1 FROM iam.grp_member m JOIN principals p ON p.kind = 'group' AND p.id = m.grp_id
                          WHERE m.user_id = u.id))
      AND (only_user IS NULL OR u.id = only_user)
      AND (status_filter IS NULL OR u.status::text = status_filter)
      AND (source_filter IS NULL OR u.source::text = source_filter)
      AND (idp_filter IS NULL OR u.idp_id = idp_filter)
      AND (q IS NULL OR lower(u.email) LIKE lower(q) || '%' OR lower(u.display_name) LIKE lower(q) || '%')
  )
  SELECT v.id, v.email, v.display_name, v.status::text, v.disabled_reason, v.source::text, v.idp_id, v.external_id, v.user_name,
    v.last_login_at, v.created_at, v.reactivated_at,
    (SELECT count(*)::integer FROM iam.session s WHERE s.user_id = v.id AND s.revoked_at IS NULL),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', g.id, 'display_name', g.display_name) ORDER BY g.display_name, g.id)
              FROM iam.grp_member m JOIN iam.grp g ON g.id = m.grp_id AND g.scim_deleted_at IS NULL WHERE m.user_id = v.id), '[]'),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', a.id, 'role', r.name, 'bu', b.code, 'bu_id', b.id,
                                                  'via_group', CASE WHEN a.principal_kind = 'group' THEN a.principal_id END,
                                                  'expires_at', a.expires_at) ORDER BY b.code, r.name, a.id)
              FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id JOIN iam.bu b ON b.id = a.bu_id
              WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
                AND ((a.principal_kind = 'user' AND a.principal_id = v.id)
                  OR (a.principal_kind = 'group' AND EXISTS (SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = v.id)))
                AND (root OR a.bu_id = ANY (bus))), '[]'),
    count(*) OVER ()
  FROM visible v ORDER BY lower(v.email), v.id
  LIMIT greatest(least(coalesce(lim, 100), 1000), 0) OFFSET greatest(coalesce(skip, 0), 0);
END $$;

CREATE FUNCTION iam.group_admin_list(only_group uuid)
RETURNS TABLE (id uuid, display_name text, external_id text, idp_id uuid, created_at timestamptz, members integer, assignments jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.user_admin_actor();
  bus   uuid[] := ARRAY(SELECT iam.user_view_bus(actor));
  root  boolean := iam.holds_permission(actor, 'user.view', NULL);
BEGIN
  RETURN QUERY
  SELECT g.id, g.display_name, g.external_id, g.idp_id, g.created_at,
    (SELECT count(*)::integer FROM iam.grp_member m WHERE m.grp_id = g.id),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', a.id, 'role', r.name, 'bu', b.code, 'bu_id', b.id) ORDER BY b.code, r.name)
              FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id JOIN iam.bu b ON b.id = a.bu_id
              WHERE a.principal_kind = 'group' AND a.principal_id = g.id AND a.revoked_at IS NULL
                AND (a.expires_at IS NULL OR a.expires_at > now()) AND (root OR a.bu_id = ANY (bus))), '[]')
  FROM iam.grp g
  WHERE g.scim_deleted_at IS NULL AND (only_group IS NULL OR g.id = only_group)
    AND (root OR g.id IN (SELECT p.id FROM iam.assigned_in(bus) p WHERE p.kind = 'group'))
  ORDER BY lower(g.display_name), g.id;
END $$;

-- disable, enable or unlock a user. Returns the new status.
CREATE FUNCTION iam.user_admin_action(target uuid, action text, reason text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.user_admin_actor();
  was   iam.app_user;
  u     iam.app_user;
BEGIN
  IF NOT iam.holds_permission(actor, 'user.manage', NULL) THEN
    RAISE EXCEPTION 'user.manage is required' USING ERRCODE = 'PF008';
  END IF;
  IF action NOT IN ('disable', 'enable', 'unlock') THEN
    RAISE EXCEPTION 'unknown action %', action USING ERRCODE = '22023';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO was FROM iam.app_user x WHERE x.id = target FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no user %', target USING ERRCODE = 'P0002';
  END IF;
  IF target = actor THEN
    RAISE EXCEPTION 'you cannot % your own account', action USING ERRCODE = 'PF003';
  END IF;
  CASE action
  WHEN 'disable' THEN
    IF was.status <> 'active' THEN
      RAISE EXCEPTION 'the user is % already', was.status USING ERRCODE = 'PF003';
    END IF;
    IF iam.is_root_grantor(target) AND NOT EXISTS (
         SELECT 1 FROM iam.app_user o WHERE o.id <> target AND o.status = 'active' AND iam.is_root_grantor(o.id)) THEN
      RAISE EXCEPTION 'the last active root administrator cannot be disabled' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'admin' WHERE x.id = target RETURNING * INTO u;
  WHEN 'enable' THEN
    IF was.status = 'locked' THEN
      RAISE EXCEPTION 'the user is locked; unlock it' USING ERRCODE = 'PF003';
    END IF;
    IF was.status = 'active' THEN
      RAISE EXCEPTION 'the user is active already' USING ERRCODE = 'PF003';
    END IF;
    IF was.disabled_reason IN ('scim', 'scim_deleted') THEN
      RAISE EXCEPTION 'the user was disabled by its identity provider; re-enable it there' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'active', disabled_reason = NULL, reactivated_at = now() WHERE x.id = target RETURNING * INTO u;
  WHEN 'unlock' THEN
    IF was.status <> 'locked' THEN
      RAISE EXCEPTION 'the user is not locked' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'active', disabled_reason = NULL, reactivated_at = now() WHERE x.id = target RETURNING * INTO u;
  END CASE;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'user.' || CASE action WHEN 'disable' THEN 'disabled' WHEN 'enable' THEN 'enabled' ELSE 'unlocked' END,
    'severity', 'high', 'actor', actor::text, 'target', 'user:' || target, 'reason', reason,
    'attributes', jsonb_build_object('email', u.email, 'before', jsonb_build_object('status', was.status, 'disabled_reason', was.disabled_reason),
                                     'after', jsonb_build_object('status', u.status, 'disabled_reason', u.disabled_reason))));
  RETURN u.status::text;
END $$;

-- The inactivity sweep (T-23) counts a re-enabling as activity.
CREATE OR REPLACE FUNCTION iam.inactivity_sweep() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  raw    jsonb := iam.instance_setting('auth.inactive_disable_after');
  period interval;
  u      iam.app_user;
  n      integer := 0;
BEGIN
  IF raw IS NULL OR jsonb_typeof(raw) <> 'string' THEN
    RAISE EXCEPTION 'auth.inactive_disable_after is not set' USING ERRCODE = 'PF003';
  END IF;
  period := (raw #>> '{}')::interval;
  IF period <= interval '0' THEN
    RAISE EXCEPTION 'auth.inactive_disable_after % is not positive', period USING ERRCODE = 'PF004';
  END IF;
  FOR u IN
    UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'inactive'
    WHERE x.status = 'active' AND x.source <> 'breakglass'
      AND greatest(coalesce(x.last_login_at, x.created_at), x.reactivated_at,
                   (SELECT max(s.last_seen_at) FROM iam.session s WHERE s.user_id = x.id)) < now() - period
    RETURNING * LOOP
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'user.disabled_inactive', 'severity', 'low', 'actor', 'system:iam',
      'target', 'user:' || u.id, 'attributes', jsonb_build_object('email', u.email, 'last_login_at', u.last_login_at,
                                                                   'inactive_after', raw #>> '{}')));
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION iam.user_admin_actor(), iam.user_view_bus(uuid), iam.assigned_in(uuid[]),
  iam.user_admin_list(uuid, text, text, uuid, text, integer, integer), iam.group_admin_list(uuid),
  iam.user_admin_action(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.user_admin_list(uuid, text, text, uuid, text, integer, integer), iam.group_admin_list(uuid),
  iam.user_admin_action(uuid, text, text) TO app_rw;

-- F-001 T-19 (AC-34; design §5.1 step 6, §6): the system-use banner.
--
--   * iam.banner: the banner text, versioned; set by banner.manage holders
--     through the iam API (iam.banner_admin_set), audited (high). A neutral
--     AC-8 notice ships as version 1.
--   * A session is created unacknowledged; while banner.enabled is on, the
--     gateway serves it nothing but /me, the acknowledgment and logout until
--     the user acknowledges the current text (iam.session_banner_ack,
--     audited). session_lookup now also returns banner_ack_at.

CREATE TABLE iam.banner (
  singleton   boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  version     integer     NOT NULL CHECK (version > 0),
  text        text        NOT NULL CHECK (length(btrim(text)) BETWEEN 1 AND 10000),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  updated_by  uuid        REFERENCES iam.app_user (id)
);
REVOKE ALL ON iam.banner FROM PUBLIC;
INSERT INTO iam.banner (version, text) VALUES (1,
'You are accessing an information system provided for authorized use only. Use of this system is monitored, recorded and subject to audit. Unauthorized use is prohibited and may result in disciplinary action and civil and criminal penalties. By using this system you consent to this monitoring and recording, and you have no expectation of privacy in any communication or data on it.');

ALTER TABLE iam.session ADD COLUMN banner_version integer;

-- The banner in force.
CREATE FUNCTION iam.banner_current() RETURNS TABLE (version integer, text text, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.version, b.text, b.updated_at FROM iam.banner b;
$$;

-- A session acknowledges banner version v: 'ok', 'stale' (v is not the
-- current version) or 'inactive' (no live session).
CREATE FUNCTION iam.session_banner_ack(id_hmac bytea, v integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s iam.session;
BEGIN
  IF v IS DISTINCT FROM (SELECT b.version FROM iam.banner b) THEN
    RETURN 'stale';
  END IF;
  UPDATE iam.session x SET banner_ack_at = coalesce(x.banner_ack_at, now()), banner_version = v
  WHERE x.id_hmac = session_banner_ack.id_hmac AND x.revoked_at IS NULL RETURNING * INTO s;
  IF NOT FOUND THEN
    RETURN 'inactive';
  END IF;
  PERFORM iam.session_event('session.banner_acknowledged', 'info', s.user_id::text, s, 'banner version ' || v);
  RETURN 'ok';
END $$;

-- Sets the banner text (banner.manage, from the signed context).
CREATE FUNCTION iam.banner_admin_set(new_text text, reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
  b iam.banner;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'the banner API needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'banner.manage', NULL) THEN
    RAISE EXCEPTION 'banner.manage is required' USING ERRCODE = 'PF008';
  END IF;
  IF new_text IS NULL OR length(btrim(new_text)) NOT BETWEEN 1 AND 10000 THEN
    RAISE EXCEPTION 'the banner text must be 1 to 10000 characters' USING ERRCODE = 'PF004';
  END IF;
  UPDATE iam.banner x SET version = x.version + 1, text = btrim(new_text), updated_at = now(), updated_by = u RETURNING * INTO b;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'banner.changed', 'severity', 'high', 'actor', u::text, 'target', 'banner',
    'reason', reason, 'attributes', jsonb_build_object('version', b.version, 'text', b.text)));
  RETURN b.version;
END $$;

-- session_lookup returns the acknowledgment too (a new result column, so
-- the function is recreated).
DROP FUNCTION iam.session_lookup(bytea, interval, interval);
CREATE FUNCTION iam.session_lookup(id_hmac bytea, idle interval, absolute interval)
RETURNS TABLE (status text, handle uuid, user_id uuid, scope_version bigint, auth_method text, created_at timestamptz,
               last_seen_at timestamptz, expires_at timestamptz, banner_ack_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  s       iam.session;
  hard    timestamptz;
  why     text;
  active  boolean;
BEGIN
  IF idle IS NULL OR idle <= interval '0' OR absolute IS NULL OR absolute <= interval '0' THEN
    RAISE EXCEPTION 'timeouts must be positive' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO s FROM iam.session x WHERE x.id_hmac = session_lookup.id_hmac FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::uuid, NULL::bigint, NULL::text, NULL::timestamptz, NULL::timestamptz,
      NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF s.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'revoked'::text, s.handle, s.user_id, NULL::bigint, s.auth_method, s.created_at, s.last_seen_at,
      NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  -- A tightened absolute timeout applies to existing sessions too.
  hard := least(s.absolute_expiry_at, s.created_at + absolute);
  SELECT u.status = 'active' INTO active FROM iam.app_user u WHERE u.id = s.user_id;
  why := CASE WHEN NOT coalesce(active, false) THEN 'user_disabled'
              WHEN now() >= hard THEN 'absolute_timeout'
              WHEN now() >= s.last_seen_at + idle THEN 'idle_timeout' END;
  IF why IS NOT NULL THEN
    UPDATE iam.session x SET revoked_at = now(), revoked_reason = why WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
    PERFORM iam.session_event('session.expired', 'info', 'system:gateway', s, why);
    RETURN QUERY SELECT why, s.handle, s.user_id, NULL::bigint, s.auth_method, s.created_at, s.last_seen_at,
      NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF now() - s.last_seen_at >= interval '60 seconds' THEN
    UPDATE iam.session x SET last_seen_at = now() WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
  END IF;
  RETURN QUERY SELECT 'active'::text, s.handle, s.user_id,
    coalesce((SELECT us.scope_version FROM authz.user_scope us WHERE us.user_id = s.user_id), 0::bigint),
    s.auth_method, s.created_at, s.last_seen_at, least(hard, s.last_seen_at + idle), s.banner_ack_at;
END $$;

REVOKE ALL ON FUNCTION iam.session_lookup(bytea, interval, interval), iam.banner_current(), iam.session_banner_ack(bytea, integer),
  iam.banner_admin_set(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.session_lookup(bytea, interval, interval), iam.session_banner_ack(bytea, integer) TO app_gateway;
GRANT EXECUTE ON FUNCTION iam.banner_current() TO app_gateway, app_rw;
GRANT EXECUTE ON FUNCTION iam.banner_admin_set(text, text) TO app_rw;

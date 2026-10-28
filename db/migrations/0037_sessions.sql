-- F-001 T-13 (AC-31, AC-33, AC-35; design §3 Identity, §5.1 step 6, §5.2):
-- gateway sessions.
--
-- The gateway issues a 256-bit random session token in the __Host-sid
-- cookie and stores only HMAC-SHA-256(pepper, token), computed by the
-- gateway with a pepper the database never sees, so neither a database
-- read nor a backup yields a usable session. The gateway connects as
-- app_gateway, which has no table privileges: everything goes through the
-- SECURITY DEFINER functions below (owned by fair_owner, as iam's are).
--
--   session_create   at login (T-15/T-16 hand the authenticated user over)
--   session_lookup   every request: idle and absolute timeouts as currently
--                    configured (a tightened timeout applies to existing
--                    sessions), user still active, last_seen throttled to
--                    once a minute; an expired session is closed with its
--                    reason
--   session_logout   the session's own logout
--   session_list,    users list and revoke their own sessions; other users'
--   session_revoke,  need session.view / session.revoke (with a reason),
--   session_revoke_all  from the signed DB context (AC-33)
--
-- Every creation, expiry and revocation is audited through the outbox in
-- the same transaction, and revocations publish iam.session.revoked.

CREATE TABLE iam.session (
  id_hmac             bytea       PRIMARY KEY CHECK (length(id_hmac) = 32),
  handle              uuid        NOT NULL UNIQUE DEFAULT gen_random_uuid(), -- the public id (never the HMAC)
  user_id             uuid        NOT NULL REFERENCES iam.app_user (id),
  auth_method         text        NOT NULL CHECK (auth_method ~ '^[a-z][a-z0-9_-]{0,31}$'),
  mfa_evidence        jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(mfa_evidence) = 'object'),
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  absolute_expiry_at  timestamptz NOT NULL,
  ip                  inet,
  ip_prefix           cidr,
  asn                 integer,
  user_agent          text        CHECK (length(user_agent) <= 512),
  banner_ack_at       timestamptz,
  revoked_at          timestamptz,
  revoked_reason      text        CHECK (revoked_reason IN ('logout', 'revoked', 'idle_timeout', 'absolute_timeout',
                                                            'user_disabled', 'network_change')),
  revoked_by          uuid        REFERENCES iam.app_user (id),
  CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
  CHECK (absolute_expiry_at > created_at)
);
CREATE INDEX session_user_active ON iam.session (user_id) WHERE revoked_at IS NULL;
REVOKE ALL ON iam.session FROM PUBLIC;

GRANT USAGE ON SCHEMA iam TO app_gateway;

-- An audit event (and, for revocations, iam.session.revoked) in the outbox.
CREATE FUNCTION iam.session_event(event text, severity text, actor text, s iam.session, reason text) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object(
    'type', event, 'severity', severity, 'actor', actor, 'target', 'session:' || s.handle,
    'reason', reason,
    'attributes', jsonb_build_object('user_id', s.user_id, 'session', s.handle, 'auth_method', s.auth_method,
                                     'ip', host(s.ip), 'revoked_reason', s.revoked_reason)));
  INSERT INTO iam.event_outbox (topic, payload)
  SELECT 'iam.session.revoked', jsonb_build_object('session', s.handle, 'user_id', s.user_id, 'reason', s.revoked_reason)
  WHERE s.revoked_at IS NOT NULL;
$$;

-- At login: a new session for an active user. absolute is the absolute
-- timeout in force (session.absolute_timeout).
CREATE FUNCTION iam.session_create(id_hmac bytea, user_id uuid, auth_method text, mfa_evidence jsonb, ip inet,
  user_agent text, absolute interval)
RETURNS TABLE (handle uuid, created_at timestamptz, absolute_expiry_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  s iam.session;
BEGIN
  IF absolute IS NULL OR absolute <= interval '0' OR absolute > interval '7 days' THEN
    RAISE EXCEPTION 'absolute timeout % out of range', absolute USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = session_create.user_id AND u.status = 'active') THEN
    RAISE EXCEPTION 'user is not active' USING ERRCODE = '28000';
  END IF;
  INSERT INTO iam.session AS x (id_hmac, user_id, auth_method, mfa_evidence, absolute_expiry_at, ip, ip_prefix, user_agent)
  VALUES (session_create.id_hmac, session_create.user_id, session_create.auth_method, coalesce(session_create.mfa_evidence, '{}'),
          now() + absolute, session_create.ip,
          CASE WHEN session_create.ip IS NULL THEN NULL
               WHEN family(session_create.ip) = 4 THEN set_masklen(session_create.ip::cidr, 24)
               ELSE set_masklen(session_create.ip::cidr, 64) END,
          left(session_create.user_agent, 512))
  RETURNING * INTO s;
  UPDATE iam.app_user u SET last_login_at = now() WHERE u.id = s.user_id;
  PERFORM iam.session_event('session.created', 'info', s.user_id::text, s, NULL);
  RETURN QUERY SELECT s.handle, s.created_at, s.absolute_expiry_at;
END $$;

-- Every request. status: active, or why the session no longer is
-- (unknown, revoked, idle_timeout, absolute_timeout, user_disabled).
CREATE FUNCTION iam.session_lookup(id_hmac bytea, idle interval, absolute interval)
RETURNS TABLE (status text, handle uuid, user_id uuid, scope_version bigint, auth_method text, created_at timestamptz,
               last_seen_at timestamptz, expires_at timestamptz)
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
    RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::uuid, NULL::bigint, NULL::text, NULL::timestamptz, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF s.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'revoked'::text, s.handle, s.user_id, NULL::bigint, s.auth_method, s.created_at, s.last_seen_at, NULL::timestamptz;
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
    RETURN QUERY SELECT why, s.handle, s.user_id, NULL::bigint, s.auth_method, s.created_at, s.last_seen_at, NULL::timestamptz;
    RETURN;
  END IF;
  IF now() - s.last_seen_at >= interval '60 seconds' THEN
    UPDATE iam.session x SET last_seen_at = now() WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
  END IF;
  RETURN QUERY SELECT 'active'::text, s.handle, s.user_id,
    coalesce((SELECT us.scope_version FROM authz.user_scope us WHERE us.user_id = s.user_id), 0::bigint),
    s.auth_method, s.created_at, s.last_seen_at, least(hard, s.last_seen_at + idle);
END $$;

-- The session's own logout. Returns whether a live session was closed.
CREATE FUNCTION iam.session_logout(id_hmac bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s iam.session;
BEGIN
  UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'logout', revoked_by = x.user_id
  WHERE x.id_hmac = session_logout.id_hmac AND x.revoked_at IS NULL RETURNING * INTO s;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  PERFORM iam.session_event('session.revoked', 'info', s.user_id::text, s, 'logout');
  RETURN true;
END $$;

-- The signed-context user (PF007 without one).
CREATE FUNCTION iam.session_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'sessions need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

-- Active sessions of target (NULL: the caller's own). Other users' need
-- session.view.
CREATE FUNCTION iam.session_list(target uuid)
RETURNS TABLE (handle uuid, user_id uuid, auth_method text, created_at timestamptz, last_seen_at timestamptz,
               absolute_expiry_at timestamptz, ip text, user_agent text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  u uuid := iam.session_actor();
  t uuid := coalesce(target, u);
BEGIN
  IF t <> u AND NOT iam.holds_permission(u, 'session.view', NULL) THEN
    RAISE EXCEPTION 'session.view is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN QUERY SELECT x.handle, x.user_id, x.auth_method, x.created_at, x.last_seen_at, x.absolute_expiry_at, host(x.ip), x.user_agent
  FROM iam.session x WHERE x.user_id = t AND x.revoked_at IS NULL ORDER BY x.created_at DESC, x.handle;
END $$;

-- Revokes one session by its handle. Other users' sessions need
-- session.revoke and a reason. Returns whether a live session was revoked.
CREATE FUNCTION iam.session_revoke(session_handle uuid, reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.session_actor();
  s iam.session;
BEGIN
  SELECT * INTO s FROM iam.session x WHERE x.handle = session_handle FOR UPDATE;
  IF NOT FOUND OR s.revoked_at IS NOT NULL THEN
    RETURN false;
  END IF;
  IF s.user_id <> u THEN
    IF NOT iam.holds_permission(u, 'session.revoke', NULL) THEN
      RAISE EXCEPTION 'session.revoke is required' USING ERRCODE = 'PF008';
    END IF;
    IF btrim(coalesce(reason, '')) = '' THEN
      RAISE EXCEPTION 'revoking another user''s session needs a reason' USING ERRCODE = 'PF002';
    END IF;
  END IF;
  UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'revoked', revoked_by = u
  WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
  PERFORM iam.session_event('session.revoked', CASE WHEN s.user_id <> u THEN 'high' ELSE 'info' END, u::text, s,
                            nullif(btrim(coalesce(reason, '')), ''));
  RETURN true;
END $$;

-- Revokes every active session of target (NULL: the caller's own), except
-- the one with handle keep. Returns how many were revoked.
CREATE FUNCTION iam.session_revoke_all(target uuid, keep uuid, reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.session_actor();
  t uuid := coalesce(target, u);
  s iam.session;
  n integer := 0;
BEGIN
  IF t <> u THEN
    IF NOT iam.holds_permission(u, 'session.revoke', NULL) THEN
      RAISE EXCEPTION 'session.revoke is required' USING ERRCODE = 'PF008';
    END IF;
    IF btrim(coalesce(reason, '')) = '' THEN
      RAISE EXCEPTION 'revoking another user''s sessions needs a reason' USING ERRCODE = 'PF002';
    END IF;
  END IF;
  FOR s IN UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'revoked', revoked_by = u
           WHERE x.user_id = t AND x.revoked_at IS NULL AND x.handle IS DISTINCT FROM keep RETURNING * LOOP
    PERFORM iam.session_event('session.revoked', CASE WHEN t <> u THEN 'high' ELSE 'info' END, u::text, s,
                              nullif(btrim(coalesce(reason, '')), ''));
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION iam.session_event(text, text, text, iam.session, text),
  iam.session_create(bytea, uuid, text, jsonb, inet, text, interval), iam.session_lookup(bytea, interval, interval),
  iam.session_logout(bytea), iam.session_actor(), iam.session_list(uuid), iam.session_revoke(uuid, text),
  iam.session_revoke_all(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval), iam.session_lookup(bytea, interval, interval),
  iam.session_logout(bytea), iam.session_list(uuid), iam.session_revoke(uuid, text), iam.session_revoke_all(uuid, uuid, text)
  TO app_gateway;

-- The gateway reads the session timeouts as services do (settings.Client).
GRANT USAGE ON SCHEMA posture TO app_gateway;
SET ROLE posture_definer; -- their owner
GRANT EXECUTE ON FUNCTION posture.effective_settings(), posture.settings_version() TO app_gateway;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- F-001 T-20 (design §5.8): session network binding.
--
--   * A session records the client's IP, its prefix (sizes configured at the
--     gateway) and ASN at login, and the IdP it came through (for the
--     re-authentication redirect).
--   * iam.session_network_changed: the gateway reports a request from
--     outside the session's network. reauthenticate revokes the session
--     (network_change); flag and off mark it (network_changed_at) once, flag
--     with an audit event. A marked session's internal tokens say so, and a
--     BU whose own session.network_binding is reauthenticate refuses it
--     (authz step-up).
--   * session_create, session_lookup and session_list are recreated with
--     the new columns.

ALTER TABLE iam.session ADD COLUMN idp_id uuid REFERENCES iam.idp (id),
                        ADD COLUMN network_changed_at timestamptz;

DROP FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval);
CREATE FUNCTION iam.session_create(id_hmac bytea, user_id uuid, auth_method text, mfa_evidence jsonb, ip inet,
  user_agent text, absolute interval, idp uuid, asn integer, prefix4 integer, prefix6 integer)
RETURNS TABLE (handle uuid, created_at timestamptz, absolute_expiry_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  s iam.session;
BEGIN
  IF absolute IS NULL OR absolute <= interval '0' OR absolute > interval '7 days' THEN
    RAISE EXCEPTION 'absolute timeout % out of range', absolute USING ERRCODE = '22023';
  END IF;
  IF prefix4 NOT BETWEEN 8 AND 32 OR prefix6 NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION 'prefix sizes /% and /% out of range', prefix4, prefix6 USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = session_create.user_id AND u.status = 'active') THEN
    RAISE EXCEPTION 'user is not active' USING ERRCODE = '28000';
  END IF;
  INSERT INTO iam.session AS x (id_hmac, user_id, auth_method, mfa_evidence, absolute_expiry_at, ip, ip_prefix, asn, user_agent, idp_id)
  VALUES (session_create.id_hmac, session_create.user_id, session_create.auth_method, coalesce(session_create.mfa_evidence, '{}'),
          now() + absolute, session_create.ip,
          CASE WHEN session_create.ip IS NULL THEN NULL
               WHEN family(session_create.ip) = 4 THEN set_masklen(session_create.ip::cidr, prefix4)
               ELSE set_masklen(session_create.ip::cidr, prefix6) END,
          session_create.asn, left(session_create.user_agent, 512), session_create.idp)
  RETURNING * INTO s;
  UPDATE iam.app_user u SET last_login_at = now() WHERE u.id = s.user_id;
  PERFORM iam.session_event('session.created', 'info', s.user_id::text, s, NULL);
  RETURN QUERY SELECT s.handle, s.created_at, s.absolute_expiry_at;
END $$;

DROP FUNCTION iam.session_lookup(bytea, interval, interval);
CREATE FUNCTION iam.session_lookup(id_hmac bytea, idle interval, absolute interval)
RETURNS TABLE (status text, handle uuid, user_id uuid, scope_version bigint, auth_method text, created_at timestamptz,
               last_seen_at timestamptz, expires_at timestamptz, banner_ack_at timestamptz, ip text, asn integer,
               idp_id uuid, network_changed_at timestamptz)
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
      NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;
  IF s.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT coalesce(nullif(s.revoked_reason, 'logout'), 'revoked'), s.handle, s.user_id, NULL::bigint, s.auth_method,
      s.created_at, s.last_seen_at, NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, s.idp_id, NULL::timestamptz;
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
      NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, s.idp_id, NULL::timestamptz;
    RETURN;
  END IF;
  IF now() - s.last_seen_at >= interval '60 seconds' THEN
    UPDATE iam.session x SET last_seen_at = now() WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
  END IF;
  RETURN QUERY SELECT 'active'::text, s.handle, s.user_id,
    coalesce((SELECT us.scope_version FROM authz.user_scope us WHERE us.user_id = s.user_id), 0::bigint),
    s.auth_method, s.created_at, s.last_seen_at, least(hard, s.last_seen_at + idle), s.banner_ack_at,
    host(s.ip), s.asn, s.idp_id, s.network_changed_at;
END $$;

-- The gateway saw the session's client outside its network (client ip and
-- asn now). mode is session.network_binding in force: reauthenticate
-- revokes ('revoked'); flag and off mark the session once ('marked'), flag
-- with an audit event. 'inactive' when the session is no longer live.
CREATE FUNCTION iam.session_network_changed(id_hmac bytea, client inet, client_asn integer, mode text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s     iam.session;
  first boolean;
BEGIN
  IF mode NOT IN ('off', 'flag', 'reauthenticate') THEN
    RAISE EXCEPTION 'unknown network binding mode %', mode USING ERRCODE = '22023';
  END IF;
  SELECT * INTO s FROM iam.session x WHERE x.id_hmac = session_network_changed.id_hmac AND x.revoked_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'inactive';
  END IF;
  first := s.network_changed_at IS NULL;
  IF mode <> 'off' AND (first OR mode = 'reauthenticate') THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'session.network_changed', 'severity', 'high', 'actor', 'system:gateway',
      'target', 'session:' || s.handle, 'reason', mode,
      'attributes', jsonb_build_object('user_id', s.user_id, 'session', s.handle, 'ip', host(s.ip), 'asn', s.asn,
                                       'new_ip', host(client), 'new_asn', client_asn, 'action',
                                       CASE WHEN mode = 'reauthenticate' THEN 'revoked' ELSE 'flagged' END)));
  END IF;
  IF mode = 'reauthenticate' THEN
    UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'network_change',
      network_changed_at = coalesce(x.network_changed_at, now())
    WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
    PERFORM iam.session_event('session.revoked', 'high', 'system:gateway', s, 'network_change');
    RETURN 'revoked';
  END IF;
  IF first THEN
    UPDATE iam.session x SET network_changed_at = now() WHERE x.id_hmac = s.id_hmac;
  END IF;
  RETURN 'marked';
END $$;

DROP FUNCTION iam.session_list(uuid);
CREATE FUNCTION iam.session_list(target uuid)
RETURNS TABLE (handle uuid, user_id uuid, auth_method text, created_at timestamptz, last_seen_at timestamptz,
               absolute_expiry_at timestamptz, ip text, user_agent text, network_changed_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  u uuid := iam.session_actor();
  t uuid := coalesce(target, u);
BEGIN
  IF t <> u AND NOT iam.holds_permission(u, 'session.view', NULL) THEN
    RAISE EXCEPTION 'session.view is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN QUERY SELECT x.handle, x.user_id, x.auth_method, x.created_at, x.last_seen_at, x.absolute_expiry_at, host(x.ip), x.user_agent,
    x.network_changed_at
  FROM iam.session x WHERE x.user_id = t AND x.revoked_at IS NULL ORDER BY x.created_at DESC, x.handle;
END $$;

REVOKE ALL ON FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval, uuid, integer, integer, integer),
  iam.session_lookup(bytea, interval, interval), iam.session_network_changed(bytea, inet, integer, text),
  iam.session_list(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval, uuid, integer, integer, integer),
  iam.session_lookup(bytea, interval, interval), iam.session_network_changed(bytea, inet, integer, text),
  iam.session_list(uuid) TO app_gateway;

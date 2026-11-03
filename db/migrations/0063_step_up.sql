-- F-015 T-24b (F-001 change; F-015-AC-33, design §6.6): step-up
-- re-authentication.
--
--   * A session records when the user authenticated at the IdP (auth_time):
--     the SAML AuthnInstant or the OIDC auth_time the login ticket carries,
--     never later than the session's start. The gateway puts it in the
--     internal token, and authz.Check refuses a restricted BU whose
--     bu.reauth_max_age it exceeds (401 step_up).
--   * A step-up sign-in is a login started with step_up: the database
--     records when it was asked for (step_up_at), so iam can refuse an IdP
--     authentication older than the request (ForceAuthn / prompt=login not
--     honoured, or no authentication time at all), and which session it
--     replaces. The new session revokes that one (reason step_up) when both
--     belong to the same user.

ALTER TABLE iam.session ADD COLUMN auth_time timestamptz;
UPDATE iam.session SET auth_time = created_at;
-- session_create writes it, never later than the session's start.
ALTER TABLE iam.session ALTER COLUMN auth_time SET NOT NULL, ALTER COLUMN auth_time SET DEFAULT now();
ALTER TABLE iam.session DROP CONSTRAINT session_revoked_reason_check,
  ADD CONSTRAINT session_revoked_reason_check CHECK (revoked_reason IN ('logout', 'revoked', 'idle_timeout', 'absolute_timeout',
                                                                         'user_disabled', 'network_change', 'step_up'));

ALTER TABLE iam.saml_request ADD COLUMN step_up_at timestamptz, ADD COLUMN replaces uuid;
ALTER TABLE iam.oidc_state ADD COLUMN step_up_at timestamptz, ADD COLUMN replaces uuid;

-- Pending SAML requests and started OIDC logins carry the step-up.
DROP FUNCTION iam.saml_request_save(uuid, text, text, timestamptz);
CREATE FUNCTION iam.saml_request_save(idp uuid, request text, return_path text, expires timestamptz, step_up boolean, replaces uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF expires > now() + interval '10 minutes' THEN
    RAISE EXCEPTION 'a pending request lives at most 10 minutes' USING ERRCODE = '22023';
  END IF;
  DELETE FROM iam.saml_request r WHERE r.expires_at < now(); -- keep the table small
  INSERT INTO iam.saml_request (idp_id, request_id, return_to, expires_at, step_up_at, replaces)
  VALUES (idp, request, return_path, expires, CASE WHEN step_up THEN now() END, CASE WHEN step_up THEN replaces END);
END $$;

DROP FUNCTION iam.saml_request_consume(uuid, text);
CREATE FUNCTION iam.saml_request_consume(idp uuid, request text)
RETURNS TABLE (return_to text, step_up_at timestamptz, replaces uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.saml_request r WHERE r.idp_id = idp AND r.request_id = request AND r.expires_at > now()
  RETURNING r.return_to, r.step_up_at, r.replaces;
$$;

DROP FUNCTION iam.oidc_state_save(uuid, text, text, text, text, timestamptz);
CREATE FUNCTION iam.oidc_state_save(idp uuid, login_state text, login_nonce text, verifier text, return_path text, expires timestamptz,
  step_up boolean, replaces uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF expires > now() + interval '10 minutes' THEN
    RAISE EXCEPTION 'a login lives at most 10 minutes' USING ERRCODE = '22023';
  END IF;
  DELETE FROM iam.oidc_state s WHERE s.expires_at < now();
  INSERT INTO iam.oidc_state (idp_id, state, nonce, code_verifier, return_to, expires_at, step_up_at, replaces)
  VALUES (idp, login_state, login_nonce, verifier, return_path, expires, CASE WHEN step_up THEN now() END, CASE WHEN step_up THEN replaces END);
END $$;

DROP FUNCTION iam.oidc_state_consume(uuid, text);
CREATE FUNCTION iam.oidc_state_consume(idp uuid, login_state text)
RETURNS TABLE (nonce text, code_verifier text, return_to text, step_up_at timestamptz, replaces uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.oidc_state s WHERE s.idp_id = idp AND s.state = login_state AND s.expires_at > now()
  RETURNING s.nonce, s.code_verifier, s.return_to, s.step_up_at, s.replaces;
$$;

REVOKE ALL ON FUNCTION iam.saml_request_save(uuid, text, text, timestamptz, boolean, uuid), iam.saml_request_consume(uuid, text),
  iam.oidc_state_save(uuid, text, text, text, text, timestamptz, boolean, uuid), iam.oidc_state_consume(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.saml_request_save(uuid, text, text, timestamptz, boolean, uuid), iam.saml_request_consume(uuid, text),
  iam.oidc_state_save(uuid, text, text, text, text, timestamptz, boolean, uuid), iam.oidc_state_consume(uuid, text) TO app_rw;

-- session_create takes the IdP's authentication time and, for a step-up,
-- the session it replaces; otherwise as in 0043.
DROP FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval, uuid, integer, integer, integer);
CREATE FUNCTION iam.session_create(id_hmac bytea, user_id uuid, auth_method text, mfa_evidence jsonb, ip inet,
  user_agent text, absolute interval, idp uuid, asn integer, prefix4 integer, prefix6 integer, authenticated_at timestamptz, replaces uuid)
RETURNS TABLE (handle uuid, created_at timestamptz, absolute_expiry_at timestamptz, auth_time timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  s   iam.session;
  old iam.session;
BEGIN
  IF absolute IS NULL OR absolute <= interval '0' OR absolute > interval '7 days' THEN
    RAISE EXCEPTION 'absolute timeout % out of range', absolute USING ERRCODE = '22023';
  END IF;
  IF prefix4 NOT BETWEEN 8 AND 32 OR prefix6 NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION 'prefix sizes /% and /% out of range', prefix4, prefix6 USING ERRCODE = '22023';
  END IF;
  -- An authentication time in the future (beyond clock skew) is refused; a
  -- missing one is the session's start.
  IF session_create.authenticated_at > now() + interval '2 minutes' THEN
    RAISE EXCEPTION 'authentication time % is in the future', session_create.authenticated_at USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = session_create.user_id AND u.status = 'active') THEN
    RAISE EXCEPTION 'user is not active' USING ERRCODE = '28000';
  END IF;
  INSERT INTO iam.session AS x (id_hmac, user_id, auth_method, mfa_evidence, absolute_expiry_at, ip, ip_prefix, asn, user_agent, idp_id,
                                auth_time)
  VALUES (session_create.id_hmac, session_create.user_id, session_create.auth_method, coalesce(session_create.mfa_evidence, '{}'),
          now() + absolute, session_create.ip,
          CASE WHEN session_create.ip IS NULL THEN NULL
               WHEN family(session_create.ip) = 4 THEN set_masklen(session_create.ip::cidr, prefix4)
               ELSE set_masklen(session_create.ip::cidr, prefix6) END,
          session_create.asn, left(session_create.user_agent, 512), session_create.idp,
          least(coalesce(session_create.authenticated_at, now()), now()))
  RETURNING * INTO s;
  UPDATE iam.app_user u SET last_login_at = now() WHERE u.id = s.user_id;
  PERFORM iam.session_event('session.created', 'info', s.user_id::text, s, NULL);
  -- A step-up replaces the session it was started from: the same user's
  -- only (a handle of another user's session is ignored).
  IF replaces IS NOT NULL THEN
    UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'step_up'
    WHERE x.handle = replaces AND x.user_id = s.user_id AND x.revoked_at IS NULL AND x.id_hmac <> s.id_hmac
    RETURNING * INTO old;
    IF FOUND THEN
      PERFORM iam.session_event('session.revoked', 'info', s.user_id::text, old, 'replaced by a step-up sign-in');
    END IF;
  END IF;
  RETURN QUERY SELECT s.handle, s.created_at, s.absolute_expiry_at, s.auth_time;
END $$;

-- session_lookup returns the authentication time too; otherwise as in 0043.
DROP FUNCTION iam.session_lookup(bytea, interval, interval);
CREATE FUNCTION iam.session_lookup(id_hmac bytea, idle interval, absolute interval)
RETURNS TABLE (status text, handle uuid, user_id uuid, scope_version bigint, auth_method text, created_at timestamptz,
               last_seen_at timestamptz, expires_at timestamptz, banner_ack_at timestamptz, ip text, asn integer,
               idp_id uuid, network_changed_at timestamptz, auth_time timestamptz)
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
      NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, NULL::uuid, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF s.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT coalesce(nullif(s.revoked_reason, 'logout'), 'revoked'), s.handle, s.user_id, NULL::bigint, s.auth_method,
      s.created_at, s.last_seen_at, NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, s.idp_id, NULL::timestamptz,
      NULL::timestamptz;
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
      NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::integer, s.idp_id, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF now() - s.last_seen_at >= interval '60 seconds' THEN
    UPDATE iam.session x SET last_seen_at = now() WHERE x.id_hmac = s.id_hmac RETURNING * INTO s;
  END IF;
  RETURN QUERY SELECT 'active'::text, s.handle, s.user_id,
    coalesce((SELECT us.scope_version FROM authz.user_scope us WHERE us.user_id = s.user_id), 0::bigint),
    s.auth_method, s.created_at, s.last_seen_at, least(hard, s.last_seen_at + idle), s.banner_ack_at,
    host(s.ip), s.asn, s.idp_id, s.network_changed_at, s.auth_time;
END $$;

REVOKE ALL ON FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval, uuid, integer, integer, integer, timestamptz, uuid),
  iam.session_lookup(bytea, interval, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.session_create(bytea, uuid, text, jsonb, inet, text, interval, uuid, integer, integer, integer, timestamptz, uuid),
  iam.session_lookup(bytea, interval, interval) TO app_gateway;

-- Login events gain authn.step_up_failed (iam refuses a step-up sign-in
-- without a fresh IdP authentication); otherwise as in 0041.
CREATE OR REPLACE FUNCTION iam.authn_event(event text, severity text, actor text, idp uuid, attributes jsonb, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF event NOT IN ('authn.login.success', 'authn.login.denied', 'authn.mfa_missing', 'authn.step_up_failed')
     OR severity NOT IN ('info', 'low', 'high') THEN
    RAISE EXCEPTION 'unknown login event %', event USING ERRCODE = '22023';
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor, 'target', 'idp:' || idp,
                                      'reason', reason, 'attributes', coalesce(attributes, '{}')));
END $$;

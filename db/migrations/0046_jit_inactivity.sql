-- F-001 T-23 (AC-09, AC-11; design §5.1 step 5, §2 scope worker):
-- just-in-time provisioning and the inactivity sweep.
--
--   * iam.jit_provision: a federated login for an unknown subject creates
--     the user, only while auth.jit_provisioning is on (off by default in
--     every profile; read here, from the settings in force, whoever calls).
--     The email must be in one of the IdP's domains (when it has any) and
--     must not belong to another account (no silent linking). The user
--     gets no roles (AC-09). Audited.
--   * iam.inactivity_sweep (the scope worker, hourly): users not seen for
--     longer than auth.inactive_disable_after (90 days by default) are
--     disabled (reason inactive; break-glass accounts excepted: they exist
--     to be unused). The T-22 trigger ends their sessions. SCIM does not
--     re-enable them; an administrator does.

-- The iam functions read the settings in force as services do.
SET ROLE posture_definer; -- the owner of posture.effective_settings
GRANT EXECUTE ON FUNCTION posture.effective_settings() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

CREATE FUNCTION iam.instance_setting(setting text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT posture.effective_settings()->'instance'->setting;
$$;
REVOKE ALL ON FUNCTION iam.instance_setting(text) FROM PUBLIC;

CREATE FUNCTION iam.jit_provision(idp uuid, subject text, user_email text, name text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  i      iam.idp;
  u      iam.app_user;
  domain text;
BEGIN
  IF coalesce((iam.instance_setting('auth.jit_provisioning'))::boolean, false) IS NOT TRUE THEN
    RAISE EXCEPTION 'just-in-time provisioning is off' USING ERRCODE = 'PF003';
  END IF;
  SELECT * INTO i FROM iam.idp x WHERE x.id = idp AND x.enabled;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no enabled IdP %', idp USING ERRCODE = 'PF003';
  END IF;
  user_email := lower(btrim(coalesce(user_email, '')));
  IF btrim(coalesce(subject, '')) = '' OR user_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' THEN
    RAISE EXCEPTION 'a subject and an email address are required' USING ERRCODE = 'PF004';
  END IF;
  domain := split_part(user_email, '@', 2);
  IF cardinality(i.email_domains) > 0 AND NOT domain = ANY (i.email_domains) THEN
    RAISE EXCEPTION 'the email domain % is not served by this IdP', domain USING ERRCODE = 'PF004';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.app_user x WHERE lower(x.email) = user_email) THEN
    RAISE EXCEPTION 'the email belongs to another account' USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.app_user (idp_id, external_id, email, display_name, status, source)
  VALUES (idp, subject, user_email, coalesce(nullif(btrim(name), ''), user_email), 'active', 'jit')
  RETURNING * INTO u;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'user.jit_provisioned', 'severity', 'low', 'actor', 'system:iam',
    'target', 'user:' || u.id, 'attributes', jsonb_build_object('idp', idp, 'email', u.email, 'external_id', subject)));
  RETURN u.id;
END $$;

-- Disables users inactive longer than auth.inactive_disable_after; returns
-- how many. Activity is the last sign-in or the last request of a session.
CREATE FUNCTION iam.inactivity_sweep() RETURNS integer
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
      AND greatest(coalesce(x.last_login_at, x.created_at),
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

REVOKE ALL ON FUNCTION iam.jit_provision(uuid, text, text, text), iam.inactivity_sweep() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.jit_provision(uuid, text, text, text), iam.inactivity_sweep() TO app_rw;

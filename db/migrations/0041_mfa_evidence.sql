-- F-001 T-18 (AC-05; design §5.1 step 4): MFA evidence rules.
--
--   * iam.login_user_privileged(u): does the user hold a privileged
--     permission (AC-54) anywhere? With auth.mfa_required_all off, the
--     auth.mfa_required_privileged floor still requires MFA of such users.
--   * iam.authn_event also records authn.mfa_missing (a login denied for
--     want of MFA evidence).
--   * iam.idp_admin_set_mfa_rule: an IdP's MFA evidence rule (validated by
--     the iam service), idp.manage, audited (high). An empty rule means the
--     built-in standards defaults.

CREATE FUNCTION iam.login_user_privileged(u uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1
    FROM iam.assignment a
    JOIN iam.role r ON r.id = a.role_id AND r.status = 'active'
    JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
    JOIN iam.permission p ON p.key = ANY (v.permissions) AND p.privileged
    WHERE a.revoked_at IS NULL
      AND (a.expires_at IS NULL OR a.expires_at > now())
      AND ((a.principal_kind = 'user' AND a.principal_id = u)
        OR (a.principal_kind = 'group' AND EXISTS (
              SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = u))));
$$;

CREATE OR REPLACE FUNCTION iam.authn_event(event text, severity text, actor text, idp uuid, attributes jsonb, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF event NOT IN ('authn.login.success', 'authn.login.denied', 'authn.mfa_missing') OR severity NOT IN ('info', 'low', 'high') THEN
    RAISE EXCEPTION 'unknown login event %', event USING ERRCODE = '22023';
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor, 'target', 'idp:' || idp,
                                      'reason', reason, 'attributes', coalesce(attributes, '{}')));
END $$;

CREATE FUNCTION iam.idp_admin_set_mfa_rule(idp uuid, rule jsonb, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  i iam.idp;
BEGIN
  UPDATE iam.idp x SET mfa_evidence_rule = coalesce(rule, '{}'::jsonb) WHERE x.id = idp RETURNING * INTO i;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'PF003';
  END IF;
  PERFORM iam.idp_event('idp.mfa_rule_changed', u, i, reason, jsonb_build_object('mfa_evidence_rule', i.mfa_evidence_rule));
END $$;

REVOKE ALL ON FUNCTION iam.login_user_privileged(uuid), iam.idp_admin_set_mfa_rule(uuid, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.login_user_privileged(uuid), iam.idp_admin_set_mfa_rule(uuid, jsonb, text) TO app_rw;

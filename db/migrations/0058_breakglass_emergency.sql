-- F-001 T-35 (AC-46; design §5.7): the IdP-outage recovery path.
--
-- While break-glass is off and every IdP is down nobody can sign in, so no
-- second administrator can approve enabling it (AC-41), and the install-time
-- path refuses once the installation is in use. The recovery is an operator
-- procedure with cluster-level access (the migrator's credentials, as for
-- `iam migrate`): `iam breakglass enable -emergency -operator NAME`
-- (docs/operations/idp-outage-recovery.md). It enables break-glass for one
-- or two holders as the install path does, with these differences:
--   * the operator's stated identity and reason are recorded; the event is
--     audited at critical severity and queued for every notification
--     channel (and the SaaS SecOps webhook);
--   * the posture exception (owner and approver: the Installer stand-in,
--     for the operator) lasts at most 24 hours, so break-glass and its
--     accounts turn off by themselves unless an administrator renews it
--     with the usual dual approval.

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Shortens the active break-glass exception to at most `most` from now.
CREATE FUNCTION posture.breakglass_limit(most interval) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  until timestamptz;
BEGIN
  UPDATE posture.exception e SET expires_at = least(e.expires_at, now() + most)
  WHERE e.key = 'breakglass.enabled' AND e.bu_id IS NULL AND NOT e.overlay AND e.state = 'active'
  RETURNING e.expires_at INTO until;
  IF until IS NULL THEN
    RAISE EXCEPTION 'no active break-glass exception' USING ERRCODE = 'PF003';
  END IF;
  RETURN until;
END $$;

REVOKE ALL ON FUNCTION posture.breakglass_limit(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.breakglass_limit(interval) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

-- The operator's emergency enablement (fair_owner only). Returns the
-- holders, as the install path does, plus the exception's expiry.
CREATE FUNCTION iam.breakglass_emergency_enable(holders jsonb, hashes bytea[], reason text, operator text)
RETURNS TABLE (accounts jsonb, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  who   text := btrim(coalesce(operator, ''));
  out   jsonb;
  until timestamptz;
  evt   jsonb;
BEGIN
  IF char_length(who) NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'the operator''s name is required (who ran the recovery)' USING ERRCODE = 'PF004';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required (the incident)' USING ERRCODE = 'PF004';
  END IF;
  out := iam.breakglass_enable_now('operator:' || who, iam.installer_user(), iam.installer_user(), NULL, holders, hashes, reason,
    jsonb_build_object('emergency', true, 'operator', who));
  until := posture.breakglass_limit(interval '24 hours');
  evt := jsonb_build_object('type', 'breakglass.emergency_enabled', 'operator', who, 'reason', btrim(reason), 'holders', out,
                            'expires_at', until, 'at', now());
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'breakglass.emergency_enabled', 'severity', 'critical', 'actor', 'operator:' || who,
    'target', 'breakglass', 'reason', btrim(reason), 'attributes', jsonb_build_object('holders', out, 'expires_at', until)));
  INSERT INTO iam.notice_outbox (kind, payload) VALUES ('breakglass.emergency_enabled', evt);
  PERFORM posture.breakglass_secops(evt);
  RETURN QUERY SELECT out, until;
END $$;

REVOKE ALL ON FUNCTION iam.breakglass_emergency_enable(jsonb, bytea[], text, text) FROM PUBLIC;

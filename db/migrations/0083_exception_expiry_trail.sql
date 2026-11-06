-- F-002 T-22 (F-015 design §8, §15): an exception's expiry is checked
-- against the audit trail.
--
-- F-015 promised that an exception whose expiry is edited in the database
-- is detected two ways: its row MAC (0035) and "expiry is checked against
-- the audit trail", deferred until the trail existed. The posture drift
-- scan now compares every live exception's expiry with the latest expiry
-- the trail recorded for it (setting.exception_created,
-- overlay.exception_created, setting.exception_renewed; attribute
-- expires_at, whole seconds) and reports exception_expiry_mismatch
-- (critical) when they differ. An exception with no online record (created
-- before the trail, or its records archived) is not compared: its MAC still
-- protects it.

SET ROLE audit_definer;

-- The latest recorded expiry of each given exception, from online records.
CREATE FUNCTION audit.exception_expiries(ids text[])
RETURNS TABLE (exception_id text, expires_at timestamptz, seq bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT ON (x.eid) x.eid, x.exp, x.seq
  FROM (SELECT b -> 'attributes' ->> 'exception_id' AS eid, (b -> 'attributes' ->> 'expires_at')::timestamptz AS exp, r.seq
        FROM audit.record r, LATERAL (SELECT convert_from(r.body, 'UTF8')::jsonb AS b) j
        WHERE r.type IN ('setting.exception_created', 'overlay.exception_created', 'setting.exception_renewed')
          AND b -> 'attributes' ->> 'exception_id' = ANY (ids)
          AND pg_input_is_valid(b -> 'attributes' ->> 'expires_at', 'timestamptz')) x
  ORDER BY x.eid, x.seq DESC;
$$;
REVOKE ALL ON FUNCTION audit.exception_expiries(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.exception_expiries(text[]) TO posture_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA audit TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Checks 1-3 (0035), and the exception expiry against the trail.
CREATE OR REPLACE FUNCTION posture.drift_scan(revert_grace interval DEFAULT interval '1 minute')
RETURNS TABLE (check_id text, severity text, controls text[], subject text, detail jsonb, remediation text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH ap AS (
    SELECT a.profile_id, a.version, p.family FROM posture.active_profile a
    JOIN posture.profile p ON p.id = a.profile_id AND p.version = a.version),
  vals AS (
    SELECT s.key, s.bu_id, s.value, s.source, pv.bound, ap.family,
           posture.below_floor(d, ap.family, s.value) AS below_floor,
           posture.compare(d, s.value, pv.bound) < 0 AS weaker,
           s.source = 'exception' AND EXISTS (
             SELECT 1 FROM posture.exception e
             WHERE e.id = s.exception_id AND e.key = s.key AND e.bu_id IS NOT DISTINCT FROM s.bu_id AND NOT e.overlay
               AND e.state IN ('active', 'revert_failed') AND e.value = s.value) AS covered
    FROM posture.setting_value s
    JOIN posture.setting_def d ON d.key = s.key
    CROSS JOIN ap
    JOIN posture.profile_value pv ON pv.profile_id = ap.profile_id AND pv.version = ap.version AND pv.key = s.key),
  ovals AS (
    SELECT o.key, o.value, posture.overlay_defaults() -> o.key AS bound, ap.family,
           posture.below_floor(d, ap.family, o.value) AS below_floor,
           posture.compare(d, o.value, posture.overlay_defaults() -> o.key) < 0 AS weaker,
           o.source = 'exception' AND EXISTS (
             SELECT 1 FROM posture.exception e
             WHERE e.id = o.exception_id AND e.key = o.key AND e.overlay
               AND e.state IN ('active', 'revert_failed') AND e.value = o.value) AS covered
    FROM posture.overlay_value o
    JOIN posture.setting_def d ON d.key = o.key
    CROSS JOIN ap),
  live AS (
    SELECT e.* FROM posture.exception e WHERE e.state IN ('active', 'revert_failed')),
  recorded AS (
    SELECT * FROM audit.exception_expiries(ARRAY(SELECT l.id::text FROM live l)))
  SELECT 'row_mac_mismatch', 'critical', ARRAY['CM-5', 'CM-6', 'SI-7'],
         CASE WHEN m.key LIKE 'overlay:%' OR m.key LIKE 'exception:%' THEN m.key ELSE posture.setting_subject(m.key, m.bu_id) END,
         jsonb_build_object('key', m.key, 'bu_id', m.bu_id),
         CASE WHEN m.key LIKE 'exception:%'
           THEN 'An exception record (its expiry, value, approver or state) was changed outside the posture service. Review the database audit log; treat the exception as untrusted and have it re-approved or revoked.'
           ELSE 'The stored value was changed outside the posture service. Review the database audit log, then set the value again through the Posture page or API.' END
  FROM posture.mac_mismatches() m
  UNION ALL
  SELECT 'hard_floor_violation', 'critical', ARRAY['CM-6', 'CM-7'], posture.setting_subject(v.key, v.bu_id),
         jsonb_build_object('key', v.key, 'bu_id', v.bu_id, 'value', v.value, 'source', v.source, 'profile_family', v.family),
         'A value below the hard floor is in force. Set it back to at least the floor at once; no exception can cover it.'
  FROM vals v WHERE v.below_floor
  UNION ALL
  SELECT 'unapproved_deviation', 'high', ARRAY['CM-3', 'CM-6'], posture.setting_subject(v.key, v.bu_id),
         jsonb_build_object('key', v.key, 'bu_id', v.bu_id, 'value', v.value, 'bound', v.bound, 'source', v.source),
         'The value is weaker than the active profile allows and no approved exception covers it. Tighten it, or request an exception.'
  FROM vals v WHERE NOT v.below_floor AND v.weaker AND NOT v.covered
  UNION ALL
  SELECT 'hard_floor_violation', 'critical', ARRAY['CM-6', 'CM-7'], 'overlay:' || o.key,
         jsonb_build_object('key', o.key, 'overlay', true, 'value', o.value, 'profile_family', o.family),
         'A Restricted BU overlay value below the hard floor is in force. Set it back to at least the floor at once.'
  FROM ovals o WHERE o.below_floor
  UNION ALL
  SELECT 'unapproved_deviation', 'high', ARRAY['CM-3', 'CM-6'], 'overlay:' || o.key,
         jsonb_build_object('key', o.key, 'overlay', true, 'value', o.value, 'bound', o.bound),
         'The Restricted BU overlay value is weaker than its default and no approved exception covers it. Tighten it, or request an exception.'
  FROM ovals o WHERE NOT o.below_floor AND o.weaker AND NOT o.covered
  UNION ALL
  SELECT 'missed_revert', 'high', ARRAY['CA-5', 'CM-6'], 'exception:' || e.id,
         jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'overlay', e.overlay, 'value', e.value, 'expired_at', e.expires_at),
         'An expired exception has not been reverted. Check that the posture service is running; the revert runs automatically.'
  FROM posture.exception e WHERE e.state = 'active' AND e.expires_at < now() - revert_grace
  UNION ALL
  SELECT 'exception_expiry_mismatch', 'critical', ARRAY['CM-5', 'CM-6', 'AU-9'], 'exception:' || l.id,
         jsonb_build_object('exception_id', l.id, 'key', l.key, 'bu_id', l.bu_id, 'overlay', l.overlay,
                            'expires_at', l.expires_at, 'recorded_expires_at', r.expires_at, 'recorded_seq', r.seq),
         'The exception''s expiry differs from the one the audit trail recorded when it was approved or renewed: it was changed '
         || 'outside the posture service. Treat the exception as untrusted; have it re-approved or revoked, and review the database audit log.'
  FROM live l JOIN recorded r ON r.exception_id = l.id::text
  WHERE date_trunc('second', l.expires_at) IS DISTINCT FROM r.expires_at;
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

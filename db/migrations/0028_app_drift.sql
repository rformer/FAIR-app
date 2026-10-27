-- F-015 T-25 (AC-36, AC-37; design §6.7): the application drift engine.
--
-- The posture service scans on every posture.setting.changed, whenever the
-- posture version moves (which also catches direct edits that fire the
-- version triggers), and at least every 15 minutes. Four checks:
--   1. row_mac_mismatch      (critical) a setting or overlay row whose MAC
--                            does not verify: an out-of-band edit;
--   2. unapproved_deviation  (high)     a value weaker than the active
--                            profile's bound (the overlay: its AC-33 default)
--                            without an exception that covers it;
--      hard_floor_violation  (critical) a value below the hard floor,
--                            exception or not;
--   3. missed_revert         (high)     an active exception still in force a
--                            minute after expiry (the revert loop runs every
--                            10 s; failures are T-18's revert_failed);
--   4. settings_mismatch / stale_settings_cache: from service heartbeats,
--                            compared in Go (internal/posture/drift.go)
--                            with the snapshot digest the settings library
--                            computes.
-- drift_scan() only reads. sync_drift_findings() opens, refreshes and
-- resolves the findings of the checks a scan ran, in the caller's
-- transaction, so the service audits each change inside it (fail closed).
-- Acknowledgement by people and the SIEM event schema are T-26.

-- Latest heartbeat per service instance (posture.settings.heartbeat, core
-- NATS). Untrusted input: validated and size-limited on the way in.
CREATE TABLE posture.service_heartbeat (
  service       text        NOT NULL CHECK (service ~ '^[A-Za-z0-9._-]{1,64}$'),
  instance      text        NOT NULL CHECK (instance ~ '^[A-Za-z0-9._:-]{1,128}$'),
  version       bigint      NOT NULL CHECK (version >= 0),
  verified      timestamptz,
  digest        text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  "values"      jsonb       NOT NULL CHECK (jsonb_typeof("values") = 'object' AND octet_length("values"::text) <= 65536),
  bu_overrides  integer     NOT NULL CHECK (bu_overrides >= 0),
  received_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (service, instance)
);
REVOKE ALL ON posture.service_heartbeat FROM PUBLIC;
ALTER TABLE posture.service_heartbeat ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.service_heartbeat FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.service_heartbeat TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON posture.service_heartbeat TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Stores a heartbeat (the JSON the settings library publishes).
CREATE FUNCTION posture.record_heartbeat(h jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  -- IS DISTINCT FROM: a missing field gives NULL, which must refuse too.
  IF jsonb_typeof(h) IS DISTINCT FROM 'object' OR jsonb_typeof(h -> 'version') IS DISTINCT FROM 'number'
     OR jsonb_typeof(h -> 'bu_overrides') IS DISTINCT FROM 'number' OR jsonb_typeof(h -> 'service') IS DISTINCT FROM 'string'
     OR jsonb_typeof(h -> 'instance') IS DISTINCT FROM 'string' OR jsonb_typeof(h -> 'digest') IS DISTINCT FROM 'string' THEN
    RAISE EXCEPTION 'malformed heartbeat' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO posture.service_heartbeat AS s (service, instance, version, verified, digest, "values", bu_overrides, received_at)
  VALUES (h ->> 'service', h ->> 'instance', (h ->> 'version')::bigint,
          CASE WHEN jsonb_typeof(h -> 'verified') = 'string' THEN (h ->> 'verified')::timestamptz END,
          h ->> 'digest', coalesce(h -> 'values', '{}'), (h ->> 'bu_overrides')::integer, now())
  ON CONFLICT (service, instance) DO UPDATE SET
    version = EXCLUDED.version, verified = EXCLUDED.verified, digest = EXCLUDED.digest, "values" = EXCLUDED."values",
    bu_overrides = EXCLUDED.bu_overrides, received_at = EXCLUDED.received_at;
  DELETE FROM posture.service_heartbeat s WHERE s.received_at < now() - interval '1 day';
EXCEPTION
  WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format
    OR datetime_field_overflow OR check_violation OR not_null_violation THEN
    RAISE EXCEPTION 'malformed heartbeat: %', SQLERRM USING ERRCODE = 'PF004';
END $$;

-- Heartbeats received within the window, with the posture version and when
-- it last changed (the database clock).
CREATE FUNCTION posture.recent_heartbeats(within interval)
RETURNS TABLE (service text, instance text, version bigint, digest text, "values" jsonb, received_at timestamptz,
               current_version bigint, changed_at timestamptz, now timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.service, h.instance, h.version, h.digest, h."values", h.received_at, st.version, st.changed_at, now()
  FROM posture.service_heartbeat h CROSS JOIN posture.state st
  WHERE h.received_at >= now() - within
  ORDER BY h.service, h.instance;
$$;

-- "setting:<key>" or "setting:<key>@<bu>".
CREATE FUNCTION posture.setting_subject(k text, bu uuid) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 'setting:' || k || coalesce('@' || bu::text, '');
$$;

-- Checks 1-3. Read-only.
CREATE FUNCTION posture.drift_scan(revert_grace interval DEFAULT interval '1 minute')
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
    CROSS JOIN ap)
  SELECT 'row_mac_mismatch', 'critical', ARRAY['CM-5', 'CM-6', 'SI-7'],
         CASE WHEN m.key LIKE 'overlay:%' THEN m.key ELSE posture.setting_subject(m.key, m.bu_id) END,
         jsonb_build_object('key', m.key, 'bu_id', m.bu_id),
         'The stored value was changed outside the posture service. Review the database audit log, then set the value again through the Posture page or API.'
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
  FROM posture.exception e WHERE e.state = 'active' AND e.expires_at < now() - revert_grace;
$$;

-- Opens or refreshes each finding and resolves the open findings of the
-- given checks that the scan no longer reports. Returns what changed:
-- opened (new) and resolved findings.
CREATE FUNCTION posture.sync_drift_findings(checks text[], findings jsonb)
RETURNS TABLE (action text, finding_id uuid, check_id text, severity text, controls text[], subject text, detail jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  f        jsonb;
  fid      uuid;
  inserted boolean;
  r        posture.drift_finding;
BEGIN
  IF cardinality(checks) = 0 OR EXISTS (SELECT 1 FROM unnest(checks) c WHERE c !~ '^[a-z][a-z0-9_]*$' OR c = 'revert_failed') THEN
    RAISE EXCEPTION 'invalid drift checks %', checks USING ERRCODE = 'PF004';
  END IF;
  FOR f IN SELECT x FROM jsonb_array_elements(coalesce(findings, '[]')) x LOOP
    IF NOT (f ->> 'check_id') = ANY (checks) THEN
      RAISE EXCEPTION 'finding for check % outside this scan', f ->> 'check_id' USING ERRCODE = 'PF004';
    END IF;
    INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
    VALUES ('app', f ->> 'check_id', f ->> 'severity', ARRAY(SELECT jsonb_array_elements_text(coalesce(f -> 'controls', '[]'))),
            f ->> 'subject', coalesce(f -> 'detail', '{}'), f ->> 'remediation')
    ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE
      SET last_seen = now(), detail = EXCLUDED.detail, severity = EXCLUDED.severity
    RETURNING d.id, (d.xmax = 0) INTO fid, inserted;
    IF inserted THEN
      SELECT * INTO r FROM posture.drift_finding d WHERE d.id = fid;
      action := 'opened'; finding_id := r.id; check_id := r.check_id; severity := r.severity;
      controls := r.controls; subject := r.subject; detail := r.detail;
      RETURN NEXT;
    END IF;
  END LOOP;
  FOR r IN
    UPDATE posture.drift_finding d SET status = 'resolved', resolved_at = now(), last_seen = now()
    WHERE d.status <> 'resolved' AND d.check_id = ANY (checks)
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(findings, '[]')) x
                      WHERE x ->> 'check_id' = d.check_id AND x ->> 'subject' = d.subject)
    RETURNING d.*
  LOOP
    action := 'resolved'; finding_id := r.id; check_id := r.check_id; severity := r.severity;
    controls := r.controls; subject := r.subject; detail := r.detail;
    RETURN NEXT;
  END LOOP;
END $$;

-- Open findings, for the Posture page and the service.
CREATE FUNCTION posture.open_drift_findings()
RETURNS TABLE (finding_id uuid, kind text, check_id text, severity text, controls text[], subject text, detail jsonb,
               remediation text, status text, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT f.id, f.kind, f.check_id, f.severity, f.controls, f.subject, f.detail, f.remediation, f.status, f.first_seen, f.last_seen
  FROM posture.drift_finding f WHERE f.status <> 'resolved'
  ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.first_seen, f.subject;
$$;

REVOKE ALL ON FUNCTION posture.record_heartbeat(jsonb), posture.recent_heartbeats(interval), posture.setting_subject(text, uuid),
  posture.drift_scan(interval), posture.sync_drift_findings(text[], jsonb), posture.open_drift_findings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.record_heartbeat(jsonb), posture.recent_heartbeats(interval), posture.drift_scan(interval),
  posture.sync_drift_findings(text[], jsonb), posture.open_drift_findings() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

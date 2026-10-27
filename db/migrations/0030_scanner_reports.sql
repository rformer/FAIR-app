-- F-015 T-27 (AC-38, AC-39; design §6.8): deployment findings reported by
-- posture-scanner over mTLS gRPC share the drift finding lifecycle (T-26)
-- with kind = 'deployment'. Each scan reports the checks it ran; posture
-- opens new findings and resolves those of the same checks no longer seen.
-- Deployment checks may not use the application drift checks' ids.
-- The latest report per scanner instance is kept for the Posture page and
-- the "Not assessed" logic of T-30.

CREATE TABLE posture.scanner_report (
  instance      text        PRIMARY KEY CHECK (instance ~ '^[A-Za-z0-9._-]{1,128}$'),
  received_at   timestamptz NOT NULL DEFAULT now(),
  started_at    timestamptz NOT NULL,
  finished_at   timestamptz NOT NULL,
  checks_run    text[]      NOT NULL,
  check_errors  jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(check_errors) = 'array'),
  findings      integer     NOT NULL CHECK (findings >= 0),
  CHECK (finished_at >= started_at)
);
REVOKE ALL ON posture.scanner_report FROM PUBLIC;
ALTER TABLE posture.scanner_report ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.scanner_report FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.scanner_report TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON posture.scanner_report TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

DROP FUNCTION posture.sync_drift_findings(text[], jsonb);
CREATE FUNCTION posture.sync_drift_findings(checks text[], findings jsonb, finding_kind text DEFAULT 'app')
RETURNS TABLE (action text, finding_id uuid, check_id text, kind text, severity text, controls text[], subject text,
               detail jsonb, remediation text, acknowledged_by uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  f        jsonb;
  fid      uuid;
  inserted boolean;
  r        posture.drift_finding;
  app_checks constant text[] := ARRAY['row_mac_mismatch', 'hard_floor_violation', 'unapproved_deviation', 'missed_revert',
                                      'settings_mismatch', 'stale_settings_cache', 'revert_failed'];
BEGIN
  IF finding_kind NOT IN ('app', 'deployment') THEN
    RAISE EXCEPTION 'invalid finding kind %', finding_kind USING ERRCODE = 'PF004';
  END IF;
  IF cardinality(checks) = 0 OR EXISTS (SELECT 1 FROM unnest(checks) c WHERE c !~ '^[a-z][a-z0-9_]*$' OR c = 'revert_failed')
     OR (finding_kind = 'deployment' AND checks && app_checks) THEN
    RAISE EXCEPTION 'invalid % checks %', finding_kind, checks USING ERRCODE = 'PF004';
  END IF;
  FOR f IN SELECT x FROM jsonb_array_elements(coalesce(findings, '[]')) x LOOP
    IF NOT (f ->> 'check_id') = ANY (checks) THEN
      RAISE EXCEPTION 'finding for check % outside this scan', f ->> 'check_id' USING ERRCODE = 'PF004';
    END IF;
    INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
    VALUES (finding_kind, f ->> 'check_id', f ->> 'severity', ARRAY(SELECT jsonb_array_elements_text(coalesce(f -> 'controls', '[]'))),
            f ->> 'subject', coalesce(f -> 'detail', '{}'), f ->> 'remediation')
    ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE
      SET last_seen = now(), detail = EXCLUDED.detail, severity = EXCLUDED.severity
    RETURNING d.id, (d.xmax = 0) INTO fid, inserted;
    IF inserted THEN
      SELECT * INTO r FROM posture.drift_finding d WHERE d.id = fid;
      action := 'opened'; finding_id := r.id; check_id := r.check_id; kind := r.kind; severity := r.severity;
      controls := r.controls; subject := r.subject; detail := r.detail; remediation := r.remediation; acknowledged_by := NULL;
      RETURN NEXT;
    END IF;
  END LOOP;
  FOR r IN
    UPDATE posture.drift_finding d SET status = 'resolved', resolved_at = now(), last_seen = now()
    WHERE d.status <> 'resolved' AND d.kind = finding_kind AND d.check_id = ANY (checks)
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(findings, '[]')) x
                      WHERE x ->> 'check_id' = d.check_id AND x ->> 'subject' = d.subject)
    RETURNING d.*
  LOOP
    action := 'resolved'; finding_id := r.id; check_id := r.check_id; kind := r.kind; severity := r.severity;
    controls := r.controls; subject := r.subject; detail := r.detail; remediation := r.remediation; acknowledged_by := r.acknowledged_by;
    RETURN NEXT;
  END LOOP;
END $$;

-- Records a scanner instance's latest report (called in the same
-- transaction as its findings).
CREATE FUNCTION posture.record_scanner_report(instance text, started_at timestamptz, finished_at timestamptz,
  checks_run text[], check_errors jsonb, findings integer) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO posture.scanner_report AS s (instance, received_at, started_at, finished_at, checks_run, check_errors, findings)
  VALUES (instance, now(), started_at, finished_at, checks_run, coalesce(check_errors, '[]'), findings)
  ON CONFLICT (instance) DO UPDATE SET received_at = now(), started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at,
    checks_run = EXCLUDED.checks_run, check_errors = EXCLUDED.check_errors, findings = EXCLUDED.findings;
$$;

-- Scanner instances and their latest reports, newest first.
CREATE FUNCTION posture.scanner_reports()
RETURNS TABLE (instance text, received_at timestamptz, started_at timestamptz, finished_at timestamptz,
               checks_run text[], check_errors jsonb, findings integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.instance, s.received_at, s.started_at, s.finished_at, s.checks_run, s.check_errors, s.findings
  FROM posture.scanner_report s ORDER BY s.received_at DESC, s.instance;
$$;

REVOKE ALL ON FUNCTION posture.sync_drift_findings(text[], jsonb, text),
  posture.record_scanner_report(text, timestamptz, timestamptz, text[], jsonb, integer), posture.scanner_reports() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.sync_drift_findings(text[], jsonb, text),
  posture.record_scanner_report(text, timestamptz, timestamptz, text[], jsonb, integer), posture.scanner_reports() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

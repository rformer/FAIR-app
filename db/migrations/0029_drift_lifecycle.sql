-- F-015 T-26 (AC-37, AC-42; design §6.7): the drift finding lifecycle.
--
--   open -> acknowledged -> resolved, and open -> resolved.
--   * Acknowledge: a holder of drift.acknowledge (signed DB context) states
--     a reason. Acknowledging records that people are handling the finding;
--     it never closes it, so drift cannot be silenced.
--   * Resolve: only the check that raised a finding resolves it, once the
--     condition is gone (sync_drift_findings for the drift engine, the
--     revert for revert_failed).
-- Each step is audited by the posture service inside its transaction, as
-- events whose schema is internal/posture/drift_events.schema.json (the
-- SIEM contract).

ALTER TABLE posture.drift_finding
  ADD COLUMN acknowledged_at     timestamptz,
  ADD COLUMN acknowledge_reason  text CHECK (acknowledge_reason IS NULL OR btrim(acknowledge_reason) <> ''),
  ADD CONSTRAINT drift_finding_acknowledged CHECK (
    (acknowledged_by IS NULL) = (acknowledged_at IS NULL) AND (acknowledged_by IS NULL) = (acknowledge_reason IS NULL)
    AND (status <> 'acknowledged' OR acknowledged_by IS NOT NULL));

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Acknowledges an open finding as the signed-context user, who needs
-- drift.acknowledge (findings are instance-wide: held at the root).
CREATE FUNCTION posture.acknowledge_drift(finding_id uuid, reason text)
RETURNS TABLE (check_id text, kind text, severity text, controls text[], subject text, remediation text, acknowledged_by uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
  f posture.drift_finding;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'acknowledging drift needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'drift.acknowledge', NULL) THEN
    RAISE EXCEPTION 'drift.acknowledge is required' USING ERRCODE = 'PF008';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'acknowledging a finding needs a stated reason' USING ERRCODE = 'PF002';
  END IF;
  UPDATE posture.drift_finding d
  SET status = 'acknowledged', acknowledged_by = u, acknowledged_at = now(), acknowledge_reason = btrim(reason)
  WHERE d.id = acknowledge_drift.finding_id AND d.status = 'open'
  RETURNING d.* INTO f;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'finding % is not open', finding_id USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY SELECT f.check_id, f.kind, f.severity, f.controls, f.subject, f.remediation, f.acknowledged_by;
END $$;

-- As in T-25, returning what the events carry: kind, remediation and, for a
-- resolved finding, who had acknowledged it.
DROP FUNCTION posture.sync_drift_findings(text[], jsonb);
CREATE FUNCTION posture.sync_drift_findings(checks text[], findings jsonb)
RETURNS TABLE (action text, finding_id uuid, check_id text, kind text, severity text, controls text[], subject text,
               detail jsonb, remediation text, acknowledged_by uuid)
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
      action := 'opened'; finding_id := r.id; check_id := r.check_id; kind := r.kind; severity := r.severity;
      controls := r.controls; subject := r.subject; detail := r.detail; remediation := r.remediation; acknowledged_by := NULL;
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
    action := 'resolved'; finding_id := r.id; check_id := r.check_id; kind := r.kind; severity := r.severity;
    controls := r.controls; subject := r.subject; detail := r.detail; remediation := r.remediation; acknowledged_by := r.acknowledged_by;
    RETURN NEXT;
  END LOOP;
END $$;

-- Findings for the Posture page: unresolved ones, plus resolved ones since
-- a time when given.
DROP FUNCTION posture.open_drift_findings();
CREATE FUNCTION posture.drift_findings(resolved_since timestamptz DEFAULT NULL)
RETURNS TABLE (finding_id uuid, kind text, check_id text, severity text, controls text[], subject text, detail jsonb,
               remediation text, status text, first_seen timestamptz, last_seen timestamptz,
               acknowledged_by uuid, acknowledged_at timestamptz, acknowledge_reason text, resolved_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT f.id, f.kind, f.check_id, f.severity, f.controls, f.subject, f.detail, f.remediation, f.status, f.first_seen, f.last_seen,
         f.acknowledged_by, f.acknowledged_at, f.acknowledge_reason, f.resolved_at
  FROM posture.drift_finding f
  WHERE f.status <> 'resolved' OR f.resolved_at >= resolved_since
  ORDER BY f.status = 'resolved', CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
           f.first_seen, f.subject;
$$;

REVOKE ALL ON FUNCTION posture.acknowledge_drift(uuid, text), posture.sync_drift_findings(text[], jsonb),
  posture.drift_findings(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.acknowledge_drift(uuid, text), posture.sync_drift_findings(text[], jsonb),
  posture.drift_findings(timestamptz) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

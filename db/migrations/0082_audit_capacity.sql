-- F-002 T-20 (F-002-AC-30, AC-31; design §6.8): audit storage capacity.
--
-- The leader measures the audit schema's storage (every table, partition,
-- index and TOAST relation in schema audit; intake included) against the
-- install's quota (FAIR_AUDIT_STORAGE_QUOTA, required in production) every
-- 5 minutes, and records the level in audit.capacity:
--   ok < 75% <= warning < 90% <= critical < 100% <= full.
-- Rising to warning records audit.capacity_warning (high), to critical or
-- full audit.capacity_critical (critical); the Posture finding
-- audit_capacity follows the level (high at warning, critical above) and
-- resolves below 75%.
--
-- The quota is a hard limit (decision of 2026-11-05, Robert Former): while
-- the trail is full, audit.intake refuses every event (PF015), so every
-- operation that would emit one fails in its own transaction and nothing is
-- dropped (AC-31). The audit service's own events (checkpoints,
-- verification, capacity, reads of the trail) are still accepted, so the
-- trail's integrity machinery keeps running.

CREATE TABLE audit.capacity (
  singleton    boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  quota        bigint      NOT NULL CHECK (quota > 0),
  used         bigint      NOT NULL CHECK (used >= 0),
  level        text        NOT NULL CHECK (level IN ('ok', 'warning', 'critical', 'full')),
  measured_at  timestamptz NOT NULL
);
REVOKE ALL ON audit.capacity FROM PUBLIC;
ALTER TABLE audit.capacity ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.capacity FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON audit.capacity TO audit_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON audit.capacity TO audit_definer;

SET ROLE audit_definer;

-- Measures the audit schema against quota, records the level, and returns
-- it with the previous one (NULL on the first measurement).
CREATE FUNCTION audit.capacity_measure(quota bigint, OUT used bigint, OUT level text, OUT previous text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pct numeric;
BEGIN
  IF quota IS NULL OR quota <= 0 THEN
    RAISE EXCEPTION 'audit.capacity_measure: a positive quota is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0) INTO used
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'audit' AND c.relkind IN ('r', 'm');
  pct := used::numeric * 100 / quota;
  level := CASE WHEN pct >= 100 THEN 'full' WHEN pct >= 90 THEN 'critical' WHEN pct >= 75 THEN 'warning' ELSE 'ok' END;
  SELECT x.level INTO previous FROM audit.capacity x FOR UPDATE;
  INSERT INTO audit.capacity AS x (quota, used, level, measured_at) VALUES (quota, used, level, clock_timestamp())
  ON CONFLICT (singleton) DO UPDATE SET quota = EXCLUDED.quota, used = EXCLUDED.used, level = EXCLUDED.level, measured_at = EXCLUDED.measured_at;
END $$;

-- AC-31: while the trail is full, events are refused, except the audit
-- service's own.
CREATE FUNCTION audit.refuse_when_full() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.producer IS DISTINCT FROM 'app_audit' AND EXISTS (SELECT 1 FROM audit.capacity c WHERE c.level = 'full') THEN
    RAISE EXCEPTION 'audit: the audit trail is full (its storage quota is reached); the operation is refused rather than its event dropped'
      USING ERRCODE = 'PF015';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION audit.refuse_when_full() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.refuse_when_full() TO fair_owner; -- creates the trigger
RESET ROLE;
SET LOCAL ROLE fair_owner;
CREATE TRIGGER intake_refuse_when_full BEFORE INSERT ON audit.intake FOR EACH ROW EXECUTE FUNCTION audit.refuse_when_full();
SET ROLE audit_definer;

-- The status (as in 0079), with storage use.
CREATE OR REPLACE FUNCTION audit.status() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  last_run  audit.verification;
  last_full audit.verification;
  last_ok   audit.verification;
  good_full timestamptz;
  failed    boolean;
  st        text;
  h         audit.head;
  cap       audit.capacity;
BEGIN
  SELECT * INTO last_run FROM audit.verification v WHERE v.finished_at IS NOT NULL ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_full FROM audit.verification v WHERE v.finished_at IS NOT NULL AND v.kind = 'full' ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_ok FROM audit.verification v WHERE v.ok ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT max(v.finished_at) INTO good_full FROM audit.verification v WHERE v.kind = 'full' AND v.ok;
  SELECT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok IS FALSE AND (good_full IS NULL OR v.finished_at > good_full)) INTO failed;
  SELECT * INTO h FROM audit.head;
  SELECT * INTO cap FROM audit.capacity;
  st := CASE
    WHEN last_run.id IS NULL THEN 'never'
    WHEN failed THEN 'failed'
    WHEN NOT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok AND v.finished_at > now() - interval '30 minutes')
      OR good_full IS NULL OR good_full < now() - interval '26 hours' THEN 'overdue'
    ELSE 'ok' END;
  RETURN jsonb_build_object(
    'state', st,
    'last_run', CASE WHEN last_run.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_run.id, 'kind', last_run.kind,
      'finished_at', last_run.finished_at, 'ok', last_run.ok, 'to_seq', last_run.to_seq, 'to_segment', last_run.to_segment,
      'failed_at_seq', last_run.failed_at_seq, 'failed_at_segment', last_run.failed_at_segment, 'detail', last_run.detail) END,
    'last_full', CASE WHEN last_full.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_full.id, 'finished_at', last_full.finished_at,
      'ok', last_full.ok, 'to_seq', last_full.to_seq, 'to_segment', last_full.to_segment) END,
    'last_verified_at', last_ok.finished_at,
    'verified_through_seq', last_ok.to_seq,
    'head_seq', coalesce(h.seq, 0),
    'open_segment', h.open_segment,
    'intake_waiting', (SELECT count(*) FROM audit.intake),
    'checkpoint_copies_waiting', (SELECT count(*) FROM audit.checkpoint c WHERE c.worm_key IS NULL),
    'destinations', coalesce((SELECT jsonb_agg(jsonb_build_object('name', d.name, 'kind', d.kind, 'address', d.address,
      'last_seq', d.last_seq,
      'backlog', CASE WHEN d.address IS NULL THEN 0 ELSE greatest(coalesce(h.seq, 0) - d.last_seq, 0) END,
      'oldest_waiting_at', CASE WHEN d.address IS NULL THEN NULL ELSE
        (SELECT r.received_at FROM audit.record r WHERE r.seq > d.last_seq ORDER BY r.seq LIMIT 1) END,
      'backlog_alert', d.backlog_alerted,
      'last_sent_at', d.last_sent_at, 'last_error', d.last_error) ORDER BY d.name)
      FROM audit.destination d), '[]'::jsonb),
    'storage', CASE WHEN cap.quota IS NULL THEN NULL ELSE jsonb_build_object('quota', cap.quota, 'used', cap.used,
      'percent', round(cap.used::numeric * 100 / cap.quota, 1), 'level', cap.level, 'measured_at', cap.measured_at) END);
END $$;

REVOKE ALL ON FUNCTION audit.capacity_measure(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.capacity_measure(bigint) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- --- The capacity finding (posture) ----------------------------------------

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Follows the capacity level: ok resolves the audit_capacity finding;
-- warning opens or refreshes it at high severity, critical and full at
-- critical. Returns opened, refreshed, resolved or unchanged.
CREATE FUNCTION posture.audit_capacity_finding(level text, detail jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  inserted boolean;
  sev      text;
BEGIN
  IF level IS NULL OR level NOT IN ('ok', 'warning', 'critical', 'full') THEN
    RAISE EXCEPTION 'posture.audit_capacity_finding: level is ok, warning, critical or full' USING ERRCODE = 'PF004';
  END IF;
  IF level = 'ok' THEN
    UPDATE posture.drift_finding f SET status = 'resolved', resolved_at = now(), last_seen = now()
    WHERE f.check_id = 'audit_capacity' AND f.subject = 'audit-trail' AND f.status <> 'resolved';
    RETURN CASE WHEN FOUND THEN 'resolved' ELSE 'unchanged' END;
  END IF;
  IF detail IS NULL OR jsonb_typeof(detail) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'posture.audit_capacity_finding: the detail is an object' USING ERRCODE = 'PF004';
  END IF;
  sev := CASE WHEN level = 'warning' THEN 'high' ELSE 'critical' END;
  INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
  VALUES ('app', 'audit_capacity', sev, ARRAY['AU-4', 'AU-5'], 'audit-trail', detail,
          'Audit storage is filling up. Raise FAIR_AUDIT_STORAGE_QUOTA (and the database storage behind it), or shorten the online '
          || 'retention so more segments move to the archive (a loosening that needs a second approver). At 100% every operation '
          || 'that records an event is refused until there is room again.')
  ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE SET last_seen = now(), detail = EXCLUDED.detail, severity = EXCLUDED.severity
  RETURNING (d.xmax = 0) INTO inserted;
  RETURN CASE WHEN inserted THEN 'opened' ELSE 'refreshed' END;
END $$;
REVOKE ALL ON FUNCTION posture.audit_capacity_finding(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.audit_capacity_finding(text, jsonb) TO app_audit;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

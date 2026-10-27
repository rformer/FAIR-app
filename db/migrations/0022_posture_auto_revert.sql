-- F-015 T-18 (AC-27 - AC-29; design §6.3): automatic revert of expired
-- exceptions, retries, and the critical revert_failed finding.
--
--   * due_reverts() claims expired active exceptions, and failed ones whose
--     retry is due, under a short lease (replicas never revert the same one
--     at once). The posture service reverts each in its own transaction as
--     system:posture, every 10 s, so a revert takes effect well within 60 s
--     (AC-28) once caches refresh.
--   * apply_revert (T-09) now also resolves the exception's open
--     revert_failed finding and queues the owner/admin notice (AC-27).
--   * record_revert_failure() marks the exception revert_failed, backs off
--     (5 s doubling, capped at 5 minutes), and opens or refreshes a critical
--     revert_failed finding that only a successful revert resolves (AC-29).
--     It reports when the hourly escalation is due.
-- posture.drift_finding is the table of design §5; its acknowledge/resolve
-- lifecycle for people (T-26) and the drift engine (T-25) come later.

CREATE TABLE posture.drift_finding (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind               text        NOT NULL CHECK (kind IN ('app', 'deployment')),
  check_id           text        NOT NULL CHECK (check_id ~ '^[a-z][a-z0-9_]*$'),
  severity           text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  controls           text[]      NOT NULL DEFAULT '{}',
  subject            text        NOT NULL,
  detail             jsonb       NOT NULL DEFAULT '{}',
  remediation        text        NOT NULL,
  first_seen         timestamptz NOT NULL DEFAULT now(),
  last_seen          timestamptz NOT NULL DEFAULT now(),
  status             text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  acknowledged_by    uuid        REFERENCES iam.app_user (id),
  resolved_at        timestamptz,
  last_escalated_at  timestamptz,
  CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);
-- One unresolved finding per check and subject.
CREATE UNIQUE INDEX drift_finding_open ON posture.drift_finding (check_id, subject) WHERE status <> 'resolved';
REVOKE ALL ON posture.drift_finding FROM PUBLIC;
ALTER TABLE posture.drift_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.drift_finding FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.drift_finding TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON posture.drift_finding TO posture_definer;

ALTER TABLE posture.exception
  ADD COLUMN revert_attempts   integer     NOT NULL DEFAULT 0,
  ADD COLUMN revert_next_at    timestamptz,
  ADD COLUMN revert_last_error text;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Expired exceptions to revert now: active ones past expiry, and failed
-- ones whose retry is due. Claimed for one minute.
CREATE FUNCTION posture.due_reverts(max_rows integer DEFAULT 50)
RETURNS TABLE (exception_id uuid, key text, bu_id uuid, owner_id uuid, attempts integer)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE posture.exception e SET revert_next_at = now() + interval '1 minute'
  WHERE e.id IN (SELECT x.id FROM posture.exception x
                 WHERE (x.state = 'active' AND x.expires_at <= now() AND (x.revert_next_at IS NULL OR x.revert_next_at <= now()))
                    OR (x.state = 'revert_failed' AND x.revert_next_at <= now())
                 ORDER BY x.expires_at LIMIT max_rows FOR UPDATE SKIP LOCKED)
  RETURNING e.id, e.key, e.bu_id, e.owner_id, e.revert_attempts;
$$;

CREATE OR REPLACE FUNCTION posture.apply_revert(exception_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e posture.exception;
BEGIN
  SELECT * INTO e FROM posture.exception x WHERE x.id = apply_revert.exception_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'exception % does not exist', exception_id USING ERRCODE = 'PF003';
  END IF;
  IF e.state NOT IN ('active', 'revert_failed') THEN
    RAISE EXCEPTION 'exception % is %, not active', exception_id, e.state USING ERRCODE = 'PF003';
  END IF;
  IF now() < e.expires_at THEN
    RAISE EXCEPTION 'exception % does not expire until %', exception_id, e.expires_at USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.setting_value s WHERE s.key = e.key AND s.bu_id IS NOT DISTINCT FROM e.bu_id
             AND s.exception_id = e.id AND s.source = 'exception') THEN
    IF e.bu_id IS NULL THEN
      PERFORM posture.write_value(e.key, NULL, (posture.active_binding(e.key)).default_value, 'revert', NULL, e.id);
    ELSE
      DELETE FROM posture.setting_value s WHERE s.key = e.key AND s.bu_id = e.bu_id;
    END IF;
  END IF;
  UPDATE posture.exception x SET state = 'reverted', revert_next_at = NULL, revert_last_error = NULL WHERE x.id = e.id;
  UPDATE posture.drift_finding f SET status = 'resolved', resolved_at = now(), last_seen = now()
  WHERE f.check_id = 'revert_failed' AND f.subject = 'exception:' || e.id AND f.status <> 'resolved';
  INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES ('setting.exception_reverted',
    jsonb_build_object('users', jsonb_build_array(e.owner_id), 'permission_holders', 'settings.approve'),
    jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'value', e.value, 'expired_at', e.expires_at,
                       'attempts', e.revert_attempts + 1));
END $$;

-- A revert failed: back off, keep a critical finding open, and report
-- whether the hourly escalation is due (it is recorded as sent).
CREATE FUNCTION posture.record_revert_failure(exception_id uuid, error text, OUT escalate boolean, OUT attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e posture.exception;
  f posture.drift_finding;
BEGIN
  UPDATE posture.exception x
  SET state = 'revert_failed', revert_attempts = x.revert_attempts + 1, revert_last_error = left(error, 1000),
      revert_next_at = now() + least(interval '5 minutes', interval '5 seconds' * power(2, least(x.revert_attempts, 10)))
  WHERE x.id = record_revert_failure.exception_id AND x.state IN ('active', 'revert_failed')
  RETURNING x.* INTO e;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'exception % is not awaiting a revert', exception_id USING ERRCODE = 'PF003';
  END IF;
  attempts := e.revert_attempts;
  INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
  VALUES ('app', 'revert_failed', 'critical', ARRAY['CA-5', 'CM-6'], 'exception:' || e.id,
          jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'value', e.value,
                             'expired_at', e.expires_at, 'attempts', e.revert_attempts, 'last_error', e.revert_last_error),
          'The setting is still out of bounds after its exception expired. Restore the failing dependency; the revert retries automatically.')
  ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE
    SET last_seen = now(), detail = EXCLUDED.detail
  RETURNING d.* INTO f;
  escalate := f.last_escalated_at IS NULL OR f.last_escalated_at <= now() - interval '1 hour';
  IF escalate THEN
    UPDATE posture.drift_finding d SET last_escalated_at = now() WHERE d.id = f.id;
    INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES ('setting.revert_failed',
      jsonb_build_object('users', jsonb_build_array(e.owner_id), 'permission_holders', 'settings.approve'),
      jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'finding_id', f.id,
                         'attempts', e.revert_attempts, 'last_error', e.revert_last_error));
  END IF;
END $$;

REVOKE ALL ON FUNCTION posture.due_reverts(integer), posture.record_revert_failure(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.due_reverts(integer), posture.record_revert_failure(uuid, text) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

-- F-015 T-15 (AC-23): in SaaS mode, every weakening change notifies the
-- vendor's security operations channel. Vendor approval is not required.
--
-- Decisions (Robert Former, 2026-10-27):
--   * The deployment mode is recorded here, set once by the installer as
--     fair_owner (posture.set_deployment_mode); services must be configured
--     with the same mode (FAIR_DEPLOYMENT_MODE) or the posture service
--     refuses to start.
--   * apply_change itself enqueues the notification, in the change's own
--     transaction, when the mode is saas: neither the service nor a direct
--     call can apply a weakening without it, and a crash cannot lose it.
--   * The posture service delivers the outbox to a signed HTTPS webhook,
--     retrying with backoff until acknowledged. F-009 may take over the
--     transport later without changing the outbox.

ALTER TABLE posture.state ADD COLUMN deployment_mode text CHECK (deployment_mode IN ('saas', 'self-hosted'));

CREATE TABLE posture.secops_outbox (
  id               bigserial   PRIMARY KEY,
  event            jsonb       NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  attempts         integer     NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  last_error       text,
  delivered_at     timestamptz
);
CREATE INDEX secops_outbox_due ON posture.secops_outbox (next_attempt_at) WHERE delivered_at IS NULL;
REVOKE ALL ON posture.secops_outbox FROM PUBLIC;
ALTER TABLE posture.secops_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.secops_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.secops_outbox TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON posture.secops_outbox TO posture_definer;
GRANT USAGE ON SEQUENCE posture.secops_outbox_id_seq TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Installer: record the deployment mode (fair_owner only).
CREATE FUNCTION posture.set_deployment_mode(mode text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF mode IS NULL OR mode NOT IN ('saas', 'self-hosted') THEN
    RAISE EXCEPTION 'deployment mode must be saas or self-hosted' USING ERRCODE = 'PF004';
  END IF;
  UPDATE posture.state SET deployment_mode = mode;
END $$;

CREATE FUNCTION posture.deployment_mode() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT deployment_mode FROM posture.state;
$$;

CREATE OR REPLACE FUNCTION posture.apply_change(change_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c   posture.change;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  ttl jsonb;
  cur jsonb;
  exc uuid;
BEGIN
  SELECT * INTO c FROM posture.change x WHERE x.id = apply_change.change_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'change % does not exist', change_id USING ERRCODE = 'PF003';
  END IF;
  IF c.state NOT IN ('requested', 'pending_approval') THEN
    RAISE EXCEPTION 'change % is %', change_id, c.state USING ERRCODE = 'PF003';
  END IF;
  d := posture.check_value(c.key, c.new_value);
  b := posture.active_binding(c.key);
  PERFORM posture.check_floor(d, b.family, c.new_value); -- never below the floor, exception or not (AC-30)
  cur := posture.current_value(c.key, c.bu_id);

  IF c.state = 'requested' THEN
    IF posture.compare(d, c.new_value, b.bound) < 0 THEN
      RAISE EXCEPTION 'change % is now outside the active profile bound %; request it again', change_id, b.bound USING ERRCODE = 'PF002';
    END IF;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'change', c.id, NULL);
  ELSE
    a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds', 'posture.change:' || c.id);
    ttl := posture.current_value('exception.max_duration', NULL);
    INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
    VALUES (c.key, c.bu_id, c.new_value, b.bound, c.explanation, c.requested_by, (a ->> 'decided_by')::uuid,
            now() + make_interval(secs => posture.duration_ns(ttl #>> '{}') / 1e9), 'active')
    RETURNING e.id INTO exc;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'exception', NULL, exc);
  END IF;
  UPDATE posture.change x SET state = 'applied', applied_at = now() WHERE x.id = c.id;

  -- AC-23: a weakening (against the value in force until now) or any
  -- exception notifies vendor SecOps in SaaS mode.
  IF posture.deployment_mode() = 'saas' AND (exc IS NOT NULL OR posture.compare(d, c.new_value, cur) < 0) THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object(
      'type', CASE WHEN exc IS NULL THEN 'setting.weakened' ELSE 'setting.exception_created' END,
      'key', c.key, 'bu_id', c.bu_id, 'previous', cur, 'value', c.new_value, 'bound', b.bound,
      'profile_family', b.family, 'change_id', c.id, 'exception_id', exc, 'requested_by', c.requested_by,
      'approved_by', a ->> 'decided_by', 'explanation', c.explanation, 'at', now()));
  END IF;
  RETURN exc;
END $$;

-- Delivery (the posture service): claim due notifications for a short lease,
-- then report each as delivered or failed. Claimed rows are invisible to
-- other replicas until the lease runs out.
CREATE FUNCTION posture.secops_claim(max_rows integer DEFAULT 50, lease interval DEFAULT interval '2 minutes')
RETURNS TABLE (id bigint, event jsonb, attempts integer)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE posture.secops_outbox o SET next_attempt_at = now() + lease
  WHERE o.id IN (SELECT x.id FROM posture.secops_outbox x
                 WHERE x.delivered_at IS NULL AND x.next_attempt_at <= now()
                 ORDER BY x.id LIMIT max_rows FOR UPDATE SKIP LOCKED)
  RETURNING o.id, o.event, o.attempts;
$$;

CREATE FUNCTION posture.secops_delivered(notification_id bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE posture.secops_outbox SET delivered_at = now(), attempts = attempts + 1, last_error = NULL
  WHERE id = notification_id AND delivered_at IS NULL;
$$;

-- Backoff: 10 s doubling per attempt, capped at 15 minutes.
CREATE FUNCTION posture.secops_failed(notification_id bigint, error text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE posture.secops_outbox
  SET attempts = attempts + 1, last_error = left(error, 1000),
      next_attempt_at = now() + least(interval '15 minutes', interval '10 seconds' * power(2, least(attempts, 10)))
  WHERE id = notification_id AND delivered_at IS NULL;
$$;

-- Oldest undelivered notification's age, for readiness and drift (T-25).
CREATE FUNCTION posture.secops_backlog(OUT pending bigint, OUT oldest timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(*), min(created_at) FROM posture.secops_outbox WHERE delivered_at IS NULL;
$$;

REVOKE ALL ON FUNCTION posture.set_deployment_mode(text), posture.deployment_mode(),
  posture.secops_claim(integer, interval), posture.secops_delivered(bigint), posture.secops_failed(bigint, text),
  posture.secops_backlog() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.set_deployment_mode(text) TO fair_owner;
GRANT EXECUTE ON FUNCTION posture.deployment_mode(), posture.secops_claim(integer, interval), posture.secops_delivered(bigint),
  posture.secops_failed(bigint, text), posture.secops_backlog() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

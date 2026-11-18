-- F-011 T-17 (F-011-AC-04, AC-08, AC-14; design §3.3): the connector
-- runner's functions, for app_integrate (no context: the runner acts as the
-- integrate service; what it submits goes through the gateway as the
-- integration's service account).
--
--   * integration.claim_due(lease_seconds, lim): due active connector
--     integrations, FOR UPDATE SKIP LOCKED, each claimed with a token and
--     its next run moved by the lease (so a replica that dies gives it
--     back); the trigger is manual when a run was asked for (run_now),
--     else schedule.
--   * integration.connector_succeeded(id, token, run): the claim's run was
--     received (by the risk service, as the service account; finish_run
--     reset the failures); the next run is a schedule away.
--   * integration.connector_failed(id, token, failure, refused_host): a
--     failed run is recorded (trigger, the service account as actor,
--     complete, the failure) with integration.run (high); a refused
--     source also records integration.destination_refused (during run,
--     AC-04); failures count up and the next run backs off exponentially
--     (the schedule times 2^(failures - 1), at most a day); the third
--     consecutive failure queues integration.run_failed to the
--     integration's managers (F-009, AC-08), once per streak.
--   * A claim whose integration was paused meanwhile is recorded and not
--     rescheduled; one deleted meanwhile is recorded only; a stale token
--     (PF031 claim_lost) changes nothing.
--   * notify.collect: source integration, kind integration.run_failed,
--     item integration (permission holders of integration.manage at the
--     integration's BU; notify.recheck checks them).

ALTER TABLE integration.integration ADD COLUMN claim_token uuid;
ALTER TABLE integration.integration ADD COLUMN claimed_at timestamptz;
ALTER TABLE integration.integration ADD COLUMN last_failure text CHECK (char_length(last_failure) <= 500);
ALTER TABLE integration.integration ADD CONSTRAINT integration_claim CHECK ((claim_token IS NULL) = (claimed_at IS NULL));
CREATE UNIQUE INDEX integration_notice_failed_once ON integration.notice_outbox (run_id) WHERE kind = 'integration.run_failed';

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.claim_due(lease_seconds integer, lim integer)
RETURNS TABLE (id uuid, bu_id uuid, kind text, mapping jsonb, connector jsonb, service_account_id uuid, trigger text, token uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF lease_seconds IS NULL OR lease_seconds NOT BETWEEN 60 AND 3600 OR lim IS NULL OR lim NOT BETWEEN 1 AND 50 THEN
    RAISE EXCEPTION 'integration: a lease of 60 to 3,600 seconds, 1 to 50 integrations' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  RETURN QUERY
  WITH due AS (
    SELECT x.id FROM integration.integration x
    WHERE x.state = 'active' AND x.delivery = 'connector' AND x.next_run_at <= now()
    ORDER BY x.next_run_at, x.id LIMIT lim FOR UPDATE SKIP LOCKED)
  UPDATE integration.integration i SET claim_token = gen_random_uuid(), claimed_at = now(), next_run_at = now() + make_interval(secs => lease_seconds)
  FROM due WHERE i.id = due.id
  RETURNING i.id, i.bu_id, i.kind, i.mapping, i.connector, i.service_account_id,
    CASE WHEN i.run_requested_by IS NOT NULL THEN 'manual' ELSE 'schedule' END, i.claim_token;
END $$;

-- The claimed integration, locked; PF031 claim_lost for a stale token.
CREATE FUNCTION integration.claimed(id uuid, token uuid) RETURNS integration.integration
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = claimed.id FOR UPDATE;
  IF i.id IS NULL OR i.claim_token IS DISTINCT FROM token THEN
    RAISE EXCEPTION 'integration: the claim on % was lost', id USING ERRCODE = 'PF031', HINT = 'claim_lost';
  END IF;
  RETURN i;
END $$;

CREATE FUNCTION integration.connector_succeeded(id uuid, token uuid, run uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.claimed(id, token);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM integration.run r WHERE r.id = connector_succeeded.run AND r.integration_id = i.id AND r.state = 'succeeded'
                 AND r.actor = i.service_account_id) THEN
    RAISE EXCEPTION 'integration: % is not a received run of the integration''s service account', run USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  IF i.state = 'deleted' THEN
    RETURN;
  END IF;
  UPDATE integration.integration x SET claim_token = NULL, claimed_at = NULL, run_requested_by = NULL, run_requested_at = NULL,
    failures = 0, last_failure = NULL,
    next_run_at = CASE WHEN x.state = 'active' THEN now() + make_interval(mins => (x.connector ->> 'schedule_minutes')::integer) END
  WHERE x.id = i.id;
END $$;

CREATE FUNCTION integration.connector_failed(id uuid, token uuid, failure text, refused_host text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.claimed(id, token); r integration.run;
  f text := left(coalesce(nullif(btrim(failure), ''), 'failed'), 500); n integer; mins integer;
BEGIN
  INSERT INTO integration.run (integration_id, trigger, actor, complete, state, failure, finished_at)
  VALUES (i.id, CASE WHEN i.run_requested_by IS NOT NULL THEN 'manual' ELSE 'schedule' END, i.service_account_id, true, 'failed', f, now())
  RETURNING * INTO r;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'integration.run', 'severity', 'high', 'actor', 'system:integrate', 'target', 'integration:' || i.id,
    'bu_id', i.bu_id, 'attributes', jsonb_build_object('integration', i.id::text, 'name', i.name, 'run', r.id::text, 'trigger', r.trigger,
      'complete', 'true', 'state', 'failed', 'failure', f)));
  IF refused_host IS NOT NULL THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'integration.destination_refused', 'severity', 'high', 'actor', 'system:integrate',
      'target', 'integration:' || i.id, 'bu_id', i.bu_id,
      'attributes', jsonb_build_object('integration', i.id::text, 'name', i.name, 'host', lower(left(refused_host, 255)), 'detail', f, 'during', 'run')));
  END IF;
  n := i.failures + 1;
  IF i.state = 'deleted' THEN
    RETURN jsonb_build_object('run', r.id, 'failures', n, 'next_run_at', NULL);
  END IF;
  mins := least((i.connector ->> 'schedule_minutes')::integer * (2 ^ least(n - 1, 10))::integer, 1440);
  UPDATE integration.integration x SET claim_token = NULL, claimed_at = NULL, run_requested_by = NULL, run_requested_at = NULL,
    failures = n, last_failure = f, next_run_at = CASE WHEN x.state = 'active' THEN now() + make_interval(mins => mins) END
  WHERE x.id = i.id RETURNING * INTO i;
  IF n = 3 THEN
    INSERT INTO integration.notice_outbox (kind, integration_id, run_id) VALUES ('integration.run_failed', i.id, r.id);
  END IF;
  RETURN jsonb_build_object('run', r.id, 'failures', n, 'next_run_at', i.next_run_at);
END $$;

-- integration.json shows the last failure.
CREATE OR REPLACE FUNCTION integration.json(i integration.integration) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', i.id, 'bu_id', i.bu_id, 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = i.bu_id), 'name', i.name,
    'kind', i.kind, 'delivery', i.delivery, 'mapping', i.mapping, 'connector', i.connector, 'service_account_id', i.service_account_id,
    'service_account_name', (SELECT s.name FROM iam.service_account s WHERE s.id = i.service_account_id), 'auto_accept', i.auto_accept,
    'state', i.state, 'version', i.version, 'created_at', i.created_at, 'changed_at', i.changed_at, 'deleted_at', i.deleted_at,
    'next_run_at', i.next_run_at, 'last_run_at', i.last_run_at, 'failures', i.failures, 'last_failure', i.last_failure,
    'run_requested_at', i.run_requested_at,
    'credentials', coalesce((SELECT jsonb_agg(jsonb_build_object('purpose', s.purpose, 'set_at', s.set_at) ORDER BY s.purpose)
                             FROM integration.secret s WHERE s.integration_id = i.id), '[]'));
$$;

REVOKE ALL ON FUNCTION integration.claim_due(integer, integer), integration.claimed(uuid, uuid), integration.connector_succeeded(uuid, uuid, uuid),
  integration.connector_failed(uuid, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.claim_due(integer, integer), integration.connector_succeeded(uuid, uuid, uuid),
  integration.connector_failed(uuid, uuid, text, text) TO app_integrate;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

CREATE OR REPLACE FUNCTION notify.collect(titles boolean, batch integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r         record;
  it        jsonb;
  collected integer := 0;
  unknown   integer := 0;
  n         uuid;
BEGIN
  IF batch IS NULL OR batch < 1 OR batch > 10000 THEN
    RAISE EXCEPTION 'notify.collect: batch is 1 to 10,000' USING ERRCODE = 'PF028', HINT = 'invalid_batch';
  END IF;
  -- F-004: estimate requests, to their estimator.
  FOR r IN SELECT * FROM estimate.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := estimate.notice_item(r.request_id);
    n := notify.add_notice('estimate', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'estimate_request', r.request_id::text,
      '/estimates/' || r.request_id, it ->> 'title', jsonb_build_object('users', jsonb_build_array(r.user_id)), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE estimate.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-008: acceptances, to the users the row names or (decision_needed)
  -- the approvers who may decide it, resolved at fan-out.
  FOR r IN SELECT * FROM acceptance.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := acceptance.notice_item(r.acceptance_id);
    n := notify.add_notice('acceptance', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'acceptance', r.acceptance_id::text,
      '/acceptances/' || r.acceptance_id, it ->> 'title',
      CASE WHEN r.user_id IS NULL THEN jsonb_build_object('deciders', r.acceptance_id) ELSE jsonb_build_object('users', jsonb_build_array(r.user_id)) END,
      titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE acceptance.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-015: setting exceptions, to the users and permission holders named.
  FOR r IN SELECT * FROM posture.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    n := notify.add_notice('posture', r.kind, r.id::text, r.created_at, (r.payload ->> 'bu_id')::uuid, 'posture', r.payload ->> 'exception_id',
      '/posture', r.payload ->> 'key', r.recipients, titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE posture.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-001: break-glass, to the holders of breakglass.manage.
  FOR r IN SELECT * FROM iam.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    n := notify.add_notice('iam', r.kind, r.id::text, r.created_at, NULL, 'breakglass', r.payload ->> 'user_id',
      '/audit?target=' || coalesce('user:' || (r.payload ->> 'user_id'), 'breakglass'), NULL,
      jsonb_build_object('permission_holders', 'breakglass.manage'), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE iam.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- Security findings, to the holders of drift.acknowledge.
  FOR r IN SELECT * FROM posture.finding_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    n := notify.add_notice('finding', 'finding.opened', r.id::text, r.created_at, NULL, 'finding', r.finding_id::text, '/posture',
      r.check_id, jsonb_build_object('permission_holders', 'drift.acknowledge', 'severity', r.severity), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE posture.finding_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-007: the register's stale and overdue notices, to the risk's owner.
  FOR r IN SELECT * FROM register.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := register.notice_risk(r.risk_id);
    n := notify.add_notice('register', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'risk', r.risk_id::text,
      '/register/risks/' || r.risk_id, it ->> 'title', jsonb_build_object('users', jsonb_build_array(r.user_id)), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE register.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-010: reports, to their requester (ready, failed) or a schedule's
  -- owner (suspended).
  FOR r IN SELECT * FROM report.notice_outbox o WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := report.notice_item(r.run_id, r.schedule_id);
    n := notify.add_notice('report', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid,
      CASE WHEN r.run_id IS NULL THEN 'report_schedule' ELSE 'report' END, coalesce(r.run_id, r.schedule_id)::text,
      CASE WHEN r.run_id IS NULL THEN '/reports/schedules/' || r.schedule_id ELSE '/reports/' || r.run_id END, it ->> 'title',
      jsonb_build_object('users', jsonb_build_array(r.user_id)), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE report.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-011: an integration's proposals waiting for review, to the holders
  -- of their kind's edit permission at its BU.
  FOR r IN SELECT * FROM integration.notice_outbox o WHERE o.delivered_at IS NULL AND o.kind = 'integration.proposals_waiting'
           ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := integration.notice_item(r.integration_id);
    n := notify.add_notice('integration', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'integration_run', r.run_id::text,
      '/integrations/proposals?run=' || r.run_id, it ->> 'title', jsonb_build_object('permission_holders', r.permission), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE integration.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-011: a control a scenario relies on is no longer in place, to the
  -- scenario's owner.
  FOR r IN SELECT * FROM integration.notice_outbox o WHERE o.delivered_at IS NULL AND o.kind = 'control.lapsed'
           ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := integration.lapsed_item(r.scenario_id);
    n := notify.add_notice('integration', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'scenario', r.scenario_id::text,
      '/scenarios/' || r.scenario_id, it ->> 'title', jsonb_build_object('users', jsonb_build_array(r.user_id)), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE integration.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  -- F-011 T-17: a connector failed three runs in a row, to the holders of
  -- integration.manage at its BU.
  FOR r IN SELECT * FROM integration.notice_outbox o WHERE o.delivered_at IS NULL AND o.kind = 'integration.run_failed'
           ORDER BY o.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    it := integration.notice_item(r.integration_id);
    n := notify.add_notice('integration', r.kind, r.id::text, r.created_at, (it ->> 'bu_id')::uuid, 'integration', r.integration_id::text,
      '/integrations/' || r.integration_id, it ->> 'title', jsonb_build_object('permission_holders', 'integration.manage'), titles);
    IF n IS NULL THEN unknown := unknown + 1; CONTINUE; END IF;
    UPDATE integration.notice_outbox o SET delivered_at = now() WHERE o.id = r.id;
    collected := collected + 1;
  END LOOP;
  RETURN jsonb_build_object('collected', collected, 'unknown', unknown);
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

-- F-010 T-16 (F-010-AC-19 to AC-21; OQ5; design §3.7): scheduled reports
-- and their notices.
--
--   * report.schedule gains reason (the reason rule applies to schedules as
--     to requests; their runs carry it).
--   * report.next_time(cadence, weekday, monthday, hour, after): the first
--     time strictly after after (UTC): daily at the hour; weekly on the
--     weekday (0 Sunday to 6 Saturday); monthly on the day (1 to 28).
--   * The owner's functions, from the signed context (report_definer):
--     report.create_schedule, update_schedule (expected_version; the kind
--     and BU stay), delete_schedule (a reason), resume_schedule (suspended
--     to active), my_schedules, get_schedule. report.export at the BU
--     (42501), owner only (P0002 otherwise), at most 20 live (PF030);
--     events report.schedule_created, _changed, _deleted, _resumed.
--   * report.due_schedules(batch) (the leader, as app_rw without a
--     context): each active schedule due is re-checked (its owner active,
--     holding report.export at its BU): it becomes a queued run (the River
--     job is queued by the caller in the same transaction), or the schedule
--     is suspended (inactive, no_permission; report.schedule_suspended and
--     a notice to the owner). Either way next_at moves to the first time
--     after now, so an outage gives one run per schedule (AC-21).
--   * A scheduled run's success or failure queues report.ready or
--     report.failed to its owner (report.complete_run, report.failed).
--   * F-009: the notice source report (notify.kind), notify.collect reads
--     report.notice_outbox (items report and report_schedule, linked to
--     /reports/<run> and /reports/schedules/<id>), notify.recheck sends a
--     report notice only to its run's requester or its schedule's owner.

ALTER TABLE report.schedule ADD COLUMN reason text CHECK (char_length(reason) BETWEEN 1 AND 500);

DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint WHERE conrelid = 'notify.kind'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%source%';
  EXECUTE format('ALTER TABLE notify.kind DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE notify.kind ADD CONSTRAINT kind_source_check
  CHECK (source IN ('estimate', 'acceptance', 'posture', 'iam', 'finding', 'register', 'report', 'notify'));

GRANT USAGE ON SCHEMA report TO notify_definer;
GRANT SELECT, UPDATE (delivered_at) ON report.notice_outbox TO notify_definer;
GRANT SELECT (id, requested_by, bu_id, kind) ON report.run TO notify_definer;
GRANT SELECT (id, owner, bu_id, kind) ON report.schedule TO notify_definer;

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

CREATE FUNCTION report.next_time(cadence text, weekday integer, monthday integer, hour integer, after timestamptz) RETURNS timestamptz
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t timestamp := after AT TIME ZONE 'UTC';
  c timestamp;
BEGIN
  IF cadence = 'daily' THEN
    c := date_trunc('day', t) + make_interval(hours => hour);
    IF c <= t THEN c := c + interval '1 day'; END IF;
  ELSIF cadence = 'weekly' THEN
    c := date_trunc('day', t) + make_interval(days => ((weekday - extract(dow FROM t)::integer + 7) % 7), hours => hour);
    IF c <= t THEN c := c + interval '7 days'; END IF;
  ELSIF cadence = 'monthly' THEN
    c := date_trunc('month', t) + make_interval(days => monthday - 1, hours => hour);
    IF c <= t THEN c := date_trunc('month', t) + interval '1 month' + make_interval(days => monthday - 1, hours => hour); END IF;
  ELSE
    RAISE EXCEPTION 'report: cadence is daily, weekly or monthly' USING ERRCODE = 'PF029', HINT = 'invalid_schedule';
  END IF;
  RETURN c AT TIME ZONE 'UTC';
END $$;

CREATE FUNCTION report.emit_schedule(type text, severity text, actor text, id uuid, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', severity, 'actor', actor, 'target', 'report_schedule:' || id, 'bu_id', bu,
    'attributes', attrs || jsonb_build_object('schedule', id::text)));
$$;

-- A schedule's cadence fields, checked (PF029 invalid_schedule).
CREATE FUNCTION report.check_cadence(cadence text, weekday integer, monthday integer, hour integer) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF cadence IS NULL OR cadence NOT IN ('daily', 'weekly', 'monthly') OR hour IS NULL OR hour NOT BETWEEN 0 AND 23
     OR (cadence = 'weekly') <> (weekday IS NOT NULL) OR (cadence = 'monthly') <> (monthday IS NOT NULL)
     OR (weekday IS NOT NULL AND weekday NOT BETWEEN 0 AND 6) OR (monthday IS NOT NULL AND monthday NOT BETWEEN 1 AND 28) THEN
    RAISE EXCEPTION 'report: a schedule is daily, weekly with a weekday (0 to 6) or monthly with a day (1 to 28), at an hour (0 to 23, UTC)'
      USING ERRCODE = 'PF029', HINT = 'invalid_schedule';
  END IF;
END $$;

CREATE FUNCTION report.schedule_json(s report.schedule) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', s.id, 'kind', s.kind, 'bu_id', s.bu_id, 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = s.bu_id),
    'params', s.params, 'formats', to_jsonb(s.formats), 'cadence', s.cadence, 'weekday', s.weekday, 'monthday', s.monthday, 'hour', s.hour,
    'reason', s.reason, 'next_at', s.next_at, 'state', s.state, 'suspended_reason', s.suspended_reason, 'version', s.version,
    'created_at', s.created_at,
    'last_run', (SELECT jsonb_build_object('id', r.id, 'state', r.state, 'requested_at', r.requested_at) FROM report.run r
                 WHERE r.schedule_id = s.id ORDER BY r.requested_at DESC LIMIT 1));
$$;

-- The caller's live schedule id, locked; P0002 for another's or a deleted one.
CREATE FUNCTION report.my_schedule(id uuid) RETURNS report.schedule
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s report.schedule;
BEGIN
  SELECT * INTO s FROM report.schedule x WHERE x.id = my_schedule.id AND x.owner = report.actor() AND x.deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such schedule %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN s;
END $$;

CREATE FUNCTION report.create_schedule(kind text, bu uuid, params jsonb, formats text[], cadence text, weekday integer, monthday integer,
  hour integer, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := report.actor();
  id uuid := gen_random_uuid();
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = create_schedule.bu AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'report: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.holds_permission(u, 'report.export', bu) THEN
    RAISE EXCEPTION 'report: scheduling a report needs report.export at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  PERFORM report.check_cadence(cadence, weekday, monthday, hour);
  INSERT INTO report.schedule (id, owner, bu_id, kind, params, formats, cadence, weekday, monthday, hour, next_at, reason)
  VALUES (id, u, bu, kind, coalesce(params, '{}'), formats, cadence, weekday, monthday, hour,
          report.next_time(cadence, weekday, monthday, hour, now()), nullif(btrim(reason), ''));
  PERFORM report.emit_schedule('report.schedule_created', 'low', u::text, id, bu, jsonb_build_object('kind', kind, 'cadence', cadence,
    'formats', array_to_string(formats, ' '), 'filters', coalesce(params, '{}')::text, 'reason', coalesce(nullif(btrim(reason), ''), '')));
  RETURN id;
END $$;

CREATE FUNCTION report.update_schedule(id uuid, expected_version integer, params jsonb, formats text[], cadence text, weekday integer,
  monthday integer, hour integer, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s report.schedule := report.my_schedule(id);
BEGIN
  IF s.version <> expected_version THEN
    RAISE EXCEPTION 'report: the schedule changed since version %', expected_version USING ERRCODE = 'PF029', HINT = 'stale_version';
  END IF;
  IF NOT iam.holds_permission(s.owner, 'report.export', s.bu_id) THEN
    RAISE EXCEPTION 'report: changing a schedule needs report.export at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  PERFORM report.check_cadence(cadence, weekday, monthday, hour);
  UPDATE report.schedule x SET params = coalesce(update_schedule.params, '{}'), formats = update_schedule.formats, cadence = update_schedule.cadence,
    weekday = update_schedule.weekday, monthday = update_schedule.monthday, hour = update_schedule.hour, reason = nullif(btrim(update_schedule.reason), ''),
    next_at = report.next_time(update_schedule.cadence, update_schedule.weekday, update_schedule.monthday, update_schedule.hour, now()),
    version = x.version + 1
  WHERE x.id = s.id;
  PERFORM report.emit_schedule('report.schedule_changed', 'low', s.owner::text, s.id, s.bu_id, jsonb_build_object('kind', s.kind,
    'cadence', cadence, 'formats', array_to_string(formats, ' '), 'filters', coalesce(params, '{}')::text,
    'reason', coalesce(nullif(btrim(reason), ''), ''), 'version', (s.version + 1)::text));
END $$;

CREATE FUNCTION report.delete_schedule(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s report.schedule := report.my_schedule(id);
BEGIN
  IF nullif(btrim(coalesce(reason, '')), '') IS NULL OR char_length(reason) > 1000 THEN
    RAISE EXCEPTION 'report: deleting a schedule takes a reason (1 to 1,000 characters)' USING ERRCODE = 'PF029', HINT = 'reason_required';
  END IF;
  UPDATE report.schedule x SET deleted_at = now() WHERE x.id = s.id;
  PERFORM report.emit_schedule('report.schedule_deleted', 'low', s.owner::text, s.id, s.bu_id, jsonb_build_object('kind', s.kind,
    'reason', btrim(reason)));
END $$;

CREATE FUNCTION report.resume_schedule(id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s report.schedule := report.my_schedule(id);
BEGIN
  IF s.state <> 'suspended' THEN
    RAISE EXCEPTION 'report: the schedule is not suspended' USING ERRCODE = 'PF029', HINT = 'not_suspended';
  END IF;
  IF NOT iam.holds_permission(s.owner, 'report.export', s.bu_id) THEN
    RAISE EXCEPTION 'report: resuming a schedule needs report.export at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  UPDATE report.schedule x SET state = 'active', suspended_reason = NULL, version = x.version + 1,
    next_at = report.next_time(x.cadence, x.weekday, x.monthday, x.hour, now())
  WHERE x.id = s.id;
  PERFORM report.emit_schedule('report.schedule_resumed', 'low', s.owner::text, s.id, s.bu_id, jsonb_build_object('kind', s.kind,
    'version', (s.version + 1)::text));
END $$;

CREATE FUNCTION report.my_schedules() RETURNS SETOF jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT report.schedule_json(s) FROM report.schedule s WHERE s.owner = report.actor() AND s.deleted_at IS NULL ORDER BY s.created_at, s.id;
$$;

CREATE FUNCTION report.get_schedule(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s report.schedule;
BEGIN
  SELECT * INTO s FROM report.schedule x WHERE x.id = get_schedule.id AND x.owner = report.actor() AND x.deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such schedule %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN report.schedule_json(s);
END $$;

-- The leader's due schedules (design §3.7): {runs: [ids], suspended: n}.
CREATE FUNCTION report.due_schedules(batch integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s report.schedule;
  run uuid;
  runs uuid[] := '{}';
  suspended integer := 0;
  why text;
BEGIN
  IF batch IS NULL OR batch NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'report: batch is 1 to 1,000' USING ERRCODE = 'PF029', HINT = 'invalid_batch';
  END IF;
  FOR s IN SELECT * FROM report.schedule x WHERE x.state = 'active' AND x.deleted_at IS NULL AND x.next_at <= now()
           ORDER BY x.next_at, x.id LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    why := CASE WHEN NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = s.owner AND u.status = 'active') THEN 'inactive'
                WHEN NOT iam.holds_permission(s.owner, 'report.export', s.bu_id) THEN 'no_permission' END;
    IF why IS NULL THEN
      run := gen_random_uuid();
      INSERT INTO report.run (id, requested_by, bu_id, kind, params, formats, reason, schedule_id)
      VALUES (run, s.owner, s.bu_id, s.kind, s.params, s.formats, s.reason, s.id);
      PERFORM report.emit('report.requested', 'low', 'system:risk', run, s.bu_id, jsonb_build_object('kind', s.kind,
        'filters', s.params::text, 'formats', array_to_string(s.formats, ' '), 'reason', coalesce(s.reason, ''), 'risk_count', ''));
      runs := runs || run;
      UPDATE report.schedule x SET next_at = report.next_time(x.cadence, x.weekday, x.monthday, x.hour, now()) WHERE x.id = s.id;
    ELSE
      UPDATE report.schedule x SET state = 'suspended', suspended_reason = why, version = x.version + 1,
        next_at = report.next_time(x.cadence, x.weekday, x.monthday, x.hour, now())
      WHERE x.id = s.id;
      PERFORM report.emit_schedule('report.schedule_suspended', 'low', 'system:risk', s.id, s.bu_id, jsonb_build_object('kind', s.kind,
        'suspended_reason', why, 'owner', s.owner::text));
      INSERT INTO report.notice_outbox (kind, user_id, schedule_id) VALUES ('report.schedule_suspended', s.owner, s.id);
      suspended := suspended + 1;
    END IF;
  END LOOP;
  RETURN jsonb_build_object('runs', to_jsonb(runs), 'suspended', suspended);
END $$;

-- A notice's item for F-009: its business unit and a title (the kind).
CREATE FUNCTION report.notice_item(run uuid, schedule uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(
    (SELECT jsonb_build_object('bu_id', r.bu_id, 'title', initcap(r.kind) || ' report') FROM report.run r WHERE r.id = notice_item.run),
    (SELECT jsonb_build_object('bu_id', s.bu_id, 'title', initcap(s.kind) || ' report schedule') FROM report.schedule s WHERE s.id = notice_item.schedule),
    '{}');
$$;

CREATE OR REPLACE FUNCTION report.failed(r report.run, failure text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE report.run x SET state = 'failed', context_nonce = NULL, failure = left(failed.failure, 500), finished_at = now() WHERE x.id = r.id;
  PERFORM report.emit('report.failed', 'low', 'system:risk', r.id, r.bu_id, jsonb_build_object('kind', r.kind,
    'failure', split_part(failed.failure, ':', 1), 'requested_by', r.requested_by::text));
  IF r.schedule_id IS NOT NULL THEN
    INSERT INTO report.notice_outbox (kind, user_id, run_id) VALUES ('report.failed', r.requested_by, r.id);
  END IF;
END $$;

CREATE OR REPLACE FUNCTION report.complete_run(id uuid, nonce text, files jsonb, data_as_of timestamptz, risk_count integer, left_out jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r report.run := report.running(id, nonce);
  f jsonb;
BEGIN
  IF jsonb_typeof(files) <> 'array' OR (SELECT array_agg(x ->> 'format' ORDER BY x ->> 'format') FROM jsonb_array_elements(files) x)
     IS DISTINCT FROM (SELECT array_agg(v ORDER BY v) FROM unnest(r.formats) v) THEN
    RAISE EXCEPTION 'report: a run stores one file per requested format' USING ERRCODE = 'PF029', HINT = 'files';
  END IF;
  FOR f IN SELECT * FROM jsonb_array_elements(files) LOOP
    INSERT INTO report.file (run_id, format, object_key, version_id, size, sha256)
    VALUES (r.id, f ->> 'format', f ->> 'object_key', f ->> 'version_id', (f ->> 'size')::bigint, f ->> 'sha256');
  END LOOP;
  UPDATE report.run x SET state = 'succeeded', context_nonce = NULL, progress = 100, data_as_of = complete_run.data_as_of,
    risk_count = complete_run.risk_count, left_out = coalesce(complete_run.left_out, '{}'), finished_at = now() WHERE x.id = r.id;
  PERFORM report.emit('report.generated', 'low', 'system:risk', r.id, r.bu_id, jsonb_build_object('kind', r.kind,
    'files', (SELECT string_agg((x ->> 'format') || ':' || (x ->> 'sha256'), ' ' ORDER BY x ->> 'format') FROM jsonb_array_elements(files) x),
    'risk_count', coalesce(complete_run.risk_count, 0)::text, 'left_out', coalesce(complete_run.left_out, '{}')::text,
    'requested_by', r.requested_by::text));
  IF r.schedule_id IS NOT NULL THEN
    INSERT INTO report.notice_outbox (kind, user_id, run_id) VALUES ('report.ready', r.requested_by, r.id);
  END IF;
END $$;

REVOKE ALL ON FUNCTION report.next_time(text, integer, integer, integer, timestamptz), report.emit_schedule(text, text, text, uuid, uuid, jsonb),
  report.check_cadence(text, integer, integer, integer), report.schedule_json(report.schedule), report.my_schedule(uuid),
  report.create_schedule(text, uuid, jsonb, text[], text, integer, integer, integer, text),
  report.update_schedule(uuid, integer, jsonb, text[], text, integer, integer, integer, text), report.delete_schedule(uuid, text),
  report.resume_schedule(uuid), report.my_schedules(), report.get_schedule(uuid), report.due_schedules(integer), report.notice_item(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.create_schedule(text, uuid, jsonb, text[], text, integer, integer, integer, text),
  report.update_schedule(uuid, integer, jsonb, text[], text, integer, integer, integer, text), report.delete_schedule(uuid, text),
  report.resume_schedule(uuid), report.my_schedules(), report.get_schedule(uuid), report.due_schedules(integer) TO app_rw;
GRANT EXECUTE ON FUNCTION report.notice_item(uuid, uuid) TO notify_definer;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

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
  RETURN jsonb_build_object('collected', collected, 'unknown', unknown);
END $$;

CREATE OR REPLACE FUNCTION notify.recheck(n notify.notice, u uuid, via text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM iam.app_user x WHERE x.id = u AND x.status = 'active') THEN 'inactive'
    WHEN via IS NOT NULL AND NOT EXISTS (SELECT 1 FROM iam.permission_holders(via, n.bu_id, 100000) h WHERE h.id = u) THEN 'no_permission'
    WHEN n.item_type = 'acceptance' AND NOT coalesce((SELECT (s.read_bus -> 'acceptance') ? n.bu_id::text FROM authz.user_scope s WHERE s.user_id = u), false)
      THEN 'not_visible'
    WHEN n.item_type = 'estimate_request' AND NOT estimate.notice_addressed(n.item_id::uuid, u) THEN 'not_visible'
    WHEN n.item_type = 'risk' AND NOT coalesce((SELECT (s.read_bus -> 'register') ? n.bu_id::text FROM authz.user_scope s WHERE s.user_id = u), false)
      THEN 'not_visible'
    WHEN n.item_type = 'report' AND NOT EXISTS (SELECT 1 FROM report.run x WHERE x.id = n.item_id::uuid AND x.requested_by = u) THEN 'not_visible'
    WHEN n.item_type = 'report_schedule' AND NOT EXISTS (SELECT 1 FROM report.schedule x WHERE x.id = n.item_id::uuid AND x.owner = u) THEN 'not_visible'
  END
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

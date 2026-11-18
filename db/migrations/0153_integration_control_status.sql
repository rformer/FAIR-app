-- F-011 T-13 (F-011-AC-23, AC-24; design §3.7): control status end to end.
--
--   * integration.control_lapsed(control, version): in the transaction that
--     accepted a proposal making the control's version (integration.applied),
--     when implementation.status went from in_place to anything else, queues
--     control.lapsed for the owner of every scenario whose latest version
--     uses the control as in_place in a current control set, once per
--     (control version, scenario).
--   * Those scenarios are found as integration_definer, whatever the
--     reviewer sees: definer reads of risk.scenario, scenario_version and
--     scenario_pin (ADR-007 amendment 3; no other definer reads them).
--   * F-009: notify.collect reads control.lapsed (item scenario);
--     notify.recheck checks a scenario notice's reader sees the scenario.

SELECT authz.allow_definer('risk.scenario', 'integration_definer');
SELECT authz.allow_definer('risk.scenario_version', 'integration_definer');
SELECT authz.allow_definer('risk.scenario_pin', 'integration_definer');
GRANT SELECT ON risk.scenario, risk.scenario_version, risk.scenario_pin, risk.control, risk.control_version TO integration_definer;

ALTER TABLE integration.notice_outbox ADD COLUMN control_version integer CHECK (control_version >= 2);
ALTER TABLE integration.notice_outbox ADD CONSTRAINT notice_outbox_lapsed_version CHECK ((kind = 'control.lapsed') = (control_version IS NOT NULL));
CREATE UNIQUE INDEX integration_notice_lapsed_once ON integration.notice_outbox (control_id, control_version, scenario_id) WHERE kind = 'control.lapsed';

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.control_lapsed(control uuid, version integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u    uuid := integration.actor();
  prev text;
  cur  text;
  n    integer := 0;
BEGIN
  -- Only a version an accepted proposal made, in the accepting transaction.
  IF NOT EXISTS (SELECT 1 FROM integration.applied a WHERE a.target_type = 'control' AND a.target_id = control AND a.version = control_lapsed.version
                 AND a.accepted_by = u AND a.accepted_at = now()) THEN
    RAISE EXCEPTION 'integration: control % version % was not accepted from a proposal here', control, version USING ERRCODE = 'PF031', HINT = 'not_accepted';
  END IF;
  SELECT convert_from(v.document, 'UTF8')::jsonb #>> '{implementation,status}' INTO cur FROM risk.control_version v
    WHERE v.control_id = control AND v.version = control_lapsed.version;
  SELECT convert_from(v.document, 'UTF8')::jsonb #>> '{implementation,status}' INTO prev FROM risk.control_version v
    WHERE v.control_id = control AND v.version = control_lapsed.version - 1;
  IF prev IS DISTINCT FROM 'in_place' OR cur IS NOT DISTINCT FROM 'in_place' THEN
    RETURN 0;
  END IF;
  INSERT INTO integration.notice_outbox (kind, user_id, control_id, control_version, scenario_id)
  SELECT 'control.lapsed', s.owner, control, control_lapsed.version, s.id
  FROM risk.scenario s JOIN risk.scenario_version v ON v.scenario_id = s.id AND v.version = s.current_version
  WHERE s.archived_at IS NULL AND s.owner IS NOT NULL
    AND s.id IN (SELECT p.scenario_id FROM risk.scenario_pin p WHERE p.to_kind = 'control' AND p.to_id = control)
    AND EXISTS (SELECT 1 FROM jsonb_array_elements(convert_from(v.document, 'UTF8')::jsonb -> 'control_sets') cs,
                     jsonb_array_elements(cs -> 'controls') cu
                WHERE (cs ->> 'current')::boolean AND cu ->> 'id' = control::text AND cu ->> 'status' = 'in_place')
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- What a control.lapsed notice says of its scenario (notify.collect).
CREATE FUNCTION integration.lapsed_item(scenario uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', s.bu_id, 'title', s.name) FROM risk.scenario s WHERE s.id = lapsed_item.scenario;
$$;

REVOKE ALL ON FUNCTION integration.control_lapsed(uuid, integer), integration.lapsed_item(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.control_lapsed(uuid, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION integration.lapsed_item(uuid) TO notify_definer;

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
    WHEN n.item_type = 'scenario' AND NOT coalesce((SELECT (s.read_bus -> 'scenario') ? n.bu_id::text FROM authz.user_scope s WHERE s.user_id = u), false)
      THEN 'not_visible'
    WHEN n.item_type = 'report' AND NOT EXISTS (SELECT 1 FROM report.run x WHERE x.id = n.item_id::uuid AND x.requested_by = u) THEN 'not_visible'
    WHEN n.item_type = 'report_schedule' AND NOT EXISTS (SELECT 1 FROM report.schedule x WHERE x.id = n.item_id::uuid AND x.owner = u) THEN 'not_visible'
  END
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

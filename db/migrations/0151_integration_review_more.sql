-- F-011 T-10b (F-011-AC-11, AC-13, AC-20, AC-25; design §3.4, §3.8, §10):
-- risks, auto-accept, provenance on reads and the proposals_waiting notice.
--
--   * integration.owner_by_email(proposal, email): the active user with
--     that email who reads the register at the proposal's BU (a risk's
--     owner; none otherwise).
--   * integration.run_descriptive(run): the caller's running run's pending
--     descriptive-only proposals (auto_accept tries them as the pusher).
--   * integration.provenance(target_type, target_id): each version that
--     came from an integration, with its integration, run, external ID and
--     who accepted it when; only to holders of the kind's view permission
--     at the proposal's BU.
--   * integration.notify_waiting(run): queues integration.proposals_waiting
--     once per run that leaves proposals pending, for the holders of the
--     kind's edit permission at the integration's BU (F-009 source
--     integration: notify.kind's source check, notify.collect).

GRANT SELECT (id, email, status, display_name) ON iam.app_user TO integration_definer;
GRANT USAGE ON SCHEMA authz TO integration_definer;
GRANT SELECT (user_id, read_bus) ON authz.user_scope TO integration_definer;

ALTER TABLE integration.notice_outbox ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE integration.notice_outbox ADD COLUMN permission text CHECK (permission IN ('library.edit', 'control.edit', 'register.edit'));
ALTER TABLE integration.notice_outbox ADD CONSTRAINT notice_outbox_waiting CHECK (
  (kind = 'integration.proposals_waiting') = (permission IS NOT NULL AND run_id IS NOT NULL AND user_id IS NULL));
CREATE UNIQUE INDEX integration_notice_waiting_once ON integration.notice_outbox (run_id) WHERE kind = 'integration.proposals_waiting';

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.owner_by_email(proposal uuid, email text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE p integration.proposal := integration.visible_proposal(proposal, false);
BEGIN
  RETURN (SELECT a.id FROM iam.app_user a JOIN authz.user_scope s ON s.user_id = a.id
          WHERE lower(a.email) = lower(btrim(owner_by_email.email)) AND a.status = 'active' AND coalesce((s.read_bus -> 'register') ? p.bu_id::text, false)
          LIMIT 1);
END $$;

CREATE FUNCTION integration.run_descriptive(run uuid) RETURNS SETOF uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run);
BEGIN
  RETURN QUERY SELECT p.id FROM integration.proposal p WHERE p.run_id = r.id AND p.state = 'pending' AND p.descriptive_only ORDER BY p.seq;
END $$;

CREATE FUNCTION integration.provenance(target_type text, target_id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor();
BEGIN
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('version', a.version, 'integration_id', i.id, 'integration_name', i.name, 'run_id', p.run_id,
      'external_id', p.external_id, 'received_at', r.started_at, 'accepted_at', a.accepted_at,
      'accepted_by_name', (SELECT x.display_name FROM iam.app_user x WHERE x.id = a.accepted_by)) ORDER BY a.version)
    FROM integration.applied a JOIN integration.proposal p ON p.id = a.proposal_id
    JOIN integration.integration i ON i.id = p.integration_id JOIN integration.run r ON r.id = p.run_id
    WHERE a.target_type = provenance.target_type AND a.target_id = provenance.target_id
      AND iam.holds_permission(u, integration.view_permission(p.target_type), p.bu_id)), '[]');
END $$;

CREATE FUNCTION integration.notify_waiting(run uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run); i integration.integration;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = r.integration_id;
  IF NOT EXISTS (SELECT 1 FROM integration.proposal p WHERE p.run_id = r.id AND p.state = 'pending') THEN
    RETURN false;
  END IF;
  INSERT INTO integration.notice_outbox (kind, integration_id, run_id, permission)
  VALUES ('integration.proposals_waiting', i.id, r.id,
          CASE i.kind WHEN 'control_status' THEN 'control.edit' WHEN 'risks' THEN 'register.edit' ELSE 'library.edit' END)
  ON CONFLICT DO NOTHING;
  RETURN true;
END $$;

-- What a notice says of its integration (notify.collect).
CREATE FUNCTION integration.notice_item(id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', i.bu_id, 'title', i.name) FROM integration.integration i WHERE i.id = notice_item.id;
$$;

REVOKE ALL ON FUNCTION integration.owner_by_email(uuid, text), integration.run_descriptive(uuid), integration.provenance(text, uuid),
  integration.notify_waiting(uuid), integration.notice_item(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.owner_by_email(uuid, text), integration.run_descriptive(uuid), integration.provenance(text, uuid),
  integration.notify_waiting(uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION integration.notice_item(uuid) TO notify_definer;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

-- F-009: the source integration.
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint WHERE conrelid = 'notify.kind'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%source%';
  EXECUTE format('ALTER TABLE notify.kind DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE notify.kind ADD CONSTRAINT kind_source_check
  CHECK (source IN ('estimate', 'acceptance', 'posture', 'iam', 'finding', 'register', 'report', 'integration', 'notify'));

GRANT USAGE ON SCHEMA integration TO notify_definer;
GRANT SELECT, UPDATE (delivered_at) ON integration.notice_outbox TO notify_definer;

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
  RETURN jsonb_build_object('collected', collected, 'unknown', unknown);
END $$;


RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

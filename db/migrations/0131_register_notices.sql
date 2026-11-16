-- F-009 T-12 (F-009-AC-20; design §3.7): notices nobody queued before: a
-- risk's exposure going stale, and its treatment actions going overdue.
--
--   * register.notice_sweep(batch) (register_definer, run by the risk
--     service's leader every 15 minutes): for open risks with an owner, a
--     condition becoming true records it in register.notice_state and
--     queues one notice to the owner in register.notice_outbox; a condition
--     that clears (or whose risk closes) loses its state row, so it notifies
--     again only after returning. At most batch changes of each kind per
--     sweep. Stale is register.status_of's (register.exposures); overdue is
--     an open action past its due date (register.treatment.next_due).
--   * notify.collect also takes register.notice_outbox (kinds risk.stale,
--     risk.action_overdue; item type risk, the owner named), and
--     notify.recheck checks a risk's visibility in the register read scope.

CREATE TABLE register.notice_state (
  risk_id   uuid        NOT NULL REFERENCES register.risk (id),
  condition text        NOT NULL CHECK (condition IN ('stale', 'action_overdue')),
  since     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (risk_id, condition)
);
CREATE TABLE register.notice_outbox (
  id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind         text        NOT NULL CHECK (kind IN ('risk.stale', 'risk.action_overdue')),
  user_id      uuid        NOT NULL REFERENCES iam.app_user (id),
  risk_id      uuid        NOT NULL REFERENCES register.risk (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE INDEX register_notice_outbox_pending ON register.notice_outbox (id) WHERE delivered_at IS NULL;
REVOKE ALL ON register.notice_state, register.notice_outbox FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON register.notice_state TO register_definer;
GRANT SELECT, INSERT ON register.notice_outbox TO register_definer;
GRANT USAGE ON SEQUENCE register.notice_outbox_id_seq TO register_definer;
GRANT USAGE ON SCHEMA register TO notify_definer;
GRANT SELECT, UPDATE (delivered_at) ON register.notice_outbox TO notify_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;
CREATE FUNCTION register.notice_sweep(batch integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  opened  integer := 0;
  cleared integer := 0;
  o2      integer;
  c2      integer;
BEGIN
  IF batch IS NULL OR batch < 1 OR batch > 10000 THEN
    RAISE EXCEPTION 'register.notice_sweep: batch is 1 to 10,000' USING ERRCODE = 'PF026', HINT = 'invalid_batch';
  END IF;
  -- Stale: by register.status_of's rules, set-based.
  WITH stale AS (
    SELECT e.risk_id, e.owner FROM register.exposures(ARRAY(SELECT r.id FROM register.risk r WHERE r.state = 'open' AND r.owner IS NOT NULL)) e
    WHERE e.status = 'stale'
  ), gone AS (
    DELETE FROM register.notice_state s WHERE s.condition = 'stale' AND s.risk_id IN (
      SELECT x.risk_id FROM register.notice_state x WHERE x.condition = 'stale' AND NOT EXISTS (SELECT 1 FROM stale WHERE stale.risk_id = x.risk_id) LIMIT batch)
    RETURNING 1
  ), fresh AS (
    INSERT INTO register.notice_state (risk_id, condition)
    SELECT f.risk_id, 'stale' FROM (SELECT stale.risk_id FROM stale
      WHERE NOT EXISTS (SELECT 1 FROM register.notice_state x WHERE x.risk_id = stale.risk_id AND x.condition = 'stale') LIMIT batch) f
    RETURNING risk_id
  ), queued AS (
    INSERT INTO register.notice_outbox (kind, user_id, risk_id)
    SELECT 'risk.stale', stale.owner, fresh.risk_id FROM fresh JOIN stale USING (risk_id) RETURNING 1
  )
  SELECT (SELECT count(*) FROM queued), (SELECT count(*) FROM gone) INTO opened, cleared;
  -- Overdue: an open action past its due date.
  WITH overdue AS (
    SELECT r.id AS risk_id, r.owner FROM register.risk r JOIN register.treatment t ON t.risk_id = r.id
    WHERE r.state = 'open' AND r.owner IS NOT NULL AND t.next_due < current_date
  ), gone AS (
    DELETE FROM register.notice_state s WHERE s.condition = 'action_overdue' AND s.risk_id IN (
      SELECT x.risk_id FROM register.notice_state x WHERE x.condition = 'action_overdue'
        AND NOT EXISTS (SELECT 1 FROM overdue o WHERE o.risk_id = x.risk_id) LIMIT batch)
    RETURNING 1
  ), fresh AS (
    INSERT INTO register.notice_state (risk_id, condition)
    SELECT f.risk_id, 'action_overdue' FROM (SELECT o.risk_id FROM overdue o
      WHERE NOT EXISTS (SELECT 1 FROM register.notice_state x WHERE x.risk_id = o.risk_id AND x.condition = 'action_overdue') LIMIT batch) f
    RETURNING risk_id
  ), queued AS (
    INSERT INTO register.notice_outbox (kind, user_id, risk_id)
    SELECT 'risk.action_overdue', o.owner, fresh.risk_id FROM fresh JOIN overdue o USING (risk_id) RETURNING 1
  )
  SELECT (SELECT count(*) FROM queued), (SELECT count(*) FROM gone) INTO o2, c2;
  RETURN jsonb_build_object('opened', opened + o2, 'cleared', cleared + c2);
END $$;
REVOKE ALL ON FUNCTION register.notice_sweep(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.notice_sweep(integer) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

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
  END
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

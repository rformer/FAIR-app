-- F-009 T-04 (F-009-AC-01, AC-05, AC-06; design §3.1, §3.3, §3.6): taking
-- the features' outboxes into notices.
--
--   * posture.finding_outbox: a trigger on posture.drift_finding queues a
--     high or critical finding when it opens (an insert; a refreshed
--     finding is an update, not queued again).
--   * Each owning schema describes its own items to notify_definer, as
--     every definer reads only what its RLS admits: estimate.notice_item
--     (estimate_definer), acceptance.notice_item (acceptance_definer) over
--     register.notice_risk (register_definer).
--   * notify.collect(titles, batch): up to batch pending rows of each
--     outbox become notices (once per source row) and are marked delivered
--     in the same transaction. The envelope (design §3.3) is the kind, the
--     time it was queued, the BU's id and name, the item's type, id and
--     link, and its title only when titles is true (the setting
--     notification.detail, read by the service) and the item's BU is not
--     inside a restricted subtree. A row whose kind the release does not
--     know is left pending and counted (unknown), never dropped.

-- Findings as notices (design §3.6).
CREATE TABLE posture.finding_outbox (
  id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  finding_id   uuid        NOT NULL REFERENCES posture.drift_finding (id),
  check_id     text        NOT NULL,
  severity     text        NOT NULL CHECK (severity IN ('high', 'critical')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE INDEX finding_outbox_pending ON posture.finding_outbox (id) WHERE delivered_at IS NULL;
REVOKE ALL ON posture.finding_outbox FROM PUBLIC;
GRANT INSERT ON posture.finding_outbox TO posture_definer;
GRANT SELECT, UPDATE (delivered_at) ON posture.finding_outbox TO notify_definer;
-- As every posture table: row-level security, forced; posture_definer
-- queues, notify_definer collects.
ALTER TABLE posture.finding_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.finding_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.finding_outbox TO posture_definer USING (true) WITH CHECK (true);
CREATE POLICY notify_collect ON posture.finding_outbox TO notify_definer USING (true) WITH CHECK (true);

CREATE FUNCTION posture.queue_finding_notice() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.severity IN ('high', 'critical') THEN
    INSERT INTO posture.finding_outbox (finding_id, check_id, severity) VALUES (NEW.id, NEW.check_id, NEW.severity);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER finding_notice AFTER INSERT ON posture.drift_finding FOR EACH ROW EXECUTE FUNCTION posture.queue_finding_notice();

-- The items, described by their owners.
GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;
CREATE FUNCTION register.notice_risk(risk uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', r.bu_id, 'title', r.title, 'owner', r.owner, 'state', r.state) FROM register.risk r WHERE r.id = notice_risk.risk
$$;
REVOKE ALL ON FUNCTION register.notice_risk(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.notice_risk(uuid) TO acceptance_definer, notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;
CREATE FUNCTION acceptance.notice_item(id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', x.bu_id, 'risk_id', x.risk_id, 'title', register.notice_risk(x.risk_id) ->> 'title',
    'owner', register.notice_risk(x.risk_id) ->> 'owner', 'requested_by', x.requested_by, 'tier_bu_id', x.tier_bu_id, 'state', x.state)
  FROM acceptance.acceptance x WHERE x.id = notice_item.id
$$;
REVOKE ALL ON FUNCTION acceptance.notice_item(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.notice_item(uuid) TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;
CREATE FUNCTION estimate.notice_item(id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', r.bu_id, 'title', r.title, 'status', r.status) FROM estimate.request r WHERE r.id = notice_item.id
$$;
REVOKE ALL ON FUNCTION estimate.notice_item(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.notice_item(uuid) TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;

GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO notify_definer;
-- posture.notice_outbox is definer-only under RLS (0021): notify_definer
-- reads it and marks rows delivered.
CREATE POLICY notify_collect ON posture.notice_outbox TO notify_definer USING (true) WITH CHECK (true);

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

-- A notice from one outbox row; NULL when the release does not know kind.
CREATE FUNCTION notify.add_notice(source text, source_kind text, source_id text, queued_at timestamptz, bu uuid, item_type text,
  item_id text, link text, title text, recipients jsonb, titles boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  k          notify.kind;
  b          iam.bu;
  id         uuid := gen_random_uuid();
  restricted boolean;
  env        jsonb;
BEGIN
  SELECT * INTO k FROM notify.kind x WHERE x.source = add_notice.source AND x.source_kind = add_notice.source_kind AND x.retired_at IS NULL;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT * INTO b FROM iam.bu x WHERE x.id = coalesce(add_notice.bu, (SELECT r.id FROM iam.bu r WHERE r.parent_id IS NULL));
  restricted := iam.restricted_root(b.id) IS NOT NULL;
  env := jsonb_build_object('id', id, 'kind', k.kind, 'at', queued_at, 'bu', jsonb_build_object('id', b.id, 'name', b.name),
    'item', jsonb_build_object('type', item_type, 'id', item_id, 'link', link));
  IF titles AND NOT restricted AND nullif(btrim(title), '') IS NOT NULL THEN
    env := env || jsonb_build_object('title', left(btrim(title), 200));
  END IF;
  INSERT INTO notify.notice (id, kind, source, source_id, envelope, item_type, item_id, bu_id, restricted, recipients, queued_at)
  VALUES (id, k.kind, add_notice.source, add_notice.source_id, env, item_type, item_id, b.id, restricted, recipients, queued_at)
  ON CONFLICT ON CONSTRAINT notice_source_source_id_key DO NOTHING;
  RETURN id;
END $$;

CREATE FUNCTION notify.collect(titles boolean, batch integer) RETURNS jsonb
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
  RETURN jsonb_build_object('collected', collected, 'unknown', unknown);
END $$;

REVOKE ALL ON FUNCTION notify.add_notice(text, text, text, timestamptz, uuid, text, text, text, text, jsonb, boolean), notify.collect(boolean, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.collect(boolean, integer) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;

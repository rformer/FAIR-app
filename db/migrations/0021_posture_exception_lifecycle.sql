-- F-015 T-17 (AC-24 - AC-26; design §6.3): the exception lifecycle.
--
--   * Expiry (AC-24): a requester may ask for a shorter exception than the
--     default; any requested duration must be positive and no longer than
--     the exception.max_duration value in force (90 days in every profile,
--     configurable within the profile's bounds), and is clamped again when
--     the exception is created. No exception is open-ended.
--   * Renewal (AC-26): only while the exception is active and unexpired,
--     with a new justification and dual approval (approval kind
--     settings.exception_renewal). It creates a new exception linked by
--     renewed_from and marks the old one renewed.
--   * Notices (AC-25): exception_notices() records the 14-, 7- and 1-day
--     notices once each and queues them for the owner and the holders of
--     settings.approve in posture.notice_outbox, for F-009 to deliver.
-- All times come from the database clock (§6.3).
-- New SQLSTATE: PF009 duration outside the allowed range.

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('settings.exception_renewal', 'settings.approve', 'Renew a security setting exception before it expires (F-015 AC-26)');

ALTER TABLE posture.change ADD COLUMN exception_ttl text; -- requested exception duration (Go duration); NULL = the maximum

CREATE TABLE posture.renewal (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  exception_id         uuid        NOT NULL REFERENCES posture.exception (id),
  justification        text        NOT NULL CHECK (btrim(justification) <> ''),
  exception_ttl        text,
  requested_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  approval_request_id  uuid        NOT NULL,
  state                text        NOT NULL DEFAULT 'pending_approval' CHECK (state IN ('pending_approval', 'applied')),
  new_exception_id     uuid        REFERENCES posture.exception (id),
  created_at           timestamptz NOT NULL DEFAULT now(),
  applied_at           timestamptz,
  CHECK ((state = 'applied') = (new_exception_id IS NOT NULL AND applied_at IS NOT NULL))
);

CREATE TABLE posture.exception_notice (
  exception_id  uuid        NOT NULL REFERENCES posture.exception (id),
  days_before   integer     NOT NULL CHECK (days_before IN (14, 7, 1)),
  recorded_at   timestamptz NOT NULL DEFAULT now(),
  sent          boolean     NOT NULL, -- false: crossed together with a nearer threshold, which was sent instead
  PRIMARY KEY (exception_id, days_before)
);

-- People-facing notifications for F-009 (notifications) to deliver.
CREATE TABLE posture.notice_outbox (
  id            bigserial   PRIMARY KEY,
  kind          text        NOT NULL,
  recipients    jsonb       NOT NULL, -- {"users": [...], "permission_holders": "settings.approve"}
  payload       jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['renewal', 'exception_notice', 'notice_outbox'] LOOP
    EXECUTE format('REVOKE ALL ON posture.%I FROM PUBLIC', t);
    EXECUTE format('ALTER TABLE posture.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE posture.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY definer_only ON posture.%I TO posture_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE ON posture.renewal, posture.exception_notice, posture.notice_outbox TO posture_definer;
GRANT USAGE ON SEQUENCE posture.notice_outbox_id_seq TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The exception duration to use: requested (a Go duration string) or the
-- maximum in force, never longer than the maximum (AC-24).
CREATE FUNCTION posture.exception_duration(requested text) RETURNS interval
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  max_ns numeric := posture.duration_ns(posture.current_value('exception.max_duration', NULL) #>> '{}');
  req_ns numeric;
BEGIN
  IF requested IS NULL THEN
    RETURN make_interval(secs => max_ns / 1e9);
  END IF;
  req_ns := posture.duration_ns(requested);
  IF req_ns <= 0 THEN
    RAISE EXCEPTION 'an exception needs a positive duration' USING ERRCODE = 'PF009';
  END IF;
  RETURN make_interval(secs => least(req_ns, max_ns) / 1e9);
END $$;

-- Refuses a requested duration longer than the maximum in force.
CREATE FUNCTION posture.check_exception_ttl(requested text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  max_v jsonb := posture.current_value('exception.max_duration', NULL);
BEGIN
  IF requested IS NULL THEN
    RETURN;
  END IF;
  IF posture.duration_ns(requested) <= 0 OR posture.duration_ns(requested) > posture.duration_ns(max_v #>> '{}') THEN
    RAISE EXCEPTION 'exception duration % must be positive and at most exception.max_duration (%)', requested, max_v #>> '{}'
      USING ERRCODE = 'PF009';
  END IF;
END $$;

DROP FUNCTION posture.request_change(text, uuid, jsonb, text);
CREATE FUNCTION posture.request_change(k text, bu uuid, new_value jsonb, explanation text, exception_ttl text DEFAULT NULL,
  OUT change_id uuid, OUT direction text, OUT state text, OUT approval_request_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.change_actor(bu);
  p     record := posture.preview_change(k, bu, new_value);
BEGIN
  IF p.below_floor THEN
    RAISE EXCEPTION '% = % is weaker than the hard floor %', k, new_value, p.hard_floor USING ERRCODE = 'PF001';
  END IF;
  change_id := gen_random_uuid();
  direction := p.direction;
  IF p.out_of_bounds AND NOT p.covered THEN
    IF btrim(coalesce(explanation, '')) = '' THEN
      RAISE EXCEPTION '% = % is outside the active profile bound %: a written explanation and dual approval are required', k, new_value, p.bound
        USING ERRCODE = 'PF002';
    END IF;
    PERFORM posture.check_exception_ttl(exception_ttl);
    approval_request_id := iam.request_approval('settings.out_of_bounds', 'posture.change:' || change_id, explanation,
      jsonb_build_object('key', k, 'bu_id', bu, 'value', new_value, 'current', p.current_value, 'bound', p.bound, 'params', p.params,
                         'exception_duration', coalesce(exception_ttl, posture.current_value('exception.max_duration', NULL) #>> '{}')), bu);
    state := 'pending_approval';
  ELSE
    state := 'requested';
  END IF;
  INSERT INTO posture.change (id, key, bu_id, old_value, new_value, direction, explanation, requested_by, approval_request_id, state, exception_ttl)
  VALUES (change_id, k, bu, p.current_value, new_value, direction, nullif(btrim(coalesce(explanation, '')), ''), actor,
          approval_request_id, state, CASE WHEN approval_request_id IS NOT NULL THEN request_change.exception_ttl END);
END $$;

CREATE OR REPLACE FUNCTION posture.apply_change(change_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c   posture.change;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  cur jsonb;
  cov uuid;
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
  cov := posture.covering_exception(c.key, c.bu_id);

  IF c.state = 'requested' THEN
    IF posture.compare(d, c.new_value, b.bound) < 0 THEN
      -- Out of bounds without approval only as a tightening under an active
      -- exception (AC-22), re-checked now.
      IF cov IS NULL OR posture.compare(d, c.new_value, cur) <= 0 THEN
        RAISE EXCEPTION 'change % is now outside the active profile bound %; request it again', change_id, b.bound USING ERRCODE = 'PF002';
      END IF;
      UPDATE posture.exception e SET value = c.new_value WHERE e.id = cov;
      PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'exception', NULL, cov);
    ELSE
      PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'change', c.id, NULL);
      IF cov IS NOT NULL THEN
        UPDATE posture.exception e SET state = 'superseded' WHERE e.id = cov; -- back within the bound
      END IF;
    END IF;
  ELSE
    a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds', 'posture.change:' || c.id);
    INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
    VALUES (c.key, c.bu_id, c.new_value, b.bound, c.explanation, c.requested_by, (a ->> 'decided_by')::uuid,
            now() + posture.exception_duration(c.exception_ttl), 'active')
    RETURNING e.id INTO exc;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'exception', NULL, exc);
    IF cov IS NOT NULL THEN
      UPDATE posture.exception e SET state = 'superseded' WHERE e.id = cov; -- replaced by the new exception
    END IF;
  END IF;
  UPDATE posture.change x SET state = 'applied', applied_at = now() WHERE x.id = c.id;

  -- AC-23: a weakening (against the value in force until now) or any new
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

-- Requests renewal of an active, unexpired exception as the signed-context
-- user (who needs settings.change where the exception applies), with a new
-- justification; opens the dual approval. Returns the renewal and approval.
CREATE FUNCTION posture.request_renewal(exception_id uuid, justification text, exception_ttl text DEFAULT NULL,
  OUT renewal_id uuid, OUT approval_request_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e     posture.exception;
  actor uuid;
BEGIN
  SELECT * INTO e FROM posture.exception x WHERE x.id = request_renewal.exception_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'exception % does not exist', exception_id USING ERRCODE = 'PF003';
  END IF;
  actor := posture.change_actor(e.bu_id);
  IF e.state <> 'active' OR now() >= e.expires_at THEN
    RAISE EXCEPTION 'exception % can no longer be renewed (%; expires %)', exception_id, e.state, e.expires_at USING ERRCODE = 'PF003';
  END IF;
  IF btrim(coalesce(justification, '')) = '' THEN
    RAISE EXCEPTION 'a renewal needs a new written justification' USING ERRCODE = 'PF002';
  END IF;
  PERFORM posture.check_exception_ttl(exception_ttl);
  renewal_id := gen_random_uuid();
  approval_request_id := iam.request_approval('settings.exception_renewal', 'posture.renewal:' || renewal_id, justification,
    jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'value', e.value, 'expires_at', e.expires_at,
                       'exception_duration', coalesce(exception_ttl, posture.current_value('exception.max_duration', NULL) #>> '{}')),
    e.bu_id);
  INSERT INTO posture.renewal (id, exception_id, justification, exception_ttl, requested_by, approval_request_id)
  VALUES (renewal_id, e.id, btrim(justification), request_renewal.exception_ttl, actor, approval_request_id);
END $$;

-- Applies an approved renewal: only while the exception is still active and
-- unexpired. Returns the new exception.
CREATE FUNCTION posture.apply_renewal(renewal_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r   posture.renewal;
  e   posture.exception;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  exc uuid;
BEGIN
  SELECT * INTO r FROM posture.renewal x WHERE x.id = apply_renewal.renewal_id FOR UPDATE;
  IF NOT FOUND OR r.state <> 'pending_approval' THEN
    RAISE EXCEPTION 'renewal % is not pending', renewal_id USING ERRCODE = 'PF003';
  END IF;
  SELECT * INTO e FROM posture.exception x WHERE x.id = r.exception_id FOR UPDATE;
  IF e.state <> 'active' OR now() >= e.expires_at THEN
    RAISE EXCEPTION 'exception % expired or closed before the renewal was applied', e.id USING ERRCODE = 'PF003';
  END IF;
  a := iam.consume_approval(r.approval_request_id, 'settings.exception_renewal', 'posture.renewal:' || r.id);
  d := posture.check_value(e.key, e.value);
  b := posture.active_binding(e.key);
  PERFORM posture.check_floor(d, b.family, e.value);
  INSERT INTO posture.exception AS n (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, renewed_from, state)
  VALUES (e.key, e.bu_id, e.value, b.bound, r.justification, r.requested_by, (a ->> 'decided_by')::uuid,
          now() + posture.exception_duration(r.exception_ttl), e.id, 'active')
  RETURNING n.id INTO exc;
  UPDATE posture.exception x SET state = 'renewed' WHERE x.id = e.id;
  IF EXISTS (SELECT 1 FROM posture.setting_value s WHERE s.key = e.key AND s.bu_id IS NOT DISTINCT FROM e.bu_id
             AND s.source = 'exception' AND s.exception_id = e.id) THEN
    PERFORM posture.write_value(e.key, e.bu_id, e.value, 'exception', NULL, exc);
  END IF;
  UPDATE posture.renewal x SET state = 'applied', new_exception_id = exc, applied_at = now() WHERE x.id = r.id;
  IF posture.deployment_mode() = 'saas' THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object(
      'type', 'setting.exception_renewed', 'key', e.key, 'bu_id', e.bu_id, 'value', e.value, 'bound', b.bound,
      'profile_family', b.family, 'exception_id', exc, 'renewed_from', e.id, 'requested_by', r.requested_by,
      'approved_by', a ->> 'decided_by', 'explanation', r.justification, 'at', now()));
  END IF;
  RETURN exc;
END $$;

-- AC-25: records the 14-, 7- and 1-day notices that are due, once each, and
-- queues them for the owner and the settings.approve holders. When several
-- thresholds are crossed at once (for example a 5-day exception), only the
-- nearest is sent. Returns the notices queued now.
CREATE FUNCTION posture.exception_notices()
RETURNS TABLE (exception_id uuid, days_before integer, key text, bu_id uuid, owner_id uuid, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e       posture.exception;
  crossed integer[];
  nearest integer;
BEGIN
  FOR e IN SELECT * FROM posture.exception x WHERE x.state = 'active' AND x.expires_at > now() ORDER BY x.expires_at FOR UPDATE SKIP LOCKED LOOP
    crossed := ARRAY(SELECT t FROM unnest(ARRAY[14, 7, 1]) t
                     WHERE e.expires_at - make_interval(days => t) <= now()
                       AND NOT EXISTS (SELECT 1 FROM posture.exception_notice n WHERE n.exception_id = e.id AND n.days_before = t));
    IF cardinality(crossed) = 0 THEN
      CONTINUE;
    END IF;
    nearest := (SELECT min(t) FROM unnest(crossed) t);
    INSERT INTO posture.exception_notice (exception_id, days_before, sent)
    SELECT e.id, t, t = nearest FROM unnest(crossed) t;
    INSERT INTO posture.notice_outbox (kind, recipients, payload) VALUES ('setting.exception_expiring',
      jsonb_build_object('users', jsonb_build_array(e.owner_id), 'permission_holders', 'settings.approve'),
      jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'value', e.value, 'days_before', nearest,
                         'expires_at', e.expires_at, 'justification', e.justification));
    exception_id := e.id; days_before := nearest; key := e.key; bu_id := e.bu_id; owner_id := e.owner_id; expires_at := e.expires_at;
    RETURN NEXT;
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION posture.exception_duration(text), posture.check_exception_ttl(text),
  posture.request_change(text, uuid, jsonb, text, text), posture.request_renewal(uuid, text, text), posture.apply_renewal(uuid),
  posture.exception_notices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.request_change(text, uuid, jsonb, text, text), posture.request_renewal(uuid, text, text),
  posture.apply_renewal(uuid) TO app_posture, app_rw;
GRANT EXECUTE ON FUNCTION posture.exception_notices() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

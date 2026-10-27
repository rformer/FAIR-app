-- F-015 T-23 (AC-33, AC-34; design §6.6, as changed 2026-10-27): the
-- Restricted BU overlay.
--
--   * The overlay is computed, not copied into rows: every BU that is
--     restricted or lies below a restricted BU gets it, by construction, and
--     loses it when no longer restricted (F-001 audits restrict/unrestrict;
--     unrestrict needs dual approval). BU tree changes already bump the
--     posture version (T-22), so caches follow at once.
--       effective(k, bu) = strictest(instance, unblocked overrides (T-22),
--                                    overlay(k) if bu is in a restricted subtree)
--   * Its AC-33 defaults are fixed here, in code (posture.overlay_defaults):
--     re-authentication within 15 minutes (bu.reauth_max_age, F-001 T-24
--     via F-015 T-24), session.network_binding = reauthenticate, and a
--     stated reason for exports (export.reason_required, F-010). A key takes
--     effect once its setting is registered as BU-scopable; until then the
--     default waits for it.
--   * Edits (AC-34) are rows in posture.overlay_value, row-MAC'd like
--     setting_value (domain-separated as "overlay:<key>"). The AC-33 default
--     is the overlay's bound: tightening, and moving back towards the
--     default, apply at once; anything weaker than the default needs a
--     written explanation and dual approval (settings.out_of_bounds) and
--     becomes an overlay exception (exception.overlay) with R-07's expiry,
--     notices, renewal and auto-revert, which restores the default. The
--     hard floor applies as everywhere.

-- Narrow tree reads for posture_definer.
CREATE FUNCTION iam.in_restricted_subtree(bu uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM iam.bu_closure c JOIN iam.bu a ON a.id = c.ancestor_id
                 WHERE c.descendant_id = bu AND a.restricted);
$$;
CREATE FUNCTION iam.restricted_subtree() RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT c.descendant_id FROM iam.bu_closure c JOIN iam.bu a ON a.id = c.ancestor_id WHERE a.restricted;
$$;
REVOKE ALL ON FUNCTION iam.in_restricted_subtree(uuid), iam.restricted_subtree() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.in_restricted_subtree(uuid), iam.restricted_subtree() TO posture_definer;

-- The AC-33 defaults (Go duration strings, as in packages).
CREATE FUNCTION posture.overlay_defaults() RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT '{"bu.reauth_max_age": "15m0s", "session.network_binding": "reauthenticate", "export.reason_required": true}'::jsonb;
$$;
REVOKE ALL ON FUNCTION posture.overlay_defaults() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.overlay_defaults() TO posture_definer;

ALTER TABLE posture.exception
  ADD COLUMN overlay boolean NOT NULL DEFAULT false, -- an exception to the Restricted BU overlay
  ADD CONSTRAINT exception_overlay_instance CHECK (NOT overlay OR bu_id IS NULL);

-- Requested overlay edits, as posture.change is for setting values.
CREATE TABLE posture.overlay_change (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  key                  text        NOT NULL REFERENCES posture.setting_def (key),
  old_value            jsonb       NOT NULL,
  new_value            jsonb       NOT NULL,
  direction            text        NOT NULL CHECK (direction IN ('tighten', 'neutral', 'loosen')),
  explanation          text,
  requested_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  approval_request_id  uuid,
  exception_ttl        text,
  state                text        NOT NULL CHECK (state IN ('requested', 'pending_approval', 'applied')),
  created_at           timestamptz NOT NULL DEFAULT now(),
  applied_at           timestamptz,
  CHECK ((state = 'applied') = (applied_at IS NOT NULL)),
  CHECK (state <> 'pending_approval' OR approval_request_id IS NOT NULL)
);

-- The overlay value of a key when it differs from the default's origin: an
-- edit or an exception. No row: the AC-33 default.
CREATE TABLE posture.overlay_value (
  key           text        PRIMARY KEY CHECK (posture.overlay_defaults() ? key),
  value         jsonb       NOT NULL,
  source        text        NOT NULL CHECK (source IN ('change', 'exception')),
  change_id     uuid        REFERENCES posture.overlay_change (id),
  exception_id  uuid        REFERENCES posture.exception (id),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  mac_key_id    text        NOT NULL REFERENCES posture.mac_key (key_id),
  row_mac       bytea       NOT NULL CHECK (octet_length(row_mac) = 32),
  CHECK ((source = 'change') = (change_id IS NOT NULL)),
  CHECK ((source = 'exception') = (exception_id IS NOT NULL))
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['overlay_change', 'overlay_value'] LOOP
    EXECUTE format('REVOKE ALL ON posture.%I FROM PUBLIC', t);
    EXECUTE format('ALTER TABLE posture.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE posture.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY definer_only ON posture.%I TO posture_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE ON posture.overlay_change TO posture_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON posture.overlay_value TO posture_definer;
CREATE TRIGGER bump_version AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON posture.overlay_value
  FOR EACH STATEMENT EXECUTE FUNCTION posture.bump_version();

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The overlay value in force for k: the edited value, else the default.
CREATE FUNCTION posture.overlay_in_force(k text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((SELECT o.value FROM posture.overlay_value o WHERE o.key = k), posture.overlay_defaults() -> k);
$$;

-- Whether the overlay takes effect for k: an overlay key registered as
-- BU-scopable.
CREATE FUNCTION posture.overlay_applies(k text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT posture.overlay_defaults() ? k AND EXISTS (SELECT 1 FROM posture.setting_def d WHERE d.key = k AND d.bu_scopable);
$$;

-- T-22 plus the overlay for BUs in a restricted subtree. An overlay value
-- that does not fit its registered setting fails the read (check_value):
-- closed, never silently dropped.
CREATE OR REPLACE FUNCTION posture.current_value(k text, bu uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  inst jsonb := coalesce((SELECT s.value FROM posture.setting_value s WHERE s.key = k AND s.bu_id IS NULL),
                         (posture.active_binding(k)).default_value);
  d    posture.setting_def;
  vals jsonb[];
  ov   jsonb;
BEGIN
  IF bu IS NULL THEN
    RETURN inst;
  END IF;
  SELECT * INTO d FROM posture.setting_def s WHERE s.key = k;
  IF NOT FOUND THEN
    RETURN inst;
  END IF;
  vals := ARRAY[inst] || ARRAY(
    SELECT s.value FROM posture.setting_value s
    WHERE s.key = k AND s.bu_id IN (SELECT iam.unblocked_ancestors(bu)));
  IF d.bu_scopable AND posture.overlay_defaults() ? k AND iam.in_restricted_subtree(bu) THEN
    ov := posture.overlay_in_force(k);
    PERFORM posture.check_value(k, ov);
    vals := vals || ov;
  END IF;
  RETURN posture.strictest(d, vals);
END $$;

-- As in T-22, with every BU in a restricted subtree reached by each overlay
-- key that applies.
CREATE OR REPLACE FUNCTION posture.effective_settings() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH a AS (SELECT profile_id, version FROM posture.active_profile),
  inst AS (
    SELECT coalesce((SELECT jsonb_object_agg(v.key, v.default_value) FROM posture.profile_value v
                     JOIN a ON v.profile_id = a.profile_id AND v.version = a.version), '{}'::jsonb)
        || coalesce((SELECT jsonb_object_agg(s.key, s.value) FROM posture.setting_value s WHERE s.bu_id IS NULL), '{}'::jsonb) AS vals),
  reached AS (
    SELECT r.bu, s.key
    FROM posture.setting_value s
    CROSS JOIN LATERAL (SELECT iam.unblocked_descendants(s.bu_id) AS bu) r
    WHERE s.bu_id IS NOT NULL
    UNION
    SELECT r.bu, k.key
    FROM jsonb_object_keys(posture.overlay_defaults()) AS k(key)
    CROSS JOIN LATERAL (SELECT iam.restricted_subtree() AS bu) r
    WHERE posture.overlay_applies(k.key)),
  eff AS (
    SELECT r.bu, r.key, posture.current_value(r.key, r.bu) AS value FROM reached r),
  diff AS (
    SELECT e.bu, jsonb_object_agg(e.key, e.value) AS vals
    FROM eff e, inst i WHERE e.value IS DISTINCT FROM i.vals -> e.key
    GROUP BY e.bu)
  SELECT jsonb_build_object(
    'version', (SELECT version FROM posture.state),
    'profile', (SELECT profile_id FROM a),
    'profile_version', (SELECT version FROM a),
    'instance', (SELECT vals FROM inst),
    'bu', coalesce((SELECT jsonb_object_agg(d.bu, d.vals) FROM diff d), '{}'::jsonb));
$$;

-- Writes the overlay value of k under the newest MAC key.
CREATE FUNCTION posture.write_overlay(k text, v jsonb, src text, change uuid, exc uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  kid text;
BEGIN
  SELECT key_id INTO kid FROM posture.mac_key WHERE retired_at IS NULL ORDER BY created_at DESC, key_id LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active posture MAC key (install one with posture.add_mac_key)' USING ERRCODE = 'PF006';
  END IF;
  INSERT INTO posture.overlay_value AS o (key, value, source, change_id, exception_id, updated_at, mac_key_id, row_mac)
  VALUES (k, v, src, change, exc, now(), kid, posture.row_mac(kid, 'overlay:' || k, NULL, v, src, change, exc))
  ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value, source = EXCLUDED.source, change_id = EXCLUDED.change_id,
    exception_id = EXCLUDED.exception_id, updated_at = EXCLUDED.updated_at,
    mac_key_id = EXCLUDED.mac_key_id, row_mac = EXCLUDED.row_mac;
END $$;

-- Overlay rows join the drift check, as "overlay:<key>".
CREATE OR REPLACE FUNCTION posture.mac_mismatches() RETURNS TABLE (key text, bu_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT x.key, x.bu_id FROM (
    SELECT s.key, s.bu_id FROM posture.setting_value s
    LEFT JOIN posture.mac_key m ON m.key_id = s.mac_key_id
    WHERE m.key_id IS NULL
       OR s.row_mac <> authz.hmac(convert_to(jsonb_build_array(s.key, s.bu_id, s.value, s.source, s.change_id, s.exception_id)::text, 'UTF8'), m.secret, 'sha256')
    UNION ALL
    SELECT 'overlay:' || o.key, NULL::uuid FROM posture.overlay_value o
    LEFT JOIN posture.mac_key m ON m.key_id = o.mac_key_id
    WHERE m.key_id IS NULL
       OR o.row_mac <> authz.hmac(convert_to(jsonb_build_array('overlay:' || o.key, NULL::uuid, o.value, o.source, o.change_id, o.exception_id)::text, 'UTF8'), m.secret, 'sha256')
  ) x
  ORDER BY x.key, x.bu_id NULLS FIRST;
$$;

-- The active overlay exception of k, if any.
CREATE FUNCTION posture.overlay_exception(k text) RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.id FROM posture.overlay_value o JOIN posture.exception e ON e.id = o.exception_id
  WHERE o.key = k AND o.source = 'exception' AND e.state = 'active' AND e.expires_at > now();
$$;

-- The overlay as the Posture page and GET /overlay show it.
CREATE FUNCTION posture.overlay()
RETURNS TABLE (key text, default_value jsonb, value jsonb, source text, exception_id uuid, expires_at timestamptz, applies boolean,
               params text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.key, k.value, coalesce(o.value, k.value), coalesce(o.source, 'default'), o.exception_id, e.expires_at,
         posture.overlay_applies(k.key), coalesce(d.params, '{}')
  FROM jsonb_each(posture.overlay_defaults()) k
  LEFT JOIN posture.setting_def d ON d.key = k.key
  LEFT JOIN posture.overlay_value o ON o.key = k.key
  LEFT JOIN posture.exception e ON e.id = o.exception_id
  ORDER BY k.key;
$$;

-- Requests an overlay edit as the signed-context user, who needs
-- settings.change at the root (the overlay is instance-wide). Classified
-- against the overlay value in force; weaker than the AC-33 default needs an
-- explanation and opens a dual approval (AC-34).
CREATE FUNCTION posture.request_overlay_change(k text, new_value jsonb, explanation text, exception_ttl text DEFAULT NULL,
  OUT change_id uuid, OUT direction text, OUT state text, OUT approval_request_id uuid,
  OUT current_value jsonb, OUT overlay_default jsonb, OUT params text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.change_actor(NULL);
  d     posture.setting_def;
  b     record;
  oob   boolean;
BEGIN
  IF NOT posture.overlay_defaults() ? k THEN
    RAISE EXCEPTION '% is not part of the Restricted BU overlay', k USING ERRCODE = 'PF003';
  END IF;
  IF NOT posture.overlay_applies(k) THEN
    RAISE EXCEPTION '% is not registered as a BU-scopable setting yet; its overlay default applies once it is', k USING ERRCODE = 'PF003';
  END IF;
  d := posture.check_value(k, new_value);
  b := posture.active_binding(k);
  PERFORM posture.check_floor(d, b.family, new_value);
  current_value := posture.overlay_in_force(k);
  overlay_default := posture.overlay_defaults() -> k;
  params := d.params;
  direction := CASE posture.compare(d, new_value, current_value) WHEN 1 THEN 'tighten' WHEN 0 THEN 'neutral' ELSE 'loosen' END;
  oob := posture.compare(d, new_value, overlay_default) < 0;
  change_id := gen_random_uuid();
  IF oob AND NOT (direction = 'tighten' AND posture.overlay_exception(k) IS NOT NULL) THEN
    IF btrim(coalesce(explanation, '')) = '' THEN
      RAISE EXCEPTION 'overlay % = % is weaker than its default %: a written explanation and dual approval are required', k, new_value, overlay_default
        USING ERRCODE = 'PF002';
    END IF;
    PERFORM posture.check_exception_ttl(exception_ttl);
    approval_request_id := iam.request_approval('settings.out_of_bounds', 'posture.overlay_change:' || change_id, explanation,
      jsonb_build_object('overlay', true, 'key', k, 'value', new_value, 'current', current_value, 'bound', overlay_default, 'params', d.params,
                         'exception_duration', coalesce(exception_ttl, posture.current_value('exception.max_duration', NULL) #>> '{}')), NULL);
    state := 'pending_approval';
  ELSE
    state := 'requested';
  END IF;
  INSERT INTO posture.overlay_change (id, key, old_value, new_value, direction, explanation, requested_by, approval_request_id, exception_ttl, state)
  VALUES (change_id, k, current_value, new_value, direction, nullif(btrim(coalesce(explanation, '')), ''), actor,
          approval_request_id, CASE WHEN approval_request_id IS NOT NULL THEN request_overlay_change.exception_ttl END, state);
END $$;

-- Applies an overlay edit: a requested one at once (re-checked), an
-- approved one as an overlay exception. Returns the new exception, if any.
CREATE FUNCTION posture.apply_overlay_change(change_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c   posture.overlay_change;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  def jsonb;
  cur jsonb;
  cov uuid;
  exc uuid;
BEGIN
  SELECT * INTO c FROM posture.overlay_change x WHERE x.id = apply_overlay_change.change_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'overlay change % does not exist', change_id USING ERRCODE = 'PF003';
  END IF;
  IF c.state NOT IN ('requested', 'pending_approval') THEN
    RAISE EXCEPTION 'overlay change % is %', change_id, c.state USING ERRCODE = 'PF003';
  END IF;
  d := posture.check_value(c.key, c.new_value);
  b := posture.active_binding(c.key);
  PERFORM posture.check_floor(d, b.family, c.new_value); -- never below the floor (AC-30)
  def := posture.overlay_defaults() -> c.key;
  cur := posture.overlay_in_force(c.key);
  cov := posture.overlay_exception(c.key);

  IF c.state = 'requested' THEN
    IF posture.compare(d, c.new_value, def) < 0 THEN
      -- Weaker than the default without approval only as a tightening under
      -- an active overlay exception, re-checked now.
      IF cov IS NULL OR posture.compare(d, c.new_value, cur) <= 0 THEN
        RAISE EXCEPTION 'overlay change % is now weaker than the default %; request it again', change_id, def USING ERRCODE = 'PF002';
      END IF;
      UPDATE posture.exception e SET value = c.new_value WHERE e.id = cov;
      PERFORM posture.write_overlay(c.key, c.new_value, 'exception', NULL, cov);
    ELSE
      PERFORM posture.write_overlay(c.key, c.new_value, 'change', c.id, NULL);
      IF cov IS NOT NULL THEN
        UPDATE posture.exception e SET state = 'superseded' WHERE e.id = cov; -- back within the default
      END IF;
    END IF;
  ELSE
    a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds', 'posture.overlay_change:' || c.id);
    INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state, overlay)
    VALUES (c.key, NULL, c.new_value, def, c.explanation, c.requested_by, (a ->> 'decided_by')::uuid,
            now() + posture.exception_duration(c.exception_ttl), 'active', true)
    RETURNING e.id INTO exc;
    PERFORM posture.write_overlay(c.key, c.new_value, 'exception', NULL, exc);
    IF cov IS NOT NULL THEN
      UPDATE posture.exception e SET state = 'superseded' WHERE e.id = cov;
    END IF;
  END IF;
  UPDATE posture.overlay_change x SET state = 'applied', applied_at = now() WHERE x.id = c.id;

  IF posture.deployment_mode() = 'saas' AND (exc IS NOT NULL OR posture.compare(d, c.new_value, cur) < 0) THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object(
      'type', CASE WHEN exc IS NULL THEN 'overlay.weakened' ELSE 'overlay.exception_created' END,
      'key', c.key, 'previous', cur, 'value', c.new_value, 'bound', def, 'profile_family', b.family,
      'change_id', c.id, 'exception_id', exc, 'requested_by', c.requested_by,
      'approved_by', a ->> 'decided_by', 'explanation', c.explanation, 'at', now()));
  END IF;
  RETURN exc;
END $$;

-- T-18's revert, plus overlay exceptions: their revert restores the default.
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
  IF e.overlay THEN
    DELETE FROM posture.overlay_value o WHERE o.key = e.key AND o.source = 'exception' AND o.exception_id = e.id;
  ELSIF EXISTS (SELECT 1 FROM posture.setting_value s WHERE s.key = e.key AND s.bu_id IS NOT DISTINCT FROM e.bu_id
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
    jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'overlay', e.overlay, 'value', e.value,
                       'expired_at', e.expires_at, 'attempts', e.revert_attempts + 1));
END $$;

-- T-17's renewal, plus overlay exceptions: the renewal carries the flag and
-- its default as the bound, and takes over the overlay row.
CREATE OR REPLACE FUNCTION posture.apply_renewal(renewal_id uuid) RETURNS uuid
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
  INSERT INTO posture.exception AS n (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, renewed_from, state, overlay)
  VALUES (e.key, e.bu_id, e.value, CASE WHEN e.overlay THEN posture.overlay_defaults() -> e.key ELSE b.bound END,
          r.justification, r.requested_by, (a ->> 'decided_by')::uuid,
          now() + posture.exception_duration(r.exception_ttl), e.id, 'active', e.overlay)
  RETURNING n.id INTO exc;
  UPDATE posture.exception x SET state = 'renewed' WHERE x.id = e.id;
  IF e.overlay THEN
    IF EXISTS (SELECT 1 FROM posture.overlay_value o WHERE o.key = e.key AND o.source = 'exception' AND o.exception_id = e.id) THEN
      PERFORM posture.write_overlay(e.key, e.value, 'exception', NULL, exc);
    END IF;
  ELSIF EXISTS (SELECT 1 FROM posture.setting_value s WHERE s.key = e.key AND s.bu_id IS NOT DISTINCT FROM e.bu_id
             AND s.source = 'exception' AND s.exception_id = e.id) THEN
    PERFORM posture.write_value(e.key, e.bu_id, e.value, 'exception', NULL, exc);
  END IF;
  UPDATE posture.renewal x SET state = 'applied', new_exception_id = exc, applied_at = now() WHERE x.id = r.id;
  IF posture.deployment_mode() = 'saas' THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object(
      'type', 'setting.exception_renewed', 'key', e.key, 'bu_id', e.bu_id, 'overlay', e.overlay, 'value', e.value, 'bound', b.bound,
      'profile_family', b.family, 'exception_id', exc, 'renewed_from', e.id, 'requested_by', r.requested_by,
      'approved_by', a ->> 'decided_by', 'explanation', r.justification, 'at', now()));
  END IF;
  RETURN exc;
END $$;

REVOKE ALL ON FUNCTION posture.overlay_in_force(text), posture.overlay_applies(text), posture.write_overlay(text, jsonb, text, uuid, uuid),
  posture.overlay_exception(text), posture.overlay(), posture.request_overlay_change(text, jsonb, text, text),
  posture.apply_overlay_change(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.overlay() TO app_posture, app_rw;
GRANT EXECUTE ON FUNCTION posture.request_overlay_change(text, jsonb, text, text), posture.apply_overlay_change(uuid) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

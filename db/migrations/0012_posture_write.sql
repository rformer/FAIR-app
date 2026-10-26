-- F-015 T-09 (AC-02): write protection for posture settings.
--
-- Application roles have no table privileges (0011). Setting values change
-- only through the SECURITY DEFINER functions below, owned by
-- posture_definer and executable only by app_posture. The database, not the
-- caller, validates each value, enforces the hard floor, classifies the
-- change against the current value, and decides whether it needs approval,
-- so a compromised service cannot label a loosening as a tightening.
-- Every setting_value row carries row_mac, an HMAC-SHA-256 keyed by
-- posture.mac_key (unreadable by application roles); mac_mismatches() lets
-- the drift engine (T-25) detect out-of-band edits.
--
-- Errors use SQLSTATE class PF so the service can map them:
--   PF001 hard floor        PF002 approval required     PF003 not applicable
--   PF004 invalid value     PF005 approvals unavailable (until F-001 T-26)
--   PF006 configuration (no active profile, unbound key, no MAC key)

-- MAC keys (installer and rotation runbook; fair_owner only), as for
-- authz.ctx_key. New MACs use the newest unretired key; rows keep the id of
-- the key that signed them, so retired keys still verify. Like every posture
-- table, RLS is forced with a posture_definer-only policy, so the key
-- functions run as posture_definer and only fair_owner may call them.
CREATE TABLE posture.mac_key (
  key_id      text        PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  secret      bytea       NOT NULL CHECK (octet_length(secret) >= 32),
  created_at  timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz
);
REVOKE ALL ON posture.mac_key FROM PUBLIC;
ALTER TABLE posture.mac_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.mac_key FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.mac_key TO posture_definer USING (true) WITH CHECK (true);

CREATE FUNCTION posture.add_mac_key(new_key_id text, new_secret bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO posture.mac_key (key_id, secret) VALUES (new_key_id, new_secret);
$$;
CREATE FUNCTION posture.retire_mac_key(old_key_id text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE posture.mac_key SET retired_at = now() WHERE key_id = old_key_id AND retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'mac_key: no active key %', old_key_id USING ERRCODE = 'no_data_found';
  END IF;
END $$;
REVOKE ALL ON FUNCTION posture.add_mac_key(text, bytea), posture.retire_mac_key(text) FROM PUBLIC;

-- The table was created empty in 0011 and nothing could write it, so the new
-- column needs no default.
ALTER TABLE posture.setting_value ADD COLUMN mac_key_id text NOT NULL REFERENCES posture.mac_key (key_id);

-- A requested change that needs no approval is 'requested' until
-- apply_change applies it (normally in the same transaction).
ALTER TABLE posture.change DROP CONSTRAINT change_state_check;
ALTER TABLE posture.change ADD CONSTRAINT change_state_check
  CHECK (state IN ('requested', 'applied', 'pending_approval', 'rejected'));

---------------------------------------------------------------------------
-- Values and strictness (design §3). Values are JSON as in profile packages:
-- durations are Go duration strings ("15m0s", "2160h0m0s").
---------------------------------------------------------------------------

-- Go duration string -> nanoseconds.
CREATE FUNCTION posture.duration_ns(d text) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  num  constant text := '([0-9]+(?:\.[0-9]*)?|\.[0-9]+)';
  unit constant text := '(ns|us|µs|μs|ms|h|m|s)';
  m    text[];
  total numeric := 0;
BEGIN
  IF d = '0' THEN
    RETURN 0;
  END IF;
  IF d !~ ('^(' || num || unit || ')+$') THEN
    RAISE EXCEPTION 'invalid duration %', d USING ERRCODE = 'PF004';
  END IF;
  FOR m IN SELECT regexp_matches(d, num || unit, 'g') LOOP
    total := total + m[1]::numeric * CASE m[2]
      WHEN 'ns' THEN 1 WHEN 'us' THEN 1e3 WHEN 'µs' THEN 1e3 WHEN 'μs' THEN 1e3
      WHEN 'ms' THEN 1e6 WHEN 's' THEN 1e9 WHEN 'm' THEN 60e9 WHEN 'h' THEN 3600e9 END;
  END LOOP;
  RETURN total;
END $$;

-- Validates v for setting k; returns its definition.
CREATE FUNCTION posture.check_value(k text, v jsonb) RETURNS posture.setting_def
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d   posture.setting_def;
  bad boolean;
BEGIN
  SELECT * INTO d FROM posture.setting_def WHERE key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown setting %', k USING ERRCODE = 'PF004';
  END IF;
  -- Nested CASEs, not OR: SQL does not guarantee short-circuit evaluation,
  -- and a cast of the wrong JSON type must not error before the type test.
  -- (Assigned first: an IF condition ends at the first THEN.)
  bad := v IS NULL OR CASE
       WHEN d.type = 'duration' THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true ELSE posture.duration_ns(v #>> '{}') < 0 END
       WHEN d.type = 'int'      THEN CASE WHEN jsonb_typeof(v) <> 'number' THEN true
                                          ELSE (v #>> '{}')::numeric <> trunc((v #>> '{}')::numeric) END
       WHEN d.type = 'bool'     THEN jsonb_typeof(v) <> 'boolean'
       WHEN d.type = 'enum'     THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true ELSE NOT (v #>> '{}') = ANY (d.enum_order) END
       ELSE true -- 'set': not supported until a setting needs it
     END;
  IF bad THEN
    RAISE EXCEPTION 'invalid value % for % (%)', v, k, d.type USING ERRCODE = 'PF004';
  END IF;
  RETURN d;
END $$;

-- Strictness rank: higher is stricter.
CREATE FUNCTION posture.rank(d posture.setting_def, v jsonb) RETURNS numeric
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE d.direction
    WHEN 'lower_is_stricter'  THEN -CASE d.type WHEN 'duration' THEN posture.duration_ns(v #>> '{}') ELSE (v #>> '{}')::numeric END
    WHEN 'higher_is_stricter' THEN  CASE d.type WHEN 'duration' THEN posture.duration_ns(v #>> '{}') ELSE (v #>> '{}')::numeric END
    WHEN 'true_is_stricter'   THEN CASE WHEN (v #>> '{}')::boolean THEN 1 ELSE 0 END
    WHEN 'false_is_stricter'  THEN CASE WHEN (v #>> '{}')::boolean THEN 0 ELSE 1 END
    WHEN 'ordered'            THEN array_position(d.enum_order, v #>> '{}')
  END;
$$;

-- -1: a is weaker than b; 0: as strict; 1: stricter.
CREATE FUNCTION posture.compare(d posture.setting_def, a jsonb, b jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT sign(posture.rank(d, a) - posture.rank(d, b))::integer;
$$;

-- The active profile's family, default and bound for k.
CREATE FUNCTION posture.active_binding(k text, OUT family text, OUT default_value jsonb, OUT bound jsonb)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  SELECT p.family, v.default_value, v.bound INTO family, default_value, bound
  FROM posture.active_profile a
  JOIN posture.profile p ON p.id = a.profile_id AND p.version = a.version
  JOIN posture.profile_value v ON v.profile_id = a.profile_id AND v.version = a.version AND v.key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active profile, or % is not bound in it', k USING ERRCODE = 'PF006';
  END IF;
END $$;

-- The value in force for (k, bu): the BU's own row, else the instance row,
-- else the active profile default. BU inheritance along iam.bu_closure and
-- strictest-of arrive with T-22.
CREATE FUNCTION posture.current_value(k text, bu uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(
    (SELECT value FROM posture.setting_value WHERE key = k AND bu IS NOT NULL AND bu_id = bu),
    (SELECT value FROM posture.setting_value WHERE key = k AND bu_id IS NULL),
    (posture.active_binding(k)).default_value);
$$;

-- Hard floor (design §3, R-08): applies when it has no families or names the
-- active profile's family.
CREATE FUNCTION posture.check_floor(d posture.setting_def, family text, v jsonb) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF d.hard_floor IS NOT NULL
     AND (cardinality(d.hard_floor_families) = 0 OR family = ANY (d.hard_floor_families))
     AND posture.compare(d, v, d.hard_floor) < 0 THEN
    RAISE EXCEPTION '% = % is weaker than the hard floor %', d.key, v, d.hard_floor USING ERRCODE = 'PF001';
  END IF;
END $$;

---------------------------------------------------------------------------
-- Row MACs
---------------------------------------------------------------------------

-- HMAC-SHA-256 over the canonical jsonb text of (key, bu_id, value, source,
-- change_id, exception_id). jsonb output is canonical (sorted keys, fixed
-- spacing), so equal rows always give equal input.
CREATE FUNCTION posture.row_mac(key_id text, k text, bu uuid, v jsonb, src text, change uuid, exc uuid) RETURNS bytea
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  secret bytea;
BEGIN
  SELECT m.secret INTO secret FROM posture.mac_key m WHERE m.key_id = row_mac.key_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown MAC key %', key_id USING ERRCODE = 'PF006';
  END IF;
  RETURN authz.hmac(convert_to(jsonb_build_array(k, bu, v, src, change, exc)::text, 'UTF8'), secret, 'sha256');
END $$;

-- Writes (k, bu) under the newest MAC key.
CREATE FUNCTION posture.write_value(k text, bu uuid, v jsonb, src text, change uuid, exc uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  kid text;
BEGIN
  SELECT key_id INTO kid FROM posture.mac_key WHERE retired_at IS NULL ORDER BY created_at DESC, key_id LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active posture MAC key (install one with posture.add_mac_key)' USING ERRCODE = 'PF006';
  END IF;
  INSERT INTO posture.setting_value AS s (key, bu_id, value, source, change_id, exception_id, updated_at, mac_key_id, row_mac)
  VALUES (k, bu, v, src, change, exc, now(), kid, posture.row_mac(kid, k, bu, v, src, change, exc))
  ON CONFLICT (key, bu_id) DO UPDATE SET
    value = EXCLUDED.value, source = EXCLUDED.source, change_id = EXCLUDED.change_id,
    exception_id = EXCLUDED.exception_id, updated_at = EXCLUDED.updated_at,
    mac_key_id = EXCLUDED.mac_key_id, row_mac = EXCLUDED.row_mac;
END $$;

-- Rows whose MAC does not verify: out-of-band edits (design §6.7 check 1).
CREATE FUNCTION posture.mac_mismatches() RETURNS TABLE (key text, bu_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.key, s.bu_id FROM posture.setting_value s
  LEFT JOIN posture.mac_key m ON m.key_id = s.mac_key_id
  WHERE m.key_id IS NULL
     OR s.row_mac <> authz.hmac(convert_to(jsonb_build_array(s.key, s.bu_id, s.value, s.source, s.change_id, s.exception_id)::text, 'UTF8'), m.secret, 'sha256')
  ORDER BY s.key, s.bu_id NULLS FIRST;
$$;

---------------------------------------------------------------------------
-- The write path (design §5 write protection, §6.2, §6.3)
---------------------------------------------------------------------------

-- Records a change requested through the settings API. The database
-- classifies it: below the hard floor is refused (PF001); weaker than the
-- active profile's bound needs an explanation and an approval request
-- (state pending_approval); anything else is 'requested', ready for
-- apply_change. requested_by is the authenticated user the service acts for.
CREATE FUNCTION posture.request_change(k text, bu uuid, new_value jsonb, explanation text,
                                       requested_by uuid, approval_request_id uuid DEFAULT NULL) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     posture.setting_def := posture.check_value(k, new_value);
  b     record := posture.active_binding(k);
  cur   jsonb := posture.current_value(k, bu);
  dir   text;
  out_of_bounds boolean;
  id    uuid;
BEGIN
  IF bu IS NOT NULL AND NOT d.bu_scopable THEN
    RAISE EXCEPTION '% cannot be overridden per BU', k USING ERRCODE = 'PF004';
  END IF;
  PERFORM posture.check_floor(d, b.family, new_value);
  dir := CASE posture.compare(d, new_value, cur) WHEN 1 THEN 'tighten' WHEN 0 THEN 'neutral' ELSE 'loosen' END;
  out_of_bounds := posture.compare(d, new_value, b.bound) < 0;
  IF out_of_bounds AND (btrim(coalesce(explanation, '')) = '' OR approval_request_id IS NULL) THEN
    RAISE EXCEPTION '% = % is outside the active profile bound %: an explanation and dual approval are required', k, new_value, b.bound
      USING ERRCODE = 'PF002';
  END IF;
  INSERT INTO posture.change AS c (key, bu_id, old_value, new_value, direction, explanation, requested_by, approval_request_id, state)
  VALUES (k, bu, cur, new_value, dir, explanation, requested_by,
          CASE WHEN out_of_bounds THEN request_change.approval_request_id END,
          CASE WHEN out_of_bounds THEN 'pending_approval' ELSE 'requested' END)
  RETURNING c.id INTO id;
  RETURN id;
END $$;

-- Applies a recorded change. It is re-evaluated against the state at apply
-- time (the floor, profile or value may have moved since the request).
-- Changes that need approval are refused until F-001 T-26 provides the
-- approvals engine to verify against (PF005; fail closed).
CREATE FUNCTION posture.apply_change(change_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c posture.change;
  d posture.setting_def;
  b record;
BEGIN
  SELECT * INTO c FROM posture.change WHERE id = change_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'change % does not exist', change_id USING ERRCODE = 'PF003';
  END IF;
  IF c.state = 'pending_approval' THEN
    RAISE EXCEPTION 'change % needs dual approval, which cannot be verified until the approvals engine exists (F-001 T-26)', change_id
      USING ERRCODE = 'PF005';
  END IF;
  IF c.state <> 'requested' THEN
    RAISE EXCEPTION 'change % is %, not requested', change_id, c.state USING ERRCODE = 'PF003';
  END IF;
  d := posture.check_value(c.key, c.new_value);
  b := posture.active_binding(c.key);
  PERFORM posture.check_floor(d, b.family, c.new_value);
  IF posture.compare(d, c.new_value, b.bound) < 0 THEN
    RAISE EXCEPTION 'change % is now outside the active profile bound %; request it again', change_id, b.bound USING ERRCODE = 'PF002';
  END IF;
  PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'change', c.id, NULL);
  UPDATE posture.change SET state = 'applied', applied_at = now() WHERE id = c.id;
END $$;

-- Reverts an expired exception (design §6.3; run by the expiry job as
-- system:posture). The instance value returns to the active profile default;
-- a BU override is removed so the BU inherits again. If a later change has
-- already replaced the exception's value, only the exception is closed.
CREATE FUNCTION posture.apply_revert(exception_id uuid) RETURNS void
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
  UPDATE posture.exception x SET state = 'reverted' WHERE x.id = e.id;
END $$;

---------------------------------------------------------------------------
-- Ownership and grants
---------------------------------------------------------------------------

-- posture_definer reads definitions, profiles and keys, and writes values,
-- changes and exceptions; it needs pgcrypto's HMAC (installed in authz).
GRANT SELECT ON posture.setting_def, posture.profile, posture.profile_value, posture.active_profile TO posture_definer;
GRANT SELECT, INSERT, UPDATE ON posture.mac_key TO posture_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON posture.setting_value TO posture_definer;
GRANT SELECT, INSERT, UPDATE ON posture.change, posture.exception TO posture_definer;
GRANT USAGE ON SCHEMA authz TO posture_definer;
GRANT EXECUTE ON FUNCTION authz.hmac(bytea, bytea, text) TO posture_definer;

-- Grant before the ownership change: afterwards fair_owner may not grant.
REVOKE ALL ON FUNCTION
  posture.duration_ns(text), posture.check_value(text, jsonb), posture.rank(posture.setting_def, jsonb),
  posture.compare(posture.setting_def, jsonb, jsonb), posture.active_binding(text), posture.current_value(text, uuid),
  posture.check_floor(posture.setting_def, text, jsonb), posture.row_mac(text, text, uuid, jsonb, text, uuid, uuid),
  posture.write_value(text, uuid, jsonb, text, uuid, uuid), posture.mac_mismatches(),
  posture.request_change(text, uuid, jsonb, text, uuid, uuid), posture.apply_change(uuid), posture.apply_revert(uuid)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  posture.mac_mismatches(), posture.request_change(text, uuid, jsonb, text, uuid, uuid),
  posture.apply_change(uuid), posture.apply_revert(uuid)
  TO app_posture;

-- posture_definer needs CREATE on the schema only while it takes ownership.
GRANT CREATE ON SCHEMA posture TO posture_definer;
DO $$
DECLARE
  f regprocedure;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'posture.add_mac_key(text, bytea)', 'posture.retire_mac_key(text)', 'posture.duration_ns(text)', 'posture.check_value(text, jsonb)', 'posture.rank(posture.setting_def, jsonb)',
    'posture.compare(posture.setting_def, jsonb, jsonb)', 'posture.active_binding(text)', 'posture.current_value(text, uuid)',
    'posture.check_floor(posture.setting_def, text, jsonb)', 'posture.row_mac(text, text, uuid, jsonb, text, uuid, uuid)',
    'posture.write_value(text, uuid, jsonb, text, uuid, uuid)', 'posture.mac_mismatches()',
    'posture.request_change(text, uuid, jsonb, text, uuid, uuid)', 'posture.apply_change(uuid)', 'posture.apply_revert(uuid)'
  ]::regprocedure[] LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO posture_definer', f);
  END LOOP;
END $$;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

-- fair_owner's right to call the key functions was its implicit owner
-- privilege; the new owner grants it explicitly.
SET ROLE posture_definer;
GRANT EXECUTE ON FUNCTION posture.add_mac_key(text, bytea), posture.retire_mac_key(text) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

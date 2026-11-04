-- F-002 T-04 (F-002-AC-24, AC-25, AC-28; design §4.4): what the audit
-- trail's settings need from F-015.
--
--   * A string kind with the direction nonempty_is_stricter: any non-empty
--     value is as strict as any other, the empty value is weaker (SIEM
--     destinations). Values are at most 255 bytes, without control
--     characters, as in pkg/settings.
--   * setting_def.loosening_needs_approval: every loosening of such a setting
--     needs a written explanation and dual approval (approval kind
--     settings.loosen), within the bound or not. Approved, a within-bound
--     loosening applies as a change, not an exception; outside the bound the
--     settings.out_of_bounds exception path is unchanged. A release may set
--     the flag but not clear it (that would weaken the setting).
--
-- Change approvals of either kind are applied by posture.apply_change, which
-- now reads the approval's kind.

ALTER TABLE posture.setting_def DROP CONSTRAINT setting_def_type_check;
ALTER TABLE posture.setting_def ADD CONSTRAINT setting_def_type_check
  CHECK (type IN ('duration', 'int', 'bool', 'enum', 'set', 'string'));
ALTER TABLE posture.setting_def DROP CONSTRAINT setting_def_check;
ALTER TABLE posture.setting_def ADD CONSTRAINT setting_def_check
  CHECK ((type IN ('duration', 'int') AND direction IN ('lower_is_stricter', 'higher_is_stricter'))
      OR (type = 'bool' AND direction IN ('true_is_stricter', 'false_is_stricter'))
      OR (type = 'enum' AND direction = 'ordered')
      OR (type = 'set' AND direction = 'subset_is_stricter')
      OR (type = 'string' AND direction = 'nonempty_is_stricter'));
ALTER TABLE posture.setting_def ADD COLUMN loosening_needs_approval boolean NOT NULL DEFAULT false;

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('settings.loosen', 'settings.approve', 'Loosening a security setting whose binding requires approval for any loosening (F-002 AC-24)');

-- apply_change reads which kind of approval a change waits for.
GRANT SELECT (id, kind) ON iam.approval_request TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

CREATE OR REPLACE FUNCTION posture.check_value(k text, v jsonb) RETURNS posture.setting_def
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d   posture.setting_def;
  bad boolean;
  max_int constant numeric := 9223372036854775807; -- int64, as in Go
BEGIN
  SELECT * INTO d FROM posture.setting_def WHERE key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown setting %', k USING ERRCODE = 'PF004';
  END IF;
  -- Nested CASEs, not OR: SQL does not guarantee short-circuit evaluation,
  -- and a cast of the wrong JSON type must not error before the type test.
  -- (Assigned first: an IF condition ends at the first THEN.)
  bad := v IS NULL OR CASE
       WHEN d.type = 'duration' THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true
                                          ELSE posture.duration_ns(v #>> '{}') NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'int'      THEN CASE WHEN jsonb_typeof(v) <> 'number' THEN true
                                          ELSE (v #>> '{}')::numeric <> trunc((v #>> '{}')::numeric)
                                            OR (v #>> '{}')::numeric NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'bool'     THEN jsonb_typeof(v) <> 'boolean'
       WHEN d.type = 'enum'     THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true ELSE NOT (v #>> '{}') = ANY (d.enum_order) END
       WHEN d.type = 'string'   THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true
                                          ELSE octet_length(v #>> '{}') > 255 OR (v #>> '{}') ~ '[[:cntrl:]]' END
       ELSE true -- 'set': not supported until a setting needs it
     END;
  IF bad THEN
    RAISE EXCEPTION 'invalid value % for % (%)', v, k, d.type USING ERRCODE = 'PF004';
  END IF;
  RETURN d;
END $$;

CREATE OR REPLACE FUNCTION posture.rank(d posture.setting_def, v jsonb) RETURNS numeric
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE d.direction
    WHEN 'lower_is_stricter'  THEN -CASE d.type WHEN 'duration' THEN posture.duration_ns(v #>> '{}') ELSE (v #>> '{}')::numeric END
    WHEN 'higher_is_stricter' THEN  CASE d.type WHEN 'duration' THEN posture.duration_ns(v #>> '{}') ELSE (v #>> '{}')::numeric END
    WHEN 'true_is_stricter'   THEN CASE WHEN (v #>> '{}')::boolean THEN 1 ELSE 0 END
    WHEN 'false_is_stricter'  THEN CASE WHEN (v #>> '{}')::boolean THEN 0 ELSE 1 END
    WHEN 'ordered'            THEN array_position(d.enum_order, v #>> '{}')
    WHEN 'nonempty_is_stricter' THEN CASE WHEN (v #>> '{}') = '' THEN 0 ELSE 1 END
  END;
$$;

CREATE OR REPLACE FUNCTION posture.register_settings(owner_feature text, registered_version text, defs jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  item    jsonb;
  d       posture.setting_def;
  old     posture.setting_def;
  b       record;
  v       jsonb;
  unbound text[] := '{}';
  n       integer := 0;
BEGIN
  IF jsonb_typeof(defs) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'definitions must be a JSON array' USING ERRCODE = 'PF004';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM posture.active_profile) THEN
    RAISE EXCEPTION 'posture is not seeded: no active profile (run posture seed)' USING ERRCODE = 'PF006';
  END IF;

  FOR item IN SELECT * FROM jsonb_array_elements(defs) LOOP
    d.key := item ->> 'key';
    d.type := item ->> 'type';
    d.direction := item ->> 'direction';
    d.enum_order := CASE WHEN item ? 'order' AND jsonb_typeof(item -> 'order') = 'array'
                         THEN ARRAY(SELECT jsonb_array_elements_text(item -> 'order')) END;
    d.bu_scopable := coalesce((item ->> 'bu_scopable')::boolean, false);
    d.hard_floor := CASE WHEN jsonb_typeof(item -> 'hard_floor') = 'null' THEN NULL ELSE item -> 'hard_floor' END;
    d.hard_floor_families := coalesce(ARRAY(SELECT jsonb_array_elements_text(item -> 'hard_floor_families')), '{}');
    d.params := coalesce(ARRAY(SELECT jsonb_array_elements_text(item -> 'params')), '{}');
    d.loosening_needs_approval := coalesce((item ->> 'loosening_needs_approval')::boolean, false);
    d.owner_feature := register_settings.owner_feature;
    d.registered_version := register_settings.registered_version;

    SELECT * INTO old FROM posture.setting_def s WHERE s.key = d.key FOR UPDATE;
    IF FOUND THEN
      IF old.type IS DISTINCT FROM d.type OR old.direction IS DISTINCT FROM d.direction
         OR old.enum_order IS DISTINCT FROM d.enum_order OR old.bu_scopable IS DISTINCT FROM d.bu_scopable
         OR old.owner_feature IS DISTINCT FROM d.owner_feature THEN
        RAISE EXCEPTION '% is already registered by % with another definition; changing it needs a release migration', d.key, old.owner_feature
          USING ERRCODE = 'PF004';
      END IF;
      IF old.hard_floor IS NOT NULL AND (
           d.hard_floor IS NULL
           OR posture.compare(old, d.hard_floor, old.hard_floor) < 0
           -- empty families = every family; the floor must cover at least
           -- the families it covered before
           OR NOT (cardinality(d.hard_floor_families) = 0
                   OR (cardinality(old.hard_floor_families) > 0 AND old.hard_floor_families <@ d.hard_floor_families))) THEN
        RAISE EXCEPTION 'registering % would weaken its hard floor (% for %)', d.key, old.hard_floor, old.hard_floor_families
          USING ERRCODE = 'PF001';
      END IF;
      IF old.loosening_needs_approval AND NOT d.loosening_needs_approval THEN
        RAISE EXCEPTION 'registering % would drop the approval its loosenings need', d.key USING ERRCODE = 'PF001';
      END IF;
      UPDATE posture.setting_def s SET hard_floor = d.hard_floor, hard_floor_families = d.hard_floor_families,
        params = d.params, loosening_needs_approval = d.loosening_needs_approval,
        registered_version = d.registered_version, registered_at = now()
      WHERE s.key = d.key;
    ELSE
      -- The table's checks validate type, direction, order and key format.
      INSERT INTO posture.setting_def (key, type, direction, enum_order, bu_scopable, hard_floor, hard_floor_families,
                                       params, owner_feature, registered_version, loosening_needs_approval)
      VALUES (d.key, d.type, d.direction, d.enum_order, d.bu_scopable, d.hard_floor, d.hard_floor_families,
              d.params, d.owner_feature, d.registered_version, d.loosening_needs_approval);
    END IF;
    SELECT * INTO d FROM posture.setting_def s WHERE s.key = d.key;
    IF d.hard_floor IS NOT NULL THEN
      PERFORM posture.check_value(d.key, d.hard_floor);
    END IF;

    -- Bound in the active profile, and everything in force is valid.
    BEGIN
      b := posture.active_binding(d.key);
    EXCEPTION WHEN SQLSTATE 'PF006' THEN
      unbound := unbound || d.key;
      CONTINUE;
    END;
    PERFORM posture.check_value(d.key, b.default_value);
    PERFORM posture.check_value(d.key, b.bound);
    PERFORM posture.check_floor(d, b.family, b.bound);
    IF posture.compare(d, b.default_value, b.bound) < 0 THEN
      RAISE EXCEPTION '%: the active profile default % is weaker than its bound %', d.key, b.default_value, b.bound USING ERRCODE = 'PF004';
    END IF;
    FOR v IN SELECT s.value FROM posture.setting_value s WHERE s.key = d.key LOOP
      PERFORM posture.check_value(d.key, v);
    END LOOP;
    n := n + 1;
  END LOOP;

  IF cardinality(unbound) > 0 THEN
    RAISE EXCEPTION 'settings not bound by the active profile: % (every setting must ship with bindings)', array_to_string(unbound, ', ')
      USING ERRCODE = 'PF006';
  END IF;
  RETURN n;
END $$;

DROP FUNCTION posture.preview_change(text, uuid, jsonb);
CREATE FUNCTION posture.preview_change(k text, bu uuid, new_value jsonb,
  OUT direction text, OUT below_floor boolean, OUT out_of_bounds boolean, OUT current_value jsonb,
  OUT bound jsonb, OUT hard_floor jsonb, OUT params text[], OUT covered boolean, OUT loosening_approval boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d posture.setting_def := posture.check_value(k, new_value);
  b record := posture.active_binding(k);
BEGIN
  IF bu IS NOT NULL AND NOT d.bu_scopable THEN
    RAISE EXCEPTION '% cannot be overridden per BU', k USING ERRCODE = 'PF004';
  END IF;
  current_value := posture.current_value(k, bu);
  direction := CASE posture.compare(d, new_value, current_value) WHEN 1 THEN 'tighten' WHEN 0 THEN 'neutral' ELSE 'loosen' END;
  below_floor := d.hard_floor IS NOT NULL
    AND (cardinality(d.hard_floor_families) = 0 OR b.family = ANY (d.hard_floor_families))
    AND posture.compare(d, new_value, d.hard_floor) < 0;
  out_of_bounds := posture.compare(d, new_value, b.bound) < 0;
  bound := b.bound;
  hard_floor := d.hard_floor;
  params := d.params;
  -- Out of bounds but a tightening under an active exception: AC-22 applies.
  covered := out_of_bounds AND direction = 'tighten' AND posture.covering_exception(k, bu) IS NOT NULL;
  -- F-002 T-04: a loosening within the bound that still needs approval.
  loosening_approval := d.loosening_needs_approval AND direction = 'loosen' AND NOT out_of_bounds;
END $$;
REVOKE ALL ON FUNCTION posture.preview_change(text, uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.preview_change(text, uuid, jsonb) TO app_posture, app_rw;

CREATE OR REPLACE FUNCTION posture.request_change(k text, bu uuid, new_value jsonb, explanation text, exception_ttl text DEFAULT NULL,
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
  ELSIF p.loosening_approval THEN
    IF btrim(coalesce(explanation, '')) = '' THEN
      RAISE EXCEPTION 'loosening % to % needs a written explanation and dual approval', k, new_value USING ERRCODE = 'PF002';
    END IF;
    approval_request_id := iam.request_approval('settings.loosen', 'posture.change:' || change_id, explanation,
      jsonb_build_object('key', k, 'bu_id', bu, 'value', new_value, 'current', p.current_value, 'bound', p.bound, 'params', p.params), bu);
    state := 'pending_approval';
  ELSE
    state := 'requested';
  END IF;
  INSERT INTO posture.change (id, key, bu_id, old_value, new_value, direction, explanation, requested_by, approval_request_id, state, exception_ttl)
  VALUES (change_id, k, bu, p.current_value, new_value, direction, nullif(btrim(coalesce(explanation, '')), ''), actor,
          approval_request_id, state, CASE WHEN approval_request_id IS NOT NULL AND NOT p.loosening_approval THEN request_change.exception_ttl END);
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
  kind text;
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

  IF c.state = 'requested' AND d.loosening_needs_approval AND posture.compare(d, c.new_value, cur) < 0 THEN
    -- F-002 T-04: requested before the flag, or the value moved since.
    RAISE EXCEPTION 'change % now loosens %, which needs approval; request it again', change_id, c.key USING ERRCODE = 'PF002';
  END IF;
  IF c.state = 'pending_approval' THEN
    SELECT r.kind INTO kind FROM iam.approval_request r WHERE r.id = c.approval_request_id;
  END IF;

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
  ELSIF kind = 'settings.loosen' THEN
    -- F-002 T-04: an approved loosening within the bound is a change.
    a := iam.consume_approval(c.approval_request_id, 'settings.loosen', 'posture.change:' || c.id);
    IF posture.compare(d, c.new_value, b.bound) < 0 THEN
      RAISE EXCEPTION 'change % is now outside the active profile bound %; request it again', change_id, b.bound USING ERRCODE = 'PF002';
    END IF;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'change', c.id, NULL);
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

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

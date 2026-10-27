-- F-015 T-21 (AC-07, AC-16 - AC-19; design §6.4): the profile switch.
--
--   request_switch   (profile.manage) target: an approved profile version;
--                    computes every conflict at once (AC-16): each explicit
--                    instance or BU value weaker than the target's bound
--                    (values from the current profile follow the target). A target
--                    with any bound weaker than the current profile's is a
--                    loosening: it needs a justification and a dual approval
--                    (profile.switch, approver profile.approve), and is
--                    audited high (AC-19). The current profile stays in
--                    force while the switch is pending (AC-18).
--   resolve_conflict conform (set to the target default at activation) or
--                    exception (reason, duration, dual approval of kind
--                    settings.out_of_bounds); no exception below a hard floor
--                    of the target's family (AC-17).
--   activate_switch  one transaction (rollback-safe): refuses while any
--                    conflict is unresolved, consumes every approval, makes
--                    the target active, re-seeds values that came from the
--                    old profile, keeps explicit values within the new
--                    bounds, applies conforms and creates the exceptions.
--   cancel_switch, pending_switch (the Posture page's pending view).
-- The design's states map to resolving (requested, conflicts computed,
-- resolving, awaiting approvals), activated and cancelled.

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('profile.switch', 'profile.approve', 'Switch to a profile with weaker bounds (F-015 AC-19)');

CREATE TABLE posture.profile_switch (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  from_profile_id      text        NOT NULL,
  from_version         text        NOT NULL,
  target_profile_id    text        NOT NULL,
  target_version       text        NOT NULL,
  state                text        NOT NULL DEFAULT 'resolving' CHECK (state IN ('resolving', 'activated', 'cancelled')),
  loosening            boolean     NOT NULL,
  justification        text,
  requested_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  approval_request_id  uuid,
  created_at           timestamptz NOT NULL DEFAULT now(),
  activated_at         timestamptz,
  activated_by         uuid        REFERENCES iam.app_user (id),
  FOREIGN KEY (from_profile_id, from_version) REFERENCES posture.profile (id, version),
  FOREIGN KEY (target_profile_id, target_version) REFERENCES posture.profile (id, version),
  CHECK (NOT loosening OR (btrim(coalesce(justification, '')) <> '' AND approval_request_id IS NOT NULL)),
  CHECK ((state = 'activated') = (activated_at IS NOT NULL))
);
-- One open switch at a time.
CREATE UNIQUE INDEX profile_switch_open ON posture.profile_switch ((true)) WHERE state = 'resolving';

CREATE TABLE posture.switch_conflict (
  switch_id            uuid        NOT NULL REFERENCES posture.profile_switch (id),
  key                  text        NOT NULL,
  bu_id                uuid        REFERENCES iam.bu (id),
  current_value        jsonb       NOT NULL,
  current_source       text        NOT NULL,
  new_default          jsonb       NOT NULL,
  new_bound            jsonb       NOT NULL,
  below_floor          boolean     NOT NULL, -- the value is below a hard floor of the target's family: conform only
  resolution           text        NOT NULL DEFAULT 'unresolved' CHECK (resolution IN ('unresolved', 'conform', 'exception')),
  exception_reason     text,
  exception_ttl        text,
  approval_request_id  uuid,
  resolved_by          uuid        REFERENCES iam.app_user (id),
  exception_id         uuid        REFERENCES posture.exception (id),
  UNIQUE NULLS NOT DISTINCT (switch_id, key, bu_id),
  CHECK (resolution <> 'exception' OR (NOT below_floor AND btrim(coalesce(exception_reason, '')) <> '' AND approval_request_id IS NOT NULL))
);

ALTER TABLE posture.active_profile ADD CONSTRAINT active_profile_switch_fk FOREIGN KEY (switch_id) REFERENCES posture.profile_switch (id);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['profile_switch', 'switch_conflict'] LOOP
    EXECUTE format('REVOKE ALL ON posture.%I FROM PUBLIC', t);
    EXECUTE format('ALTER TABLE posture.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE posture.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY definer_only ON posture.%I TO posture_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE ON posture.profile_switch, posture.switch_conflict TO posture_definer;
GRANT UPDATE ON posture.active_profile TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Is the target profile weaker than the source on any registered bound?
CREATE FUNCTION posture.profile_loosens(from_id text, from_ver text, to_id text, to_ver text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM posture.profile_value f
    JOIN posture.profile_value t ON t.profile_id = to_id AND t.version = to_ver AND t.key = f.key
    JOIN posture.setting_def d ON d.key = f.key
    WHERE f.profile_id = from_id AND f.version = from_ver AND posture.compare(d, t.bound, f.bound) < 0);
$$;

-- Value v of setting d is below a hard floor that applies to family.
CREATE FUNCTION posture.below_floor(d posture.setting_def, family text, v jsonb) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.hard_floor IS NOT NULL
     AND (cardinality(d.hard_floor_families) = 0 OR family = ANY (d.hard_floor_families))
     AND posture.compare(d, v, d.hard_floor) < 0;
$$;

CREATE FUNCTION posture.request_switch(target_id text, target_version text, justification text DEFAULT NULL,
  OUT switch_id uuid, OUT loosening boolean, OUT conflicts integer, OUT approval_request_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
  a     posture.active_profile;
  t     posture.profile;
BEGIN
  SELECT * INTO a FROM posture.active_profile;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'posture is not seeded' USING ERRCODE = 'PF006';
  END IF;
  SELECT * INTO t FROM posture.profile x WHERE x.id = target_id AND x.version = request_switch.target_version;
  IF NOT FOUND OR t.status <> 'approved' THEN
    RAISE EXCEPTION 'profile % % is not an approved profile', target_id, target_version USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.profile_switch s WHERE s.state = 'resolving') THEN
    RAISE EXCEPTION 'another profile switch is pending' USING ERRCODE = 'PF003';
  END IF;
  switch_id := gen_random_uuid();
  loosening := posture.profile_loosens(a.profile_id, a.version, t.id, t.version);
  IF loosening THEN
    IF btrim(coalesce(justification, '')) = '' THEN
      RAISE EXCEPTION 'switching to % % loosens bounds: a written justification and dual approval are required', t.id, t.version
        USING ERRCODE = 'PF002';
    END IF;
    approval_request_id := iam.request_approval('profile.switch', 'posture.switch:' || switch_id, justification,
      jsonb_build_object('from', a.profile_id || '@' || a.version, 'to', t.id || '@' || t.version), NULL);
  END IF;
  INSERT INTO posture.profile_switch (id, from_profile_id, from_version, target_profile_id, target_version, loosening,
                                      justification, requested_by, approval_request_id)
  VALUES (switch_id, a.profile_id, a.version, t.id, t.version, loosening, nullif(btrim(coalesce(justification, '')), ''),
          actor, approval_request_id);
  -- AC-16: every explicit value weaker than the target's bound. Instance
  -- values that came from the current profile are not conflicts: they follow
  -- the target's defaults at activation (design §6.4).
  INSERT INTO posture.switch_conflict (switch_id, key, bu_id, current_value, current_source, new_default, new_bound, below_floor)
  SELECT request_switch.switch_id, s.key, s.bu_id, s.value, s.source, n.default_value, n.bound, posture.below_floor(d, t.family, s.value)
  FROM posture.setting_value s
  JOIN posture.setting_def d ON d.key = s.key
  JOIN posture.profile_value n ON n.profile_id = t.id AND n.version = t.version AND n.key = s.key
  WHERE posture.compare(d, s.value, n.bound) < 0 AND NOT (s.source = 'profile' AND s.bu_id IS NULL);
  GET DIAGNOSTICS conflicts = ROW_COUNT;
END $$;

-- Resolves one conflict (bu NULL: the instance value).
CREATE FUNCTION posture.resolve_conflict(sw uuid, k text, bu uuid, resolution text, reason text DEFAULT NULL, exception_ttl text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
  c     posture.switch_conflict;
  req   uuid;
BEGIN
  SELECT x.* INTO c FROM posture.switch_conflict x JOIN posture.profile_switch s ON s.id = x.switch_id
  WHERE x.switch_id = sw AND x.key = k AND x.bu_id IS NOT DISTINCT FROM bu AND s.state = 'resolving' FOR UPDATE OF x;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no open conflict for % in switch %', k, sw USING ERRCODE = 'PF003';
  END IF;
  IF resolution = 'conform' THEN
    UPDATE posture.switch_conflict x SET resolution = 'conform', exception_reason = NULL, exception_ttl = NULL,
      approval_request_id = NULL, resolved_by = actor
    WHERE x.switch_id = sw AND x.key = k AND x.bu_id IS NOT DISTINCT FROM bu;
    RETURN NULL;
  ELSIF resolution = 'exception' THEN
    IF c.below_floor THEN
      RAISE EXCEPTION '% = % is below the hard floor of the target profile: it can only conform', k, c.current_value USING ERRCODE = 'PF001';
    END IF;
    IF btrim(coalesce(reason, '')) = '' THEN
      RAISE EXCEPTION 'an exception needs a reason' USING ERRCODE = 'PF002';
    END IF;
    IF exception_ttl IS NOT NULL AND posture.duration_ns(exception_ttl) <= 0 THEN
      RAISE EXCEPTION 'an exception needs a positive duration' USING ERRCODE = 'PF009';
    END IF;
    req := iam.request_approval('settings.out_of_bounds', 'posture.conflict:' || sw || ':' || k || ':' || coalesce(bu::text, 'instance'), reason,
      jsonb_build_object('switch_id', sw, 'key', k, 'bu_id', bu, 'value', c.current_value, 'new_bound', c.new_bound,
                         'exception_duration', exception_ttl), bu);
    UPDATE posture.switch_conflict x SET resolution = 'exception', exception_reason = btrim(reason),
      exception_ttl = resolve_conflict.exception_ttl, approval_request_id = req, resolved_by = actor
    WHERE x.switch_id = sw AND x.key = k AND x.bu_id IS NOT DISTINCT FROM bu;
    RETURN req;
  END IF;
  RAISE EXCEPTION 'resolution must be conform or exception' USING ERRCODE = 'PF004';
END $$;

CREATE FUNCTION posture.cancel_switch(sw uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
BEGIN
  UPDATE posture.profile_switch s SET state = 'cancelled' WHERE s.id = sw AND s.state = 'resolving';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'switch % is not pending', sw USING ERRCODE = 'PF003';
  END IF;
END $$;

-- AC-17, AC-19: one transaction; any failure (an unresolved conflict, an
-- approval not granted) leaves everything as it was.
CREATE FUNCTION posture.activate_switch(sw uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor   uuid := posture.profile_actor('profile.manage');
  s       posture.profile_switch;
  t       posture.profile;
  c       posture.switch_conflict;
  v       posture.setting_value;
  d       posture.setting_def;
  n       posture.profile_value;
  a       jsonb;
  exc     uuid;
  changed integer := 0;
BEGIN
  SELECT * INTO s FROM posture.profile_switch x WHERE x.id = sw FOR UPDATE;
  IF NOT FOUND OR s.state <> 'resolving' THEN
    RAISE EXCEPTION 'switch % is not pending', sw USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.switch_conflict x WHERE x.switch_id = sw AND x.resolution = 'unresolved') THEN
    RAISE EXCEPTION 'switch % has unresolved conflicts (AC-17)', sw USING ERRCODE = 'PF003';
  END IF;
  SELECT * INTO t FROM posture.profile x WHERE x.id = s.target_profile_id AND x.version = s.target_version;
  IF t.status <> 'approved' THEN
    RAISE EXCEPTION 'profile % % is no longer approved', t.id, t.version USING ERRCODE = 'PF003';
  END IF;
  IF s.loosening THEN
    PERFORM iam.consume_approval(s.approval_request_id, 'profile.switch', 'posture.switch:' || sw);
  END IF;
  -- Values are re-checked against the profiles as they are now; anything
  -- weaker than the target bound that is not a recorded conflict refuses.
  IF EXISTS (SELECT 1 FROM posture.setting_value x
             JOIN posture.setting_def dd ON dd.key = x.key
             JOIN posture.profile_value nn ON nn.profile_id = t.id AND nn.version = t.version AND nn.key = x.key
             WHERE posture.compare(dd, x.value, nn.bound) < 0 AND NOT (x.source = 'profile' AND x.bu_id IS NULL)
               AND NOT EXISTS (SELECT 1 FROM posture.switch_conflict y WHERE y.switch_id = sw AND y.key = x.key AND y.bu_id IS NOT DISTINCT FROM x.bu_id)) THEN
    RAISE EXCEPTION 'settings changed since the switch was requested; cancel it and request it again' USING ERRCODE = 'PF003';
  END IF;

  UPDATE posture.profile x SET status = 'approved' WHERE x.id = s.from_profile_id AND x.version = s.from_version;
  UPDATE posture.profile x SET status = 'active' WHERE x.id = t.id AND x.version = t.version;
  UPDATE posture.active_profile SET profile_id = t.id, version = t.version, activated_at = now(), activated_by = actor, switch_id = sw;

  -- 1. Values that came from the old profile follow the new defaults
  --    (explicit values within the new bounds stay), and settings the new
  --    profile binds without a value get one. Done first, so exceptions
  --    below use the new exception.max_duration.
  FOR v IN SELECT x.* FROM posture.setting_value x
           WHERE x.source = 'profile' AND x.bu_id IS NULL
             AND NOT EXISTS (SELECT 1 FROM posture.switch_conflict y WHERE y.switch_id = sw AND y.key = x.key AND y.bu_id IS NULL)
           ORDER BY x.key LOOP
    SELECT * INTO n FROM posture.profile_value x WHERE x.profile_id = t.id AND x.version = t.version AND x.key = v.key;
    IF FOUND AND n.default_value <> v.value THEN
      PERFORM posture.write_value(v.key, NULL, n.default_value, 'profile', NULL, NULL);
      changed := changed + 1;
    END IF;
  END LOOP;
  FOR n IN SELECT x.* FROM posture.profile_value x WHERE x.profile_id = t.id AND x.version = t.version
           AND NOT EXISTS (SELECT 1 FROM posture.setting_value y WHERE y.key = x.key AND y.bu_id IS NULL) LOOP
    PERFORM posture.write_value(n.key, NULL, n.default_value, 'profile', NULL, NULL);
    changed := changed + 1;
  END LOOP;

  -- 2. Conflicts, as resolved.
  FOR c IN SELECT x.* FROM posture.switch_conflict x WHERE x.switch_id = sw ORDER BY x.key, x.bu_id NULLS FIRST LOOP
    SELECT * INTO v FROM posture.setting_value x WHERE x.key = c.key AND x.bu_id IS NOT DISTINCT FROM c.bu_id;
    IF v.source = 'exception' THEN -- the old exception ends either way
      UPDATE posture.exception e SET state = 'superseded' WHERE e.id = v.exception_id AND e.state = 'active';
    END IF;
    IF c.resolution = 'conform' THEN
      PERFORM posture.write_value(c.key, c.bu_id, c.new_default, 'profile', NULL, NULL);
    ELSE
      a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds',
                                'posture.conflict:' || sw || ':' || c.key || ':' || coalesce(c.bu_id::text, 'instance'));
      INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
      VALUES (c.key, c.bu_id, v.value, c.new_bound, c.exception_reason, c.resolved_by, (a ->> 'decided_by')::uuid,
              now() + posture.exception_duration(c.exception_ttl), 'active')
      RETURNING e.id INTO exc;
      PERFORM posture.write_value(c.key, c.bu_id, v.value, 'exception', NULL, exc);
      UPDATE posture.switch_conflict x SET exception_id = exc WHERE x.switch_id = sw AND x.key = c.key AND x.bu_id IS NOT DISTINCT FROM c.bu_id;
    END IF;
    changed := changed + 1;
  END LOOP;

  UPDATE posture.profile_switch x SET state = 'activated', activated_at = now(), activated_by = actor WHERE x.id = sw;
  IF s.loosening AND posture.deployment_mode() = 'saas' THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object(
      'type', 'profile.switched', 'from', s.from_profile_id || '@' || s.from_version, 'to', t.id || '@' || t.version,
      'loosening', true, 'justification', s.justification, 'requested_by', s.requested_by, 'activated_by', actor, 'at', now()));
  END IF;
  RETURN changed;
END $$;

-- AC-18: the pending switch and its conflicts.
CREATE FUNCTION posture.pending_switch()
RETURNS TABLE (switch_id uuid, from_profile text, target_profile text, loosening boolean, approval_request_id uuid,
               key text, bu_id uuid, current_value jsonb, new_bound jsonb, below_floor boolean, resolution text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  reader uuid := posture.profile_reader();
BEGIN
  RETURN QUERY
  SELECT s.id, s.from_profile_id || '@' || s.from_version, s.target_profile_id || '@' || s.target_version, s.loosening, s.approval_request_id,
         c.key, c.bu_id, c.current_value, c.new_bound, c.below_floor, c.resolution
  FROM posture.profile_switch s LEFT JOIN posture.switch_conflict c ON c.switch_id = s.id
  WHERE s.state = 'resolving'
  ORDER BY c.key, c.bu_id NULLS FIRST;
END $$;

REVOKE ALL ON FUNCTION posture.profile_loosens(text, text, text, text), posture.below_floor(posture.setting_def, text, jsonb),
  posture.request_switch(text, text, text), posture.resolve_conflict(uuid, text, uuid, text, text, text),
  posture.cancel_switch(uuid), posture.activate_switch(uuid), posture.pending_switch() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.request_switch(text, text, text), posture.resolve_conflict(uuid, text, uuid, text, text, text),
  posture.cancel_switch(uuid), posture.activate_switch(uuid), posture.pending_switch() TO app_posture, app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

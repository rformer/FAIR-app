-- F-015 T-12 (AC-01): startup registration (design §6.1).
--
-- Each service registers the settings it reads when it starts. A registered
-- key that the active profile does not bind is a startup error (PF006), so
-- every new setting must ship with bindings. Any service may register
-- (app_rw), so registration can never weaken anything:
--   * a new key is checked against the active profile: its default and bound,
--     and every value in force, must be valid for the definition and not
--     below its hard floor;
--   * an existing key must keep its type, direction, enum order, BU scoping
--     and owning feature; its hard floor may only stay or tighten.
-- Changing a definition otherwise needs a release migration.

CREATE FUNCTION posture.register_settings(owner_feature text, registered_version text, defs jsonb) RETURNS integer
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
      UPDATE posture.setting_def s SET hard_floor = d.hard_floor, hard_floor_families = d.hard_floor_families,
        params = d.params, registered_version = d.registered_version, registered_at = now()
      WHERE s.key = d.key;
    ELSE
      -- The table's checks validate type, direction, order and key format.
      INSERT INTO posture.setting_def (key, type, direction, enum_order, bu_scopable, hard_floor, hard_floor_families,
                                       params, owner_feature, registered_version)
      VALUES (d.key, d.type, d.direction, d.enum_order, d.bu_scopable, d.hard_floor, d.hard_floor_families,
              d.params, d.owner_feature, d.registered_version);
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

GRANT INSERT, UPDATE ON posture.setting_def TO posture_definer;
REVOKE ALL ON FUNCTION posture.register_settings(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.register_settings(text, text, jsonb) TO app_rw, app_posture;

GRANT CREATE ON SCHEMA posture TO posture_definer;
ALTER FUNCTION posture.register_settings(text, text, jsonb) OWNER TO posture_definer;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

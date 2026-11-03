-- F-001 T-42 (design §6, AC-25): an id that does not exist answers 404, as
-- one out of the caller's reach does. The posture functions report a
-- missing object with the error they use for a state conflict (PF003), so
-- the Posture API asks posture.exists first and answers 404 itself; an
-- object that exists in the wrong state still answers 409.

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

CREATE FUNCTION posture.exists(kind text, object_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  CASE kind
    WHEN 'setting' THEN
      RETURN EXISTS (SELECT 1 FROM posture.setting_def d WHERE d.key = object_id);
    WHEN 'exception' THEN
      RETURN EXISTS (SELECT 1 FROM posture.exception e WHERE e.id::text = object_id);
    WHEN 'profile' THEN
      RETURN EXISTS (SELECT 1 FROM posture.profile p WHERE p.id = object_id);
    WHEN 'custom_profile' THEN
      RETURN EXISTS (SELECT 1 FROM posture.profile p WHERE p.id = object_id AND p.kind = 'custom');
    WHEN 'switch' THEN
      RETURN EXISTS (SELECT 1 FROM posture.profile_switch s WHERE s.id::text = object_id);
    WHEN 'drift_finding' THEN
      RETURN EXISTS (SELECT 1 FROM posture.drift_finding f WHERE f.id::text = object_id);
    ELSE
      RAISE EXCEPTION 'posture.exists: unknown kind %', kind USING ERRCODE = 'PF004';
  END CASE;
END $$;

REVOKE ALL ON FUNCTION posture.exists(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.exists(text, text) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

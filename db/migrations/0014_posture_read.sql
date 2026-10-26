-- F-015 T-11 (AC-01, NFR 60 s): the read side of the settings library.
--
-- Services read effective values only through the two definer functions
-- below (design §5 access model); they still have no table privileges.
-- posture.state.version increases with every change to the values in force
-- (setting values, the active profile, profile values), including
-- out-of-band edits, so a cache can poll it cheaply (30 s TTL backstop) and
-- events can say which version they announce.

CREATE TABLE posture.state (
  singleton  boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  version    bigint      NOT NULL DEFAULT 1,
  changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO posture.state DEFAULT VALUES;
REVOKE ALL ON posture.state FROM PUBLIC;
ALTER TABLE posture.state ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.state FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.state TO posture_definer USING (true) WITH CHECK (true);

-- Runs as posture_definer whoever writes, so direct edits bump it too.
CREATE FUNCTION posture.bump_version() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE posture.state SET version = version + 1, changed_at = now();
  RETURN NULL;
END $$;

CREATE TRIGGER bump_version AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON posture.setting_value
  FOR EACH STATEMENT EXECUTE FUNCTION posture.bump_version();
CREATE TRIGGER bump_version AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON posture.active_profile
  FOR EACH STATEMENT EXECUTE FUNCTION posture.bump_version();
CREATE TRIGGER bump_version AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON posture.profile_value
  FOR EACH STATEMENT EXECUTE FUNCTION posture.bump_version();

CREATE FUNCTION posture.settings_version() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT version FROM posture.state;
$$;

-- One consistent snapshot of the values in force:
--   {"version": n, "profile": id, "profile_version": v,
--    "instance": {key: value},            -- active profile defaults, overlaid
--                                         -- by instance-wide values
--    "bu": {bu_id: {key: value}}}         -- BU overrides
-- Without an active profile (not yet seeded) profile is null and instance
-- holds only explicit values. BU inheritance along iam.bu_closure and
-- strictest-of arrive with T-22.
CREATE FUNCTION posture.effective_settings() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH a AS (SELECT profile_id, version FROM posture.active_profile)
  SELECT jsonb_build_object(
    'version', (SELECT version FROM posture.state),
    'profile', (SELECT profile_id FROM a),
    'profile_version', (SELECT version FROM a),
    'instance', coalesce((SELECT jsonb_object_agg(v.key, v.default_value) FROM posture.profile_value v
                          JOIN a ON v.profile_id = a.profile_id AND v.version = a.version), '{}'::jsonb)
             || coalesce((SELECT jsonb_object_agg(s.key, s.value) FROM posture.setting_value s WHERE s.bu_id IS NULL), '{}'::jsonb),
    'bu', coalesce((SELECT jsonb_object_agg(b.bu_id, b.vals) FROM (
                      SELECT s.bu_id, jsonb_object_agg(s.key, s.value) AS vals
                      FROM posture.setting_value s WHERE s.bu_id IS NOT NULL GROUP BY s.bu_id) b), '{}'::jsonb));
$$;

GRANT SELECT, UPDATE ON posture.state TO posture_definer;
REVOKE ALL ON FUNCTION posture.bump_version(), posture.settings_version(), posture.effective_settings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.settings_version(), posture.effective_settings() TO app_rw, app_posture;
-- Services reach the read functions through the schema; still no table
-- privileges (design §5 access model; app_rw's schema access was deferred
-- to this task).
GRANT USAGE ON SCHEMA posture TO app_rw;

GRANT CREATE ON SCHEMA posture TO posture_definer;
ALTER FUNCTION posture.bump_version() OWNER TO posture_definer;
ALTER FUNCTION posture.settings_version() OWNER TO posture_definer;
ALTER FUNCTION posture.effective_settings() OWNER TO posture_definer;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

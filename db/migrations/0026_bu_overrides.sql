-- F-015 T-22 (AC-32, AC-35; design §6.6): BU overrides inherit down the BU
-- tree the way F-001 role assignments do, stopping at restricted BUs, and
-- the value in force for a BU is the strictest of the instance value and
-- every override that reaches it:
--
--   effective(k, bu) = strictest(instance(k),
--                                override(k, a) for every ancestor a of bu,
--                                bu included, whose path to bu is unblocked)
--
-- An override on a restricted BU applies to it and below; one above stops at
-- it (iam.bu_closure.blocked, F-001 T-05). current_value (used by the change
-- evaluator, previews and switches) and effective_settings (read by every
-- service's settings client) follow this rule, and BU tree changes (moves,
-- restrictions) bump the posture version so caches refresh.

-- Narrow tree reads for posture_definer, which reads no iam table.
CREATE FUNCTION iam.unblocked_ancestors(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.ancestor_id FROM iam.bu_closure c WHERE c.descendant_id = bu AND NOT c.blocked;
$$;
CREATE FUNCTION iam.unblocked_descendants(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id FROM iam.bu_closure c WHERE c.ancestor_id = bu AND NOT c.blocked;
$$;
REVOKE ALL ON FUNCTION iam.unblocked_ancestors(uuid), iam.unblocked_descendants(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.unblocked_ancestors(uuid), iam.unblocked_descendants(uuid) TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The value in force for (k, bu); bu NULL is the instance value.
CREATE OR REPLACE FUNCTION posture.current_value(k text, bu uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  inst jsonb := coalesce((SELECT s.value FROM posture.setting_value s WHERE s.key = k AND s.bu_id IS NULL),
                         (posture.active_binding(k)).default_value);
  d    posture.setting_def;
BEGIN
  IF bu IS NULL THEN
    RETURN inst;
  END IF;
  SELECT * INTO d FROM posture.setting_def s WHERE s.key = k;
  IF NOT FOUND THEN
    RETURN inst;
  END IF;
  RETURN posture.strictest(d, ARRAY[inst] || ARRAY(
    SELECT s.value FROM posture.setting_value s
    WHERE s.key = k AND s.bu_id IN (SELECT iam.unblocked_ancestors(bu))));
END $$;

-- As in T-11, but "bu" now holds, for every BU an override reaches, each
-- BU-scopable value that differs from the instance value.
CREATE OR REPLACE FUNCTION posture.effective_settings() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH a AS (SELECT profile_id, version FROM posture.active_profile),
  inst AS (
    SELECT coalesce((SELECT jsonb_object_agg(v.key, v.default_value) FROM posture.profile_value v
                     JOIN a ON v.profile_id = a.profile_id AND v.version = a.version), '{}'::jsonb)
        || coalesce((SELECT jsonb_object_agg(s.key, s.value) FROM posture.setting_value s WHERE s.bu_id IS NULL), '{}'::jsonb) AS vals),
  reached AS (
    SELECT DISTINCT r.bu, s.key
    FROM posture.setting_value s
    CROSS JOIN LATERAL (SELECT iam.unblocked_descendants(s.bu_id) AS bu) r
    WHERE s.bu_id IS NOT NULL),
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

-- fair_owner's BU tree trigger below calls bump_version.
GRANT EXECUTE ON FUNCTION posture.bump_version() TO fair_owner;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

CREATE TRIGGER posture_bump_version AFTER INSERT OR UPDATE OR DELETE ON iam.bu_closure
  FOR EACH STATEMENT EXECUTE FUNCTION posture.bump_version();

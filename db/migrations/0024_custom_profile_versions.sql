-- F-015 T-20 (AC-14, AC-15; design §6.5): custom profile versions, diffs,
-- and base updates that never silently weaken.
--
--   * new_custom_version copies a custom profile version into the next
--     numbered draft; submitted versions never change.
--   * profile_diff compares two profile versions key by key.
--   * base_update_effects shows, for every profile derived from a base, what
--     moving to a new base version would do per key; rebase_custom_profile
--     creates that new draft version. For each key, with C the custom value
--     and N the new base value:
--       N weaker than C   -> pinned: C is kept (never silently weaker, AC-15);
--       N stricter than C -> proposed: C is kept and N offered; if C is now
--                            looser than the new base it needs a justification
--                            (or the proposal adopted) before submission;
--       equal             -> unchanged; keys new in the base -> added from it.
--   * custom_profile_export / profile_meta feed the JSON and OSCAL export;
--     import (in the service) creates a draft through the edit rules.

-- A rebase can leave a key looser than the new base with no justification
-- yet (the base got stricter): it is marked needs_review, which blocks
-- submission until the key is edited (proposal adopted or value justified).
-- Outside review, a loosened key still needs its justification.
ALTER TABLE posture.profile_value ADD COLUMN needs_review boolean NOT NULL DEFAULT false;
ALTER TABLE posture.profile_value DROP CONSTRAINT profile_value_check;
ALTER TABLE posture.profile_value ADD CONSTRAINT profile_value_justified
  CHECK (NOT loosened OR needs_review OR btrim(coalesce(justification, '')) <> '');

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Editing a key resolves its review.
CREATE OR REPLACE FUNCTION posture.edit_custom_value(pid text, ver text, k text, new_default jsonb, new_bound jsonb, justification text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor  uuid := posture.profile_actor('profile.manage');
  p      posture.profile := posture.draft_profile(pid, ver);
  d      posture.setting_def;
  base   posture.profile_value;
  loose  boolean;
BEGIN
  SELECT * INTO d FROM posture.setting_def s WHERE s.key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION '% is not a registered setting and cannot be edited', k USING ERRCODE = 'PF004';
  END IF;
  PERFORM posture.check_value(k, new_default);
  PERFORM posture.check_value(k, new_bound);
  IF posture.compare(d, new_default, new_bound) < 0 THEN
    RAISE EXCEPTION '%: the default % is weaker than the bound %', k, new_default, new_bound USING ERRCODE = 'PF004';
  END IF;
  PERFORM posture.check_floor(d, p.family, new_bound); -- AC-11: nothing on the hard floor can be weakened
  SELECT * INTO base FROM posture.profile_value v WHERE v.profile_id = p.base_profile_id AND v.version = p.base_version AND v.key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION '% is not part of the base profile', k USING ERRCODE = 'PF004';
  END IF;
  loose := posture.compare(d, new_bound, base.bound) < 0 OR posture.compare(d, new_default, base.default_value) < 0;
  IF loose AND btrim(coalesce(justification, '')) = '' THEN
    RAISE EXCEPTION '%: a loosened value needs a written justification (AC-12)', k USING ERRCODE = 'PF002';
  END IF;
  UPDATE posture.profile_value v
  SET default_value = new_default, bound = new_bound, loosened = loose, needs_review = false,
      justification = CASE WHEN loose THEN btrim(edit_custom_value.justification) END
  WHERE v.profile_id = pid AND v.version = ver AND v.key = k;
  UPDATE posture.profile x SET label_deviates = EXISTS (
    SELECT 1 FROM posture.profile_value v WHERE v.profile_id = pid AND v.version = ver AND v.loosened)
  WHERE x.id = pid AND x.version = ver;
  RETURN loose;
END $$;

-- Submission also refuses keys still under review.
CREATE OR REPLACE FUNCTION posture.validate_custom_profile(pid text, ver text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p        posture.profile;
  d        posture.setting_def;
  v        posture.profile_value;
  b        posture.profile_value;
  problems text[] := '{}';
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = ver;
  FOR d IN SELECT * FROM posture.setting_def ORDER BY key LOOP
    SELECT * INTO v FROM posture.profile_value x WHERE x.profile_id = pid AND x.version = ver AND x.key = d.key;
    IF NOT FOUND THEN
      problems := problems || (d.key || ': not bound');
      CONTINUE;
    END IF;
    BEGIN
      PERFORM posture.check_value(d.key, v.default_value);
      PERFORM posture.check_value(d.key, v.bound);
      PERFORM posture.check_floor(d, p.family, v.bound);
    EXCEPTION WHEN SQLSTATE 'PF001' OR SQLSTATE 'PF004' THEN
      problems := problems || (d.key || ': ' || SQLERRM);
      CONTINUE;
    END;
    IF posture.compare(d, v.default_value, v.bound) < 0 THEN
      problems := problems || (d.key || ': default weaker than bound');
    END IF;
    IF v.needs_review THEN
      SELECT * INTO b FROM posture.profile_value x WHERE x.profile_id = p.base_profile_id AND x.version = p.base_version AND x.key = d.key;
      problems := problems || (d.key || ': the base update proposes ' || b.default_value::text || '/' || b.bound::text
                               || '; adopt it or justify the current value');
    ELSIF v.loosened AND btrim(coalesce(v.justification, '')) = '' THEN
      problems := problems || (d.key || ': loosened without justification');
    END IF;
  END LOOP;
  RETURN problems;
END $$;

-- Holders of profile.manage or profile.approve may read profiles.
CREATE FUNCTION posture.profile_reader() RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL OR NOT (iam.holds_permission(u, 'profile.manage', NULL) OR iam.holds_permission(u, 'profile.approve', NULL)) THEN
    RAISE EXCEPTION 'profile.manage or profile.approve is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- The next version of a custom profile, as a draft copy of from_version.
CREATE FUNCTION posture.new_custom_version(pid text, from_version text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
  p     posture.profile;
  nv    text;
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = from_version AND x.kind = 'custom';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom profile % % does not exist', pid, from_version USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = pid AND x.status = 'draft') THEN
    RAISE EXCEPTION 'custom profile % already has a draft version', pid USING ERRCODE = 'PF003';
  END IF;
  nv := (SELECT (max(x.version::integer) + 1)::text FROM posture.profile x WHERE x.id = pid);
  INSERT INTO posture.profile (id, version, name, family, kind, base_profile_id, base_version, status, label_deviates, created_by)
  VALUES (pid, nv, p.name, p.family, 'custom', p.base_profile_id, p.base_version, 'draft', p.label_deviates, actor);
  INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound, justification, loosened, needs_review)
  SELECT pid, nv, v.key, v.default_value, v.bound, v.justification, v.loosened, v.needs_review
  FROM posture.profile_value v WHERE v.profile_id = pid AND v.version = from_version;
  RETURN nv;
END $$;

-- Key-by-key comparison of two profile versions (AC-14). change is
-- 'tighten', 'loosen', 'mixed', 'unchanged', 'added' (only in b),
-- 'removed' (only in a) or 'unregistered'.
CREATE FUNCTION posture.profile_diff(a_id text, a_version text, b_id text, b_version text)
RETURNS TABLE (key text, a_default jsonb, a_bound jsonb, b_default jsonb, b_bound jsonb, change text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  reader uuid := posture.profile_reader();
BEGIN
  IF NOT EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = a_id AND x.version = a_version)
     OR NOT EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = b_id AND x.version = b_version) THEN
    RAISE EXCEPTION 'unknown profile version' USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY
  SELECT coalesce(a.key, b.key), a.default_value, a.bound, b.default_value, b.bound,
         CASE WHEN a.key IS NULL THEN 'added' WHEN b.key IS NULL THEN 'removed'
              WHEN sd.key IS NULL THEN 'unregistered'
              ELSE posture.change_kind(sd, a.default_value, a.bound, b.default_value, b.bound) END
  FROM (SELECT * FROM posture.profile_value v WHERE v.profile_id = a_id AND v.version = a_version) a
  FULL JOIN (SELECT * FROM posture.profile_value v WHERE v.profile_id = b_id AND v.version = b_version) b ON b.key = a.key
  LEFT JOIN posture.setting_def sd ON sd.key = coalesce(a.key, b.key)
  ORDER BY 1;
END $$;

-- How (b_default, b_bound) relates to (a_default, a_bound).
CREATE FUNCTION posture.change_kind(d posture.setting_def, a_def jsonb, a_bound jsonb, b_def jsonb, b_bound jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN posture.compare(d, b_def, a_def) = 0 AND posture.compare(d, b_bound, a_bound) = 0 THEN 'unchanged'
    WHEN posture.compare(d, b_def, a_def) >= 0 AND posture.compare(d, b_bound, a_bound) >= 0 THEN 'tighten'
    WHEN posture.compare(d, b_def, a_def) <= 0 AND posture.compare(d, b_bound, a_bound) <= 0 THEN 'loosen'
    ELSE 'mixed' END;
$$;

-- AC-15: what moving each profile derived from base_id to new_base_version
-- would do, per key ('pinned', 'proposed', 'unchanged', 'added').
CREATE FUNCTION posture.base_update_effects(base_id text, new_base_version text)
RETURNS TABLE (profile_id text, version text, key text, current_default jsonb, current_bound jsonb,
               base_default jsonb, base_bound jsonb, action text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  reader uuid := posture.profile_reader();
BEGIN
  IF NOT EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = base_id AND x.version = new_base_version AND x.kind = 'builtin') THEN
    RAISE EXCEPTION 'base profile % % is not loaded', base_id, new_base_version USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY
  SELECT p.id, p.version, n.key, c.default_value, c.bound, n.default_value, n.bound,
         CASE WHEN c.key IS NULL THEN 'added'
              WHEN sd.key IS NULL THEN CASE WHEN c.default_value = n.default_value AND c.bound = n.bound THEN 'unchanged' ELSE 'pinned' END
              ELSE CASE posture.change_kind(sd, c.default_value, c.bound, n.default_value, n.bound)
                     WHEN 'unchanged' THEN 'unchanged' WHEN 'tighten' THEN 'proposed' ELSE 'pinned' END END
  FROM posture.profile p
  JOIN posture.profile_value n ON n.profile_id = base_id AND n.version = new_base_version
  LEFT JOIN posture.profile_value c ON c.profile_id = p.id AND c.version = p.version AND c.key = n.key
  LEFT JOIN posture.setting_def sd ON sd.key = n.key
  WHERE p.kind = 'custom' AND p.base_profile_id = base_id AND p.base_version <> new_base_version
    AND p.status IN ('approved', 'active')  -- the versions in use
  ORDER BY p.id, p.version, n.key;
END $$;

-- AC-15: a new draft version of a custom profile on new_base_version.
-- Pinned keys keep their values; proposed keys keep theirs too and stay
-- loosened (needing a justification) until the proposal is adopted.
CREATE FUNCTION posture.rebase_custom_profile(pid text, from_version text, new_base_version text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
  p     posture.profile;
  nv    text;
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = from_version AND x.kind = 'custom';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom profile % % does not exist', pid, from_version USING ERRCODE = 'PF003';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = p.base_profile_id AND x.version = new_base_version AND x.kind = 'builtin') THEN
    RAISE EXCEPTION 'base profile % % is not loaded', p.base_profile_id, new_base_version USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = pid AND x.status = 'draft') THEN
    RAISE EXCEPTION 'custom profile % already has a draft version', pid USING ERRCODE = 'PF003';
  END IF;
  nv := (SELECT (max(x.version::integer) + 1)::text FROM posture.profile x WHERE x.id = pid);
  INSERT INTO posture.profile (id, version, name, family, kind, base_profile_id, base_version, status, created_by)
  VALUES (pid, nv, p.name, p.family, 'custom', p.base_profile_id, new_base_version, 'draft', actor);
  -- Every key of the new base: the custom value where there is one (pinned
  -- or proposed), the base value for keys new in the base.
  INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound, justification, loosened, needs_review)
  SELECT pid, nv, x.key, x.def, x.bnd, CASE WHEN x.loose THEN x.just END, x.loose,
         x.loose AND btrim(coalesce(x.just, '')) = ''
  FROM (
    SELECT n.key, coalesce(c.default_value, n.default_value) AS def, coalesce(c.bound, n.bound) AS bnd, c.justification AS just,
           (c.key IS NOT NULL AND sd.key IS NOT NULL
             AND posture.change_kind(sd, n.default_value, n.bound, c.default_value, c.bound) IN ('loosen', 'mixed')) AS loose
    FROM posture.profile_value n
    LEFT JOIN posture.profile_value c ON c.profile_id = pid AND c.version = from_version AND c.key = n.key
    LEFT JOIN posture.setting_def sd ON sd.key = n.key
    WHERE n.profile_id = p.base_profile_id AND n.version = new_base_version) x;
  UPDATE posture.profile x SET label_deviates = EXISTS (
    SELECT 1 FROM posture.profile_value v WHERE v.profile_id = pid AND v.version = nv AND v.loosened)
  WHERE x.id = pid AND x.version = nv;
  RETURN nv;
END $$;

-- Metadata for export and display.
CREATE FUNCTION posture.profile_meta(pid text, ver text,
  OUT name text, OUT family text, OUT kind text, OUT base_profile_id text, OUT base_version text, OUT status text,
  OUT label_deviates boolean, OUT base_name text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  reader uuid := posture.profile_reader();
BEGIN
  SELECT p.name, p.family, p.kind, p.base_profile_id, p.base_version, p.status, p.label_deviates, b.name
  INTO name, family, kind, base_profile_id, base_version, status, label_deviates, base_name
  FROM posture.profile p LEFT JOIN posture.profile b ON b.id = p.base_profile_id AND b.version = p.base_version
  WHERE p.id = pid AND p.version = ver;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'profile % % does not exist', pid, ver USING ERRCODE = 'PF003';
  END IF;
END $$;

REVOKE ALL ON FUNCTION posture.profile_reader(), posture.new_custom_version(text, text),
  posture.profile_diff(text, text, text, text), posture.change_kind(posture.setting_def, jsonb, jsonb, jsonb, jsonb),
  posture.base_update_effects(text, text), posture.rebase_custom_profile(text, text, text), posture.profile_meta(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.new_custom_version(text, text), posture.profile_diff(text, text, text, text),
  posture.base_update_effects(text, text), posture.rebase_custom_profile(text, text, text), posture.profile_meta(text, text)
  TO app_posture, app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

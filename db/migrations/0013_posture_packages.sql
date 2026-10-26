-- F-015 T-10 (AC-05, AC-09, AC-10): profile package loading and the
-- install-time seed.
--
-- Two ways in (design §4.3, decision of 2026-10-26):
--   * posture.sync_packages: the release's own packages, embedded in the
--     binary and passed by `iam migrate` as fair_owner (the trusted release
--     path, like iam.sync_release for the permission catalog);
--   * posture.import_package: packages delivered later (AC-05 offline import,
--     AC-06 new profiles), called by the posture service after it has
--     verified the release signature and manifest; PostgreSQL cannot verify
--     ECDSA, so here the database trusts app_posture. An imported profile
--     still needs a dual-approved switch (T-21) before it takes effect.
-- Either way the database computes the digest from the exact bytes it
-- stores, loads insert-only (an existing id and version with another digest
-- is refused: packages are immutable), and re-checks every value and bound
-- against registered setting definitions and their hard floors.

CREATE FUNCTION posture.load_package(raw bytea) RETURNS text
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  dig      text := encode(authz.digest(raw, 'sha256'), 'hex');
  doc      jsonb;
  p        jsonb;
  existing text;
  k        text;
  s        jsonb;
  d        posture.setting_def;
BEGIN
  BEGIN
    doc := convert_from(raw, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'profile package is not JSON: %', SQLERRM USING ERRCODE = 'PF004';
  END;
  p := doc -> 'profile';
  IF doc ->> 'format' IS DISTINCT FROM 'fair-profile-package/v1' OR p IS NULL
     OR jsonb_typeof(doc -> 'settings') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'not a fair-profile-package/v1 package' USING ERRCODE = 'PF004';
  END IF;

  SELECT package_digest INTO existing FROM posture.profile WHERE id = p ->> 'id' AND version = p ->> 'version';
  IF FOUND THEN
    IF existing IS NOT DISTINCT FROM dig THEN
      RETURN 'unchanged';
    END IF;
    RAISE EXCEPTION 'profile % version % is already loaded with digest %; packages are immutable, so a changed package needs a new version',
      p ->> 'id', p ->> 'version', existing USING ERRCODE = 'PF003';
  END IF;

  INSERT INTO posture.profile (id, version, name, family, kind, package_digest, status)
  VALUES (p ->> 'id', p ->> 'version', p ->> 'title', p ->> 'family', 'builtin', dig, 'approved');

  FOR k, s IN SELECT e.key, e.value FROM jsonb_each(doc -> 'settings') e LOOP
    SELECT * INTO d FROM posture.setting_def WHERE key = k;
    IF FOUND THEN
      -- A registered setting: its compiled definition and floor win.
      PERFORM posture.check_value(k, s -> 'default');
      PERFORM posture.check_value(k, s -> 'bound');
      PERFORM posture.check_floor(d, p ->> 'family', s -> 'bound');
      IF posture.compare(d, s -> 'default', s -> 'bound') < 0 THEN
        RAISE EXCEPTION '%: default % is weaker than its bound %', k, s -> 'default', s -> 'bound' USING ERRCODE = 'PF004';
      END IF;
    END IF;
    INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound)
    VALUES (p ->> 'id', p ->> 'version', k, s -> 'default', s -> 'bound');
  END LOOP;
  RETURN 'imported';
END $$;

-- The release's packages (iam migrate, as fair_owner). Returns
-- {"imported": [...], "unchanged": [...]} as "id@version" strings.
CREATE FUNCTION posture.sync_packages(packages bytea[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  raw bytea;
  doc jsonb;
  imported text[] := '{}';
  unchanged text[] := '{}';
BEGIN
  FOREACH raw IN ARRAY coalesce(packages, '{}') LOOP
    doc := convert_from(raw, 'UTF8')::jsonb;
    IF posture.load_package(raw) = 'imported' THEN
      imported := imported || ((doc #>> '{profile,id}') || '@' || (doc #>> '{profile,version}'));
    ELSE
      unchanged := unchanged || ((doc #>> '{profile,id}') || '@' || (doc #>> '{profile,version}'));
    END IF;
  END LOOP;
  RETURN jsonb_build_object('imported', to_jsonb(imported), 'unchanged', to_jsonb(unchanged));
END $$;

-- A package the posture service has verified (signature and manifest pin).
CREATE FUNCTION posture.import_package(raw bytea) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT posture.load_package(raw);
$$;

-- Install-time seed (AC-09, AC-10): makes the selected built-in profile
-- active and writes every setting's instance value from it. Runs once: an
-- install that already has an active profile changes profile only through a
-- switch (T-21). version NULL selects the only loaded version of the
-- profile. Returns what was seeded, for the audit event.
CREATE FUNCTION posture.seed(profile_id text, version text DEFAULT NULL,
                             OUT seeded_version text, OUT package_digest text, OUT settings integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pr posture.profile;
  v  posture.profile_value;
  want text := seed.version;
BEGIN
  settings := 0;
  -- Concurrent seeds serialize on active_profile's singleton key: the
  -- second insert waits, then fails, and its transaction rolls back.
  IF EXISTS (SELECT 1 FROM posture.active_profile) THEN
    RAISE EXCEPTION 'posture is already seeded; change profile with a profile switch' USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.setting_value) THEN
    RAISE EXCEPTION 'setting values exist without an active profile' USING ERRCODE = 'PF003';
  END IF;
  IF want IS NULL THEN
    IF (SELECT count(*) FROM posture.profile p WHERE p.id = seed.profile_id) > 1 THEN
      RAISE EXCEPTION 'profile % has several loaded versions; name one', profile_id USING ERRCODE = 'PF003';
    END IF;
    SELECT p.version INTO want FROM posture.profile p WHERE p.id = seed.profile_id;
  END IF;
  SELECT * INTO pr FROM posture.profile p WHERE p.id = seed.profile_id AND p.version = want;
  IF NOT FOUND OR pr.kind <> 'builtin' OR pr.status <> 'approved' THEN
    RAISE EXCEPTION 'profile % version % is not a loaded built-in profile', profile_id, coalesce(want, '(any)') USING ERRCODE = 'PF003';
  END IF;

  INSERT INTO posture.active_profile (profile_id, version) VALUES (pr.id, pr.version);
  UPDATE posture.profile p SET status = 'active' WHERE p.id = pr.id AND p.version = pr.version;
  FOR v IN SELECT * FROM posture.profile_value x WHERE x.profile_id = pr.id AND x.version = pr.version ORDER BY x.key LOOP
    PERFORM posture.write_value(v.key, NULL, v.default_value, 'profile', NULL, NULL);
    settings := settings + 1;
  END LOOP;
  seeded_version := pr.version;
  package_digest := pr.package_digest;
END $$;

-- Ownership and grants.
GRANT INSERT ON posture.profile_value, posture.active_profile TO posture_definer;
GRANT INSERT, UPDATE ON posture.profile TO posture_definer;
GRANT EXECUTE ON FUNCTION authz.digest(bytea, text) TO posture_definer;

REVOKE ALL ON FUNCTION posture.load_package(bytea), posture.sync_packages(bytea[]), posture.import_package(bytea),
  posture.seed(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.import_package(bytea), posture.seed(text, text) TO app_posture;

GRANT CREATE ON SCHEMA posture TO posture_definer;
ALTER FUNCTION posture.load_package(bytea) OWNER TO posture_definer;
ALTER FUNCTION posture.sync_packages(bytea[]) OWNER TO posture_definer;
ALTER FUNCTION posture.import_package(bytea) OWNER TO posture_definer;
ALTER FUNCTION posture.seed(text, text) OWNER TO posture_definer;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

-- fair_owner (iam migrate) loads the release's packages; as in 0012, the new
-- owner grants it.
SET ROLE posture_definer;
GRANT EXECUTE ON FUNCTION posture.sync_packages(bytea[]) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- F-015 T-19 (AC-11 - AC-13; design §6.5): custom profiles.
--
-- A holder of profile.manage clones any built-in profile into a draft and
-- edits it key by key; every value is validated against the registered
-- definitions, no bound may sit below a hard floor that applies to the
-- profile's family, and each loosened key (weaker than the base) needs a
-- written justification. Submitting validates the whole profile and opens a
-- profile.approval request (F-001 approvals: a different person holding
-- profile.approve decides it); approving it marks the profile approved.
-- Activation is the profile switch (T-21). Deviations are stored as
-- loosened rows, and label_deviates drives "Deviates from <base>".
-- Actors always come from the signed database context.

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('profile.approval', 'profile.approve', 'Approve a custom security profile before it can be activated (F-015 AC-12)');

ALTER TABLE posture.profile ADD COLUMN approval_request_id uuid;
GRANT UPDATE ON posture.profile_value TO posture_definer; -- draft edits

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The signed-context user, who must hold perm at the root (profiles apply
-- to the whole instance).
CREATE FUNCTION posture.profile_actor(perm text) RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'profile changes need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, perm, NULL) THEN
    RAISE EXCEPTION '% is required', perm USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- A custom profile for editing: it must exist, be custom, and be a draft.
CREATE FUNCTION posture.draft_profile(pid text, ver text) RETURNS posture.profile
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p posture.profile;
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = ver;
  IF NOT FOUND OR p.kind <> 'custom' THEN
    RAISE EXCEPTION 'custom profile % % does not exist', pid, ver USING ERRCODE = 'PF003';
  END IF;
  IF p.status <> 'draft' THEN
    RAISE EXCEPTION 'custom profile % % is %, not a draft', pid, ver, p.status USING ERRCODE = 'PF003';
  END IF;
  RETURN p;
END $$;

-- AC-11: clone a built-in profile into a draft (version 1).
CREATE FUNCTION posture.create_custom_profile(base_id text, base_version text, new_id text, name text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
  b     posture.profile;
BEGIN
  SELECT * INTO b FROM posture.profile x WHERE x.id = create_custom_profile.base_id AND x.version = create_custom_profile.base_version;
  IF NOT FOUND OR b.kind <> 'builtin' THEN
    RAISE EXCEPTION 'base profile % % is not a built-in profile', base_id, base_version USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM posture.profile x WHERE x.id = create_custom_profile.new_id) THEN
    RAISE EXCEPTION 'a profile with id % already exists', new_id USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO posture.profile (id, version, name, family, kind, base_profile_id, base_version, status, created_by)
  VALUES (new_id, '1', name, b.family, 'custom', b.id, b.version, 'draft', actor);
  INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound)
  SELECT new_id, '1', v.key, v.default_value, v.bound FROM posture.profile_value v
  WHERE v.profile_id = b.id AND v.version = b.version;
  RETURN '1';
END $$;

-- Edits one key of a draft. Returns whether the key now deviates (is
-- loosened) from the base.
CREATE FUNCTION posture.edit_custom_value(pid text, ver text, k text, new_default jsonb, new_bound jsonb, justification text)
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
  SET default_value = new_default, bound = new_bound, loosened = loose,
      justification = CASE WHEN loose THEN btrim(edit_custom_value.justification) END
  WHERE v.profile_id = pid AND v.version = ver AND v.key = k;
  UPDATE posture.profile x SET label_deviates = EXISTS (
    SELECT 1 FROM posture.profile_value v WHERE v.profile_id = pid AND v.version = ver AND v.loosened)
  WHERE x.id = pid AND x.version = ver;
  RETURN loose;
END $$;

-- AC-13: the per-key editor and deviation view: base and new values, the
-- direction against the base, and the parameters (for the controls).
CREATE FUNCTION posture.custom_profile_view(pid text, ver text)
RETURNS TABLE (key text, type text, base_default jsonb, base_bound jsonb, default_value jsonb, bound jsonb,
               direction text, loosened boolean, justification text, params text[])
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
  p posture.profile;
BEGIN
  IF u IS NULL OR NOT (iam.holds_permission(u, 'profile.manage', NULL) OR iam.holds_permission(u, 'profile.approve', NULL)) THEN
    RAISE EXCEPTION 'profile.manage or profile.approve is required' USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = ver AND x.kind = 'custom';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom profile % % does not exist', pid, ver USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY
  SELECT v.key, sd.type, b.default_value, b.bound, v.default_value, v.bound,
         CASE WHEN sd.key IS NULL THEN 'unregistered'
              WHEN posture.compare(sd, v.bound, b.bound) < 0 OR posture.compare(sd, v.default_value, b.default_value) < 0 THEN 'loosen'
              WHEN posture.compare(sd, v.bound, b.bound) > 0 OR posture.compare(sd, v.default_value, b.default_value) > 0 THEN 'tighten'
              ELSE 'unchanged' END,
         v.loosened, v.justification, coalesce(sd.params, '{}')
  FROM posture.profile_value v
  JOIN posture.profile_value b ON b.profile_id = p.base_profile_id AND b.version = p.base_version AND b.key = v.key
  LEFT JOIN posture.setting_def sd ON sd.key = v.key
  WHERE v.profile_id = pid AND v.version = ver
  ORDER BY v.key;
END $$;

-- Problems that block submission; empty means valid.
CREATE FUNCTION posture.validate_custom_profile(pid text, ver text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p        posture.profile;
  d        posture.setting_def;
  v        posture.profile_value;
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
    IF v.loosened AND btrim(coalesce(v.justification, '')) = '' THEN
      problems := problems || (d.key || ': loosened without justification');
    END IF;
  END LOOP;
  RETURN problems;
END $$;

-- Submits a draft for approval (AC-12). Returns the approval request.
CREATE FUNCTION posture.submit_custom_profile(pid text, ver text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor    uuid := posture.profile_actor('profile.manage');
  p        posture.profile := posture.draft_profile(pid, ver);
  problems text[] := posture.validate_custom_profile(pid, ver);
  req      uuid;
BEGIN
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'custom profile % % is not valid: %', pid, ver, array_to_string(problems, '; ') USING ERRCODE = 'PF004';
  END IF;
  req := iam.request_approval('profile.approval', 'posture.profile:' || pid || '@' || ver,
    'Custom profile ' || p.name || ' (from ' || p.base_profile_id || ' ' || p.base_version || ')',
    jsonb_build_object('profile_id', pid, 'version', ver, 'base', p.base_profile_id, 'base_version', p.base_version,
                       'deviates', p.label_deviates,
                       'loosened', (SELECT coalesce(jsonb_agg(jsonb_build_object('key', v.key, 'bound', v.bound, 'justification', v.justification) ORDER BY v.key), '[]')
                                    FROM posture.profile_value v WHERE v.profile_id = pid AND v.version = ver AND v.loosened)), NULL);
  UPDATE posture.profile x SET status = 'pending_approval', approval_request_id = req WHERE x.id = pid AND x.version = ver;
  RETURN req;
END $$;

-- Once a different person has approved: approved (activation is T-21).
CREATE FUNCTION posture.approve_custom_profile(pid text, ver text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p posture.profile;
  a jsonb;
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = ver FOR UPDATE;
  IF NOT FOUND OR p.kind <> 'custom' OR p.status <> 'pending_approval' THEN
    RAISE EXCEPTION 'custom profile % % is not awaiting approval', pid, ver USING ERRCODE = 'PF003';
  END IF;
  a := iam.consume_approval(p.approval_request_id, 'profile.approval', 'posture.profile:' || pid || '@' || ver);
  IF cardinality(posture.validate_custom_profile(pid, ver)) > 0 THEN -- definitions may have changed meanwhile
    RAISE EXCEPTION 'custom profile % % is no longer valid', pid, ver USING ERRCODE = 'PF004';
  END IF;
  UPDATE posture.profile x SET status = 'approved' WHERE x.id = pid AND x.version = ver;
  RETURN (a ->> 'decided_by')::uuid;
END $$;

-- Back to draft after a rejection or to make changes; any pending approval
-- can no longer be used (its target is no longer pending).
CREATE FUNCTION posture.reopen_custom_profile(pid text, ver text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := posture.profile_actor('profile.manage');
BEGIN
  UPDATE posture.profile x SET status = 'draft', approval_request_id = NULL
  WHERE x.id = pid AND x.version = ver AND x.kind = 'custom' AND x.status = 'pending_approval';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom profile % % is not awaiting approval', pid, ver USING ERRCODE = 'PF003';
  END IF;
END $$;

REVOKE ALL ON FUNCTION posture.profile_actor(text), posture.draft_profile(text, text),
  posture.create_custom_profile(text, text, text, text), posture.edit_custom_value(text, text, text, jsonb, jsonb, text),
  posture.custom_profile_view(text, text), posture.validate_custom_profile(text, text), posture.submit_custom_profile(text, text),
  posture.approve_custom_profile(text, text), posture.reopen_custom_profile(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.create_custom_profile(text, text, text, text), posture.edit_custom_value(text, text, text, jsonb, jsonb, text),
  posture.custom_profile_view(text, text), posture.submit_custom_profile(text, text), posture.approve_custom_profile(text, text),
  posture.reopen_custom_profile(text, text) TO app_posture, app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

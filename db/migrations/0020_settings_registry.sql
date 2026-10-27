-- F-015 T-16 (design §12): the posture registry replaces the F-001 T-00b
-- settings stand-in.
--
-- Decision (Robert Former, 2026-10-27): settings.Set is served by the change
-- evaluator embedded in each service, connecting as app_rw. The database
-- already enforces every rule on the caller's signed context (requester and
-- settings.change, floors, bounds, approvals, the SecOps queue), so the
-- evaluator's functions are granted to app_rw as well as app_posture.
--
-- Porting the stand-in's F-001 tests found a gap in T-14: AC-22 says a
-- tightening takes effect at once with no approval, but a tightening that is
-- still outside the bound (an approved exception at 60m tightened to 45m)
-- was sent back to approval. Now:
--   * a tightening still out of bounds, while an active exception covers
--     the value in force, applies under that exception (its value follows);
--   * a change back within the bound supersedes the covering exception
--     (new exception state 'superseded').

ALTER TABLE posture.exception DROP CONSTRAINT exception_state_check;
ALTER TABLE posture.exception ADD CONSTRAINT exception_state_check
  CHECK (state IN ('active', 'renewed', 'expired', 'reverted', 'revert_failed', 'superseded'));

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The active, unexpired exception whose value is in force for (k, bu).
CREATE FUNCTION posture.covering_exception(k text, bu uuid) RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.id FROM posture.setting_value s
  JOIN posture.exception e ON e.id = s.exception_id
  WHERE s.key = k AND s.bu_id IS NOT DISTINCT FROM bu AND s.source = 'exception'
    AND e.state = 'active' AND e.expires_at > now();
$$;

DROP FUNCTION posture.preview_change(text, uuid, jsonb);
CREATE FUNCTION posture.preview_change(k text, bu uuid, new_value jsonb,
  OUT direction text, OUT below_floor boolean, OUT out_of_bounds boolean, OUT current_value jsonb,
  OUT bound jsonb, OUT hard_floor jsonb, OUT params text[], OUT covered boolean)
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
END $$;

CREATE OR REPLACE FUNCTION posture.request_change(k text, bu uuid, new_value jsonb, explanation text,
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
    approval_request_id := iam.request_approval('settings.out_of_bounds', 'posture.change:' || change_id, explanation,
      jsonb_build_object('key', k, 'bu_id', bu, 'value', new_value, 'current', p.current_value, 'bound', p.bound, 'params', p.params), bu);
    state := 'pending_approval';
  ELSE
    state := 'requested';
  END IF;
  INSERT INTO posture.change (id, key, bu_id, old_value, new_value, direction, explanation, requested_by, approval_request_id, state)
  VALUES (change_id, k, bu, p.current_value, new_value, direction, nullif(btrim(coalesce(explanation, '')), ''), actor,
          approval_request_id, state);
END $$;

CREATE OR REPLACE FUNCTION posture.apply_change(change_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c   posture.change;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  ttl jsonb;
  cur jsonb;
  cov uuid;
  exc uuid;
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
  ELSE
    a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds', 'posture.change:' || c.id);
    ttl := posture.current_value('exception.max_duration', NULL);
    INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
    VALUES (c.key, c.bu_id, c.new_value, b.bound, c.explanation, c.requested_by, (a ->> 'decided_by')::uuid,
            now() + make_interval(secs => posture.duration_ns(ttl #>> '{}') / 1e9), 'active')
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

REVOKE ALL ON FUNCTION posture.covering_exception(text, uuid), posture.preview_change(text, uuid, jsonb) FROM PUBLIC;
-- The evaluator's entry points, for every service's embedded settings.Set.
GRANT EXECUTE ON FUNCTION posture.preview_change(text, uuid, jsonb) TO app_posture, app_rw;
GRANT EXECUTE ON FUNCTION posture.request_change(text, uuid, jsonb, text), posture.apply_change(uuid),
  posture.change_summary(uuid), posture.exception_summary(uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

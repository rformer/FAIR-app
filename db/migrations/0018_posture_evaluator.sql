-- F-015 T-14 (AC-20 - AC-22, AC-30, AC-31; design §6.2): the change
-- evaluator's database side, wired to the F-001 approvals engine (T-26).
--
--   * The requester is the signed-context user (ADR-007), never a parameter
--     (deferred from T-09), and must hold settings.change at the BU (the root
--     for instance-wide changes).
--   * request_change classifies the change. Out of bounds, it needs a written
--     explanation and opens a settings.out_of_bounds approval request for the
--     same user, in the same transaction.
--   * apply_change applies a requested change, or, for an approved one,
--     consumes the approval once and applies the value as an exception
--     (AC-21) that expires after the exception.max_duration value in force
--     (90 days by default; AC-24). The hard floor is re-checked: no exception
--     may weaken it (AC-30).
--   * preview_change lets the service show the warning (bound, parameters)
--     before anything is written.
-- New SQLSTATEs: PF007 no valid signed context; PF008 not permitted.

-- The approvals engine returns who requested and decided, so the exception
-- can record its approver. Nothing consumed approvals before this task.
CREATE OR REPLACE FUNCTION iam.consume_approval(request_id uuid, kind text, target_ref text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.approval_request;
BEGIN
  SELECT * INTO r FROM iam.approval_request a WHERE a.id = request_id FOR UPDATE;
  IF NOT FOUND OR r.kind IS DISTINCT FROM consume_approval.kind OR r.target_ref IS DISTINCT FROM consume_approval.target_ref THEN
    RAISE EXCEPTION 'no approval % for % %', request_id, kind, target_ref USING ERRCODE = 'AP004';
  END IF;
  IF r.status <> 'approved' OR r.consumed_at IS NOT NULL OR now() >= r.expires_at THEN
    RAISE EXCEPTION 'approval % is not usable (status %, consumed %, expires %)', request_id, r.status, r.consumed_at, r.expires_at
      USING ERRCODE = 'AP004';
  END IF;
  UPDATE iam.approval_request a SET consumed_at = now() WHERE a.id = r.id RETURNING a.* INTO r;
  PERFORM iam.approval_audit('approval.consumed', 'info', r.decided_by, r);
  RETURN jsonb_build_object('payload', r.payload, 'requested_by', r.requested_by, 'decided_by', r.decided_by);
END $$;

-- Whether u holds perm at bu (NULL = root): the effective-access rule, for
-- other features' definer roles, which cannot read iam's tables.
CREATE FUNCTION iam.holds_permission(u uuid, perm text, bu uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(u, perm, coalesce(bu, (SELECT id FROM iam.bu WHERE parent_id IS NULL)));
$$;
REVOKE ALL ON FUNCTION iam.holds_permission(uuid, text, uuid) FROM PUBLIC;

-- posture_definer acts for the signed-context user and uses the approvals
-- engine; it reads nothing in iam directly.
GRANT USAGE ON SCHEMA iam TO posture_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid), iam.request_approval(text, text, text, jsonb, uuid),
  iam.consume_approval(uuid, text, text) TO posture_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope() TO posture_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The signed-context user, who must hold settings.change at bu (NULL = root).
CREATE FUNCTION posture.change_actor(bu uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'setting changes need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'settings.change', bu) THEN
    RAISE EXCEPTION 'settings.change is required here' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- What a change would be, without writing anything.
CREATE FUNCTION posture.preview_change(k text, bu uuid, new_value jsonb,
  OUT direction text, OUT below_floor boolean, OUT out_of_bounds boolean, OUT current_value jsonb,
  OUT bound jsonb, OUT hard_floor jsonb, OUT params text[])
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
END $$;

DROP FUNCTION posture.request_change(text, uuid, jsonb, text, uuid, uuid);

-- Records a change as the signed-context user. Below the floor: PF001.
-- Out of bounds: an explanation is required (PF002) and a
-- settings.out_of_bounds approval request is opened (state
-- pending_approval). Otherwise the change is 'requested', ready for
-- apply_change in the same transaction.
CREATE FUNCTION posture.request_change(k text, bu uuid, new_value jsonb, explanation text,
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
  IF p.out_of_bounds THEN
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

DROP FUNCTION posture.apply_change(uuid);

-- Applies a recorded change and returns the exception it created, if any.
-- 'requested': re-evaluated against the state now, then written.
-- 'pending_approval': the approval is consumed (once, for exactly this
-- change), the floor re-checked, and the value applied as an exception.
CREATE FUNCTION posture.apply_change(change_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c   posture.change;
  d   posture.setting_def;
  b   record;
  a   jsonb;
  ttl jsonb;
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

  IF c.state = 'requested' THEN
    IF posture.compare(d, c.new_value, b.bound) < 0 THEN
      RAISE EXCEPTION 'change % is now outside the active profile bound %; request it again', change_id, b.bound USING ERRCODE = 'PF002';
    END IF;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'change', c.id, NULL);
  ELSE
    a := iam.consume_approval(c.approval_request_id, 'settings.out_of_bounds', 'posture.change:' || c.id);
    ttl := posture.current_value('exception.max_duration', NULL);
    INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
    VALUES (c.key, c.bu_id, c.new_value, b.bound, c.explanation, c.requested_by, (a ->> 'decided_by')::uuid,
            now() + make_interval(secs => posture.duration_ns(ttl #>> '{}') / 1e9), 'active')
    RETURNING e.id INTO exc;
    PERFORM posture.write_value(c.key, c.bu_id, c.new_value, 'exception', NULL, exc);
  END IF;
  UPDATE posture.change x SET state = 'applied', applied_at = now() WHERE x.id = c.id;
  RETURN exc;
END $$;

-- What the service needs to audit and announce a change or an exception.
CREATE FUNCTION posture.change_summary(change_id uuid,
  OUT key text, OUT bu_id uuid, OUT new_value jsonb, OUT direction text, OUT state text, OUT requested_by uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.key, c.bu_id, c.new_value, c.direction, c.state, c.requested_by
  FROM posture.change c WHERE c.id = change_summary.change_id;
$$;
CREATE FUNCTION posture.exception_summary(exception_id uuid,
  OUT key text, OUT bu_id uuid, OUT value jsonb, OUT owner_id uuid, OUT approved_by uuid, OUT expires_at timestamptz, OUT state text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.key, e.bu_id, e.value, e.owner_id, e.approved_by, e.expires_at, e.state
  FROM posture.exception e WHERE e.id = exception_summary.exception_id;
$$;

REVOKE ALL ON FUNCTION posture.change_actor(uuid), posture.preview_change(text, uuid, jsonb),
  posture.request_change(text, uuid, jsonb, text), posture.apply_change(uuid), posture.change_summary(uuid),
  posture.exception_summary(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.preview_change(text, uuid, jsonb), posture.request_change(text, uuid, jsonb, text),
  posture.apply_change(uuid), posture.change_summary(uuid), posture.exception_summary(uuid) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
GRANT INSERT ON posture.exception TO posture_definer;

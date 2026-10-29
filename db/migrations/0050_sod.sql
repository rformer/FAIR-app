-- F-001 T-27 (AC-29, AC-53; design §3 sod_rule, sod_exception, §6
-- /sod-rules, /sod-exceptions, /approvals): separation of duties.
--
--   * iam.sod_rule: conflicting permission pairs. The built-in rule pairs
--     analysis.edit with acceptance.approve (an analysis author cannot approve
--     an acceptance relying on it; F-008 enforces it per record); built-in
--     rules cannot be disabled. sod.manage adds rules and enables or disables
--     them, audited high; enabling (or adding) a rule that a custom role
--     already breaks is refused, listing the roles.
--   * A custom role version containing both permissions of an enabled rule
--     is refused (AC-53) unless the role holds a live exception for that rule.
--     Built-in roles are exempt (they come from the release catalog).
--   * iam.sod_exception: per role and rule, with a reason and an expiry (at
--     most a year), created only by consuming an approved sod.exception
--     request (T-26: the approver holds sod.manage and is not the requester).
--   * Expiry (the scope worker, hourly) and revocation re-check the role: a
--     custom role whose current version still breaks an enabled rule without
--     an exception is suspended (it grants nothing; audited high). Saving a
--     clean version, or a new exception, makes it active again.
--   * iam.approval_list: the approval requests the caller made or may decide
--     (for /api/v1/approvals).

CREATE TABLE iam.sod_rule (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Catalog keys (checked when a rule is added; the catalog itself is
  -- loaded after the migrations, by iam.sync_release).
  permission_a  text        NOT NULL CHECK (permission_a ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
  permission_b  text        NOT NULL CHECK (permission_b ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
  description   text        NOT NULL CHECK (btrim(description) <> ''),
  enabled       boolean     NOT NULL DEFAULT true,
  builtin       boolean     NOT NULL DEFAULT false,
  created_by    uuid        REFERENCES iam.app_user (id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CHECK (permission_a < permission_b),   -- one canonical order per pair
  CHECK (NOT builtin OR enabled),
  UNIQUE (permission_a, permission_b)
);
REVOKE ALL ON iam.sod_rule FROM PUBLIC;
INSERT INTO iam.sod_rule (permission_a, permission_b, description, builtin)
VALUES ('acceptance.approve', 'analysis.edit',
        'An analysis author cannot approve a risk acceptance that relies on that analysis (enforced per record in F-008)', true);

CREATE TABLE iam.sod_exception (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id       uuid        NOT NULL REFERENCES iam.role (id),
  rule_id       uuid        NOT NULL REFERENCES iam.sod_rule (id),
  reason        text        NOT NULL CHECK (btrim(reason) <> ''),
  requested_by  uuid        NOT NULL REFERENCES iam.app_user (id),
  approved_by   uuid        NOT NULL REFERENCES iam.app_user (id),
  approval_id   uuid        NOT NULL UNIQUE REFERENCES iam.approval_request (id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  ended_at      timestamptz,
  ended_reason  text CHECK (ended_reason IN ('expired', 'revoked')),
  ended_by      uuid        REFERENCES iam.app_user (id),
  CHECK (approved_by <> requested_by),
  CHECK (expires_at > created_at),
  CHECK ((ended_at IS NULL) = (ended_reason IS NULL))
);
CREATE INDEX sod_exception_live ON iam.sod_exception (role_id, rule_id) WHERE ended_at IS NULL;
REVOKE ALL ON iam.sod_exception FROM PUBLIC;

-- The enabled rules perms breaks without a live exception for role.
CREATE FUNCTION iam.sod_violations(role uuid, perms text[])
RETURNS TABLE (rule_id uuid, permission_a text, permission_b text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.id, r.permission_a, r.permission_b FROM iam.sod_rule r
  WHERE r.enabled AND r.permission_a = ANY (perms) AND r.permission_b = ANY (perms)
    AND NOT EXISTS (SELECT 1 FROM iam.sod_exception x WHERE x.role_id = role AND x.rule_id = r.id
                    AND x.ended_at IS NULL AND x.expires_at > now())
  ORDER BY r.permission_a, r.permission_b;
$$;

CREATE FUNCTION iam.role_permissions(role uuid) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT v.permissions FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version WHERE r.id = role;
$$;

CREATE FUNCTION iam.sod_event(event text, actor text, target text, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor, 'target', target, 'reason', reason,
                                      'attributes', coalesce(attrs, '{}')));
$$;

-- Suspends a custom role whose current version breaks a rule without an
-- exception, and reactivates a suspended one that no longer does.
CREATE FUNCTION iam.role_sod_enforce(role uuid, actor text, why text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r      iam.role;
  broken jsonb;
BEGIN
  SELECT * INTO r FROM iam.role x WHERE x.id = role FOR UPDATE;
  IF NOT FOUND OR r.builtin OR r.status = 'retired' OR r.current_version = 0 THEN
    RETURN coalesce(r.status::text, 'none');
  END IF;
  SELECT jsonb_agg(jsonb_build_array(v.permission_a, v.permission_b)) INTO broken
  FROM iam.sod_violations(role, iam.role_permissions(role)) v;
  IF broken IS NOT NULL AND r.status = 'active' THEN
    UPDATE iam.role x SET status = 'suspended' WHERE x.id = role;
    PERFORM iam.sod_event('role.suspended', actor, 'role:' || role, why, jsonb_build_object('name', r.name, 'conflicts', broken));
    RETURN 'suspended';
  END IF;
  IF broken IS NULL AND r.status = 'suspended' THEN
    UPDATE iam.role x SET status = 'active' WHERE x.id = role;
    PERFORM iam.sod_event('role.reactivated', actor, 'role:' || role, why, jsonb_build_object('name', r.name));
    RETURN 'active';
  END IF;
  RETURN r.status::text;
END $$;

-- AC-53: a custom role version may not combine a rule's permissions without
-- a live exception (runs after role_version_before_insert normalizes).
CREATE FUNCTION iam.role_version_sod() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v record;
BEGIN
  IF (SELECT r.builtin FROM iam.role r WHERE r.id = NEW.role_id) THEN
    RETURN NEW;
  END IF;
  SELECT * INTO v FROM iam.sod_violations(NEW.role_id, NEW.permissions) LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION 'separation of duties: % and % may not be in one role without an approved exception (AC-53)',
      v.permission_a, v.permission_b USING ERRCODE = 'PF003';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER role_version_sod BEFORE INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.role_version_sod();

-- A clean version reactivates a suspended role.
CREATE FUNCTION iam.role_version_sod_after() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (SELECT r.status FROM iam.role r WHERE r.id = NEW.role_id) = 'suspended' THEN
    PERFORM iam.role_sod_enforce(NEW.role_id, coalesce(NEW.changed_by::text, 'system:iam'), 'a version without the conflict');
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER role_version_sod_after AFTER INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.role_version_sod_after();

-- Expired exceptions end; their roles are re-checked (the scope worker).
CREATE FUNCTION iam.sod_exception_sweep() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  x iam.sod_exception;
  n integer := 0;
BEGIN
  FOR x IN UPDATE iam.sod_exception e SET ended_at = now(), ended_reason = 'expired'
           WHERE e.ended_at IS NULL AND e.expires_at <= now() RETURNING * LOOP
    PERFORM iam.sod_event('sod.exception_expired', 'system:iam', 'sod_exception:' || x.id, NULL,
      jsonb_build_object('role', x.role_id, 'rule', x.rule_id));
    IF iam.role_sod_enforce(x.role_id, 'system:iam', 'separation-of-duties exception expired') = 'suspended' THEN
      n := n + 1;
    END IF;
  END LOOP;
  RETURN n;
END $$;

-- The API (signed context) ------------------------------------------------

CREATE FUNCTION iam.sod_actor(perm text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'separation of duties needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF perm IS NOT NULL AND NOT iam.holds_permission(u, perm, NULL) THEN
    RAISE EXCEPTION '% is required', perm USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- Custom roles (active or suspended) that rule a/b would break now.
CREATE FUNCTION iam.sod_rule_breakers(a text, b text, rule uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT string_agg(r.name, ', ' ORDER BY r.name) FROM iam.role r
  WHERE NOT r.builtin AND r.status IN ('active', 'suspended') AND r.current_version > 0
    AND a = ANY (iam.role_permissions(r.id)) AND b = ANY (iam.role_permissions(r.id))
    AND NOT EXISTS (SELECT 1 FROM iam.sod_exception x WHERE x.role_id = r.id AND x.rule_id = rule
                    AND x.ended_at IS NULL AND x.expires_at > now());
$$;

CREATE FUNCTION iam.sod_rule_create(pa text, pb text, description text, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sod_actor('sod.manage');
  a     text := least(pa, pb);
  b     text := greatest(pa, pb);
  roles text;
  r     iam.sod_rule;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF a = b OR NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = a) OR NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = b) THEN
    RAISE EXCEPTION 'a rule pairs two different catalog permissions' USING ERRCODE = 'PF004';
  END IF;
  roles := iam.sod_rule_breakers(a, b, NULL);
  IF roles IS NOT NULL THEN
    RAISE EXCEPTION 'custom roles already combine % and %: %; change them or approve exceptions first', a, b, roles USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.sod_rule (permission_a, permission_b, description, created_by) VALUES (a, b, btrim(description), actor) RETURNING * INTO r;
  PERFORM iam.sod_event('sod.rule_created', actor::text, 'sod_rule:' || r.id, btrim(reason),
    jsonb_build_object('permission_a', a, 'permission_b', b, 'description', r.description));
  RETURN r.id;
END $$;

CREATE FUNCTION iam.sod_rule_set_enabled(rule uuid, on_off boolean, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sod_actor('sod.manage');
  r     iam.sod_rule;
  roles text;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO r FROM iam.sod_rule x WHERE x.id = rule FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no rule %', rule USING ERRCODE = 'P0002';
  END IF;
  IF r.builtin AND NOT on_off THEN
    RAISE EXCEPTION 'the built-in rule cannot be disabled' USING ERRCODE = 'PF003';
  END IF;
  IF on_off AND NOT r.enabled THEN
    roles := iam.sod_rule_breakers(r.permission_a, r.permission_b, r.id);
    IF roles IS NOT NULL THEN
      RAISE EXCEPTION 'custom roles combine % and %: %; change them or approve exceptions first', r.permission_a, r.permission_b, roles
        USING ERRCODE = 'PF003';
    END IF;
  END IF;
  IF r.enabled = on_off THEN
    RETURN;
  END IF;
  UPDATE iam.sod_rule x SET enabled = on_off, updated_at = now() WHERE x.id = rule;
  PERFORM iam.sod_event(CASE WHEN on_off THEN 'sod.rule_enabled' ELSE 'sod.rule_disabled' END, actor::text, 'sod_rule:' || rule,
    btrim(reason), jsonb_build_object('permission_a', r.permission_a, 'permission_b', r.permission_b));
  IF NOT on_off THEN
    -- Roles suspended only for this rule work again.
    PERFORM iam.role_sod_enforce(x.id, actor::text, 'rule disabled') FROM iam.role x WHERE x.status = 'suspended';
  END IF;
END $$;

-- Asks for an exception (role.manage; the approver needs sod.manage, T-26).
CREATE FUNCTION iam.sod_exception_request(role uuid, rule uuid, expires timestamptz, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sod_actor('role.manage');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.role r WHERE r.id = role AND NOT r.builtin AND r.status <> 'retired') THEN
    RAISE EXCEPTION 'no custom role %', role USING ERRCODE = 'P0002';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.sod_rule r WHERE r.id = rule AND r.enabled) THEN
    RAISE EXCEPTION 'no enabled rule %', rule USING ERRCODE = 'P0002';
  END IF;
  IF expires IS NULL OR expires <= now() OR expires > now() + interval '366 days' THEN
    RAISE EXCEPTION 'an exception expires within a year' USING ERRCODE = 'PF004';
  END IF;
  RETURN iam.request_approval('sod.exception', 'role:' || role || ':rule:' || rule, reason,
    jsonb_build_object('role_id', role, 'rule_id', rule, 'expires_at', expires), NULL);
END $$;

-- Turns an approved request into the exception (role.manage).
CREATE FUNCTION iam.sod_exception_apply(approval uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor   uuid := iam.sod_actor('role.manage');
  req     iam.approval_request;
  used    jsonb;
  granted jsonb;
  x       iam.sod_exception;
BEGIN
  SELECT * INTO req FROM iam.approval_request a WHERE a.id = approval AND a.kind = 'sod.exception';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no separation-of-duties request %', approval USING ERRCODE = 'P0002';
  END IF;
  -- {payload, requested_by, decided_by} (0018's contract).
  used := iam.consume_approval(approval, 'sod.exception', req.target_ref);
  granted := used->'payload';
  IF granted IS NULL OR granted->>'role_id' IS NULL OR granted->>'rule_id' IS NULL OR granted->>'expires_at' IS NULL THEN
    RAISE EXCEPTION 'the approved request % carries no exception (payload %)', approval, granted USING ERRCODE = 'PF004';
  END IF;
  IF (granted->>'expires_at')::timestamptz <= now() THEN
    RAISE EXCEPTION 'the approved expiry has passed; request again' USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.sod_exception (role_id, rule_id, reason, requested_by, approved_by, approval_id, expires_at)
  VALUES ((granted->>'role_id')::uuid, (granted->>'rule_id')::uuid, req.reason, (used->>'requested_by')::uuid, (used->>'decided_by')::uuid, approval,
          (granted->>'expires_at')::timestamptz) RETURNING * INTO x;
  PERFORM iam.sod_event('sod.exception_granted', actor::text, 'sod_exception:' || x.id, x.reason,
    jsonb_build_object('role', x.role_id, 'rule', x.rule_id, 'requested_by', x.requested_by, 'approved_by', x.approved_by,
                       'expires_at', x.expires_at));
  PERFORM iam.role_sod_enforce(x.role_id, actor::text, 'separation-of-duties exception granted');
  RETURN x.id;
END $$;

CREATE FUNCTION iam.sod_exception_revoke(exception uuid, reason text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sod_actor('sod.manage');
  x     iam.sod_exception;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  UPDATE iam.sod_exception e SET ended_at = now(), ended_reason = 'revoked', ended_by = actor
  WHERE e.id = exception AND e.ended_at IS NULL RETURNING * INTO x;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no live exception %', exception USING ERRCODE = 'P0002';
  END IF;
  PERFORM iam.sod_event('sod.exception_revoked', actor::text, 'sod_exception:' || x.id, btrim(reason),
    jsonb_build_object('role', x.role_id, 'rule', x.rule_id));
  RETURN iam.role_sod_enforce(x.role_id, actor::text, 'separation-of-duties exception revoked');
END $$;

CREATE FUNCTION iam.sod_rule_list()
RETURNS TABLE (id uuid, permission_a text, permission_b text, description text, enabled boolean, builtin boolean,
               created_at timestamptz, updated_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.sod_actor(NULL);
  RETURN QUERY SELECT r.id, r.permission_a, r.permission_b, r.description, r.enabled, r.builtin, r.created_at, r.updated_at
  FROM iam.sod_rule r ORDER BY r.builtin DESC, r.permission_a, r.permission_b;
END $$;

CREATE FUNCTION iam.sod_exception_list()
RETURNS TABLE (id uuid, role_id uuid, role_name text, role_status text, rule_id uuid, permission_a text, permission_b text, reason text,
               requested_by uuid, approved_by uuid, created_at timestamptz, expires_at timestamptz, ended_at timestamptz,
               ended_reason text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.sod_actor(NULL);
  RETURN QUERY SELECT x.id, x.role_id, r.name, r.status::text, x.rule_id, s.permission_a, s.permission_b, x.reason, x.requested_by,
    x.approved_by, x.created_at, x.expires_at, x.ended_at, x.ended_reason
  FROM iam.sod_exception x JOIN iam.role r ON r.id = x.role_id JOIN iam.sod_rule s ON s.id = x.rule_id
  ORDER BY (x.ended_at IS NULL) DESC, x.expires_at, x.id;
END $$;

-- Approval requests the caller made or may decide, newest first.
CREATE FUNCTION iam.approval_list(only_pending boolean) RETURNS SETOF iam.approval_request
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.* FROM iam.approval_request a
  WHERE (a.requested_by = iam.approval_actor() OR iam.may_approve(iam.approval_actor(), a.kind, a.bu_id))
    AND (NOT only_pending OR (a.status = 'pending' AND a.expires_at > now()))
  ORDER BY a.created_at DESC, a.id
  LIMIT 500;
$$;

REVOKE ALL ON FUNCTION iam.sod_violations(uuid, text[]), iam.role_permissions(uuid), iam.sod_event(text, text, text, text, jsonb),
  iam.role_sod_enforce(uuid, text, text), iam.role_version_sod(), iam.role_version_sod_after(), iam.sod_exception_sweep(),
  iam.sod_actor(text), iam.sod_rule_breakers(text, text, uuid), iam.sod_rule_create(text, text, text, text),
  iam.sod_rule_set_enabled(uuid, boolean, text), iam.sod_exception_request(uuid, uuid, timestamptz, text),
  iam.sod_exception_apply(uuid), iam.sod_exception_revoke(uuid, text), iam.sod_rule_list(), iam.sod_exception_list(),
  iam.approval_list(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.sod_exception_sweep(), iam.sod_rule_create(text, text, text, text),
  iam.sod_rule_set_enabled(uuid, boolean, text), iam.sod_exception_request(uuid, uuid, timestamptz, text),
  iam.sod_exception_apply(uuid), iam.sod_exception_revoke(uuid, text), iam.sod_rule_list(), iam.sod_exception_list(),
  iam.approval_list(boolean) TO app_rw;

-- F-001 T-24 (AC-12, AC-13, AC-14; design §3 assignment.source and
-- mapping_id, §6 /group-mappings): group-to-role mappings.
--
--   * iam.group_role_mapping: a group (SCIM-provisioned) mapped to a role at
--     a BU, created and removed through the iam API with access.map_groups
--     at that BU (and at the root for roles with admin permissions: AC-22),
--     audited high.
--   * Each active member of a mapped group holds one assignment per mapping,
--     source mapped with its mapping_id (AC-14). Joining the group, leaving
--     it, the user's deactivation or reactivation, the mapping's creation or
--     removal, and the group's deletion all reconcile the member's mapped
--     assignments in the same transaction (AC-13), each audited.
--   * A member for whom a mapped grant would break a rule (AC-28: the
--     mapping's creator; AC-30: admin with risk-data permissions; an
--     inactive user) is skipped: no assignment, a high-severity audit event,
--     and an entry in iam.group_mapping_skip until resolved. Membership
--     changes never fail because of one member.
--   * Mapped assignments are written and revoked only by these functions
--     (the insert and revocation triggers check it).

CREATE TABLE iam.group_role_mapping (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  grp_id      uuid        NOT NULL REFERENCES iam.grp (id),
  role_id     uuid        NOT NULL REFERENCES iam.role (id),
  bu_id       uuid        NOT NULL REFERENCES iam.bu (id),
  reason      text        NOT NULL CHECK (btrim(reason) <> ''),
  created_by  uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  removed_at  timestamptz,
  removed_by  uuid        REFERENCES iam.app_user (id)
);
CREATE UNIQUE INDEX group_role_mapping_live ON iam.group_role_mapping (grp_id, role_id, bu_id) WHERE removed_at IS NULL;
REVOKE ALL ON iam.group_role_mapping FROM PUBLIC;

ALTER TABLE iam.assignment ADD CONSTRAINT assignment_mapping_fk FOREIGN KEY (mapping_id) REFERENCES iam.group_role_mapping (id);
CREATE UNIQUE INDEX assignment_mapped_live ON iam.assignment (mapping_id, principal_id) WHERE source = 'mapped' AND revoked_at IS NULL;

CREATE TABLE iam.group_mapping_skip (
  mapping_id  uuid        NOT NULL REFERENCES iam.group_role_mapping (id),
  user_id     uuid        NOT NULL REFERENCES iam.app_user (id),
  reason      text        NOT NULL,
  at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (mapping_id, user_id)
);
REVOKE ALL ON iam.group_mapping_skip FROM PUBLIC;

-- Set by the mapping functions for their own writes (as the bootstrap flag).
CREATE FUNCTION iam.in_mapping_sync() RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT current_user = 'fair_owner' AND coalesce(current_setting('iam.mapping_sync', true), '') = 'on';
$$;

-- The assignment triggers (0005), now with the mapped path.
CREATE OR REPLACE FUNCTION iam.assignment_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.role;
  perms text[];
  b iam.bu;
  u uuid;
  m iam.group_role_mapping;
BEGIN
  -- Serialize assignment writes so the AC-30 check sees every concurrent grant.
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  NEW.granted_at := now();
  NEW.revoked_at := NULL;
  NEW.revoked_by := NULL;

  IF NEW.source = 'mapped' THEN
    -- Only the mapping functions write mapped assignments, for an active
    -- member of a live mapping's group, matching the mapping.
    IF NOT iam.in_mapping_sync() THEN
      RAISE EXCEPTION 'assignment: mapped assignments are written by group mappings only' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO m FROM iam.group_role_mapping x WHERE x.id = NEW.mapping_id AND x.removed_at IS NULL;
    IF NOT FOUND OR NEW.principal_kind <> 'user' OR NEW.role_id <> m.role_id OR NEW.bu_id <> m.bu_id
       OR NOT EXISTS (SELECT 1 FROM iam.grp_member gm WHERE gm.grp_id = m.grp_id AND gm.user_id = NEW.principal_id) THEN
      RAISE EXCEPTION 'assignment: not a member of a live mapping' USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  SELECT * INTO r FROM iam.role WHERE id = NEW.role_id;
  IF NOT FOUND THEN
    RETURN NEW;  -- the foreign key reports it
  END IF;
  IF r.status <> 'active' OR r.current_version = 0 THEN
    RAISE EXCEPTION 'assignment: role "%" is not assignable', r.name USING ERRCODE = 'check_violation';
  END IF;
  SELECT v.permissions INTO perms FROM iam.role_version v WHERE v.role_id = r.id AND v.version = r.current_version;

  SELECT * INTO b FROM iam.bu WHERE id = NEW.bu_id;
  IF FOUND AND b.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'assignment: BU % is archived', b.id USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.principal_kind = 'user' AND NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.principal_id)
     OR NEW.principal_kind = 'group' AND NOT EXISTS (SELECT 1 FROM iam.grp WHERE id = NEW.principal_id) THEN
    RAISE EXCEPTION 'assignment: unknown % %', NEW.principal_kind, NEW.principal_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF NEW.source = 'mapped' THEN
    -- The grantor's authority was checked when the mapping was created;
    -- AC-28 still holds for its creator.
    IF NEW.principal_id = m.created_by THEN
      RAISE EXCEPTION 'assignment: users cannot assign roles to themselves (AC-28)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.principal_id AND status = 'active') THEN
      RAISE EXCEPTION 'assignment: the user is not active' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.granted_by IS NULL THEN
    IF NOT iam.in_assignment_bootstrap() THEN
      RAISE EXCEPTION 'assignment: granted_by is required' USING ERRCODE = 'not_null_violation';
    END IF;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.granted_by AND status = 'active') THEN
      RAISE EXCEPTION 'assignment: grantor is not an active user' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-28: no self-assignment, directly or through a group.
    IF NEW.granted_by IN (SELECT iam.principal_users(NEW.principal_kind, NEW.principal_id)) THEN
      RAISE EXCEPTION 'assignment: users cannot assign roles to themselves (AC-28)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-22: authority at the target BU.
    IF NOT iam.can_assign_at(NEW.granted_by, NEW.bu_id) THEN
      RAISE EXCEPTION 'assignment: grantor lacks access.assign at BU % (AC-22)', NEW.bu_id USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-22: only root-level grantors grant roles with admin permissions.
    IF EXISTS (SELECT 1 FROM iam.permission WHERE key = ANY (perms) AND action = 'admin')
       AND NOT iam.is_root_grantor(NEW.granted_by) THEN
      RAISE EXCEPTION 'assignment: role "%" contains admin permissions; only root-level grantors may assign it (AC-22)', r.name
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;

  -- AC-30: no affected user may combine admin and risk-data permissions.
  FOR u IN SELECT iam.principal_users(NEW.principal_kind, NEW.principal_id) LOOP
    IF EXISTS (SELECT 1 FROM iam.permission p
               WHERE p.action = 'admin' AND (p.key = ANY (perms) OR p.key IN (SELECT iam.user_permissions(u))))
       AND EXISTS (SELECT 1 FROM iam.permission p
               WHERE p.risk_data AND (p.key = ANY (perms) OR p.key IN (SELECT iam.user_permissions(u)))) THEN
      RAISE EXCEPTION 'assignment: user % would hold both admin and risk-data permissions; this needs dual approval (AC-30, T-26)', u
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION iam.assignment_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.principal_kind, NEW.principal_id, NEW.role_id, NEW.bu_id, NEW.source, NEW.mapping_id, NEW.granted_by, NEW.granted_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.id, OLD.principal_kind, OLD.principal_id, OLD.role_id, OLD.bu_id, OLD.source, OLD.mapping_id, OLD.granted_by, OLD.granted_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'assignment: assignments are immutable; revoke and grant a new one' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'assignment: already revoked' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.revoked_at IS NULL THEN
    RETURN NEW;  -- no-op update
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  NEW.revoked_at := now();
  -- A mapped assignment ends with its membership or mapping: the mapping
  -- functions revoke it (no revoker); nobody else may.
  IF OLD.source = 'mapped' THEN
    IF NOT iam.in_mapping_sync() THEN
      RAISE EXCEPTION 'assignment: mapped assignments end with their group membership or mapping (AC-13)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.revoked_by IS NULL THEN
    RAISE EXCEPTION 'assignment: revoked_by is required (system revocation arrives with T-32)' USING ERRCODE = 'not_null_violation';
  END IF;
  IF NEW.revoked_by IN (SELECT iam.principal_users(OLD.principal_kind, OLD.principal_id)) THEN
    RAISE EXCEPTION 'assignment: users cannot change their own assignments (AC-28)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT iam.can_assign_at(NEW.revoked_by, OLD.bu_id) THEN
    RAISE EXCEPTION 'assignment: revoker lacks access.assign at BU % (AC-22)', OLD.bu_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.mapping_event(event text, severity text, actor text, m iam.group_role_mapping, user_id uuid, reason text) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor,
    'target', CASE WHEN user_id IS NULL THEN 'group_mapping:' || m.id ELSE 'user:' || user_id END, 'reason', reason,
    'attributes', jsonb_build_object('mapping', m.id, 'group', m.grp_id, 'role', m.role_id, 'bu', m.bu_id, 'user', user_id)));
$$;

-- Brings one member's assignment for one mapping in line: held while the
-- mapping is live, the user an active member, and no rule forbids it;
-- revoked otherwise; a forbidden grant is recorded as skipped.
CREATE FUNCTION iam.mapping_reconcile(mid uuid, uid uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  m      iam.group_role_mapping;
  want   boolean;
  held   uuid;
  why    text;
BEGIN
  PERFORM set_config('iam.mapping_sync', 'on', true);
  SELECT * INTO m FROM iam.group_role_mapping x WHERE x.id = mid;
  want := m.removed_at IS NULL
      AND EXISTS (SELECT 1 FROM iam.grp_member gm WHERE gm.grp_id = m.grp_id AND gm.user_id = uid)
      AND EXISTS (SELECT 1 FROM iam.grp g WHERE g.id = m.grp_id AND g.scim_deleted_at IS NULL);
  SELECT a.id INTO held FROM iam.assignment a
  WHERE a.source = 'mapped' AND a.mapping_id = mid AND a.principal_id = uid AND a.revoked_at IS NULL;
  IF NOT want THEN
    DELETE FROM iam.group_mapping_skip s WHERE s.mapping_id = mid AND s.user_id = uid;
    IF held IS NULL THEN
      RETURN 'none';
    END IF;
    UPDATE iam.assignment a SET revoked_at = now() WHERE a.id = held;
    PERFORM iam.mapping_event('assignment.mapped_revoked', 'info', 'system:iam', m, uid,
      CASE WHEN m.removed_at IS NOT NULL THEN 'mapping removed' ELSE 'left the group' END);
    RETURN 'revoked';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = uid AND u.status = 'active') THEN
    why := 'the user is not active';
  END IF;
  IF why IS NULL AND held IS NOT NULL THEN
    RETURN 'kept';
  END IF;
  IF why IS NULL THEN
    BEGIN
      INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, source, mapping_id, granted_by)
      VALUES ('user', uid, m.role_id, m.bu_id, 'mapped', mid, m.created_by);
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN
      why := SQLERRM;
    END;
  END IF;
  IF why IS NULL THEN
    DELETE FROM iam.group_mapping_skip s WHERE s.mapping_id = mid AND s.user_id = uid;
    PERFORM iam.mapping_event('assignment.mapped_granted', 'info', 'system:iam', m, uid, NULL);
    RETURN 'assigned';
  END IF;
  -- Skipped: a held assignment the user may no longer keep ends too.
  IF held IS NOT NULL THEN
    UPDATE iam.assignment a SET revoked_at = now() WHERE a.id = held;
  END IF;
  INSERT INTO iam.group_mapping_skip (mapping_id, user_id, reason) VALUES (mid, uid, why)
  ON CONFLICT (mapping_id, user_id) DO UPDATE SET reason = EXCLUDED.reason, at = now()
  WHERE iam.group_mapping_skip.reason IS DISTINCT FROM EXCLUDED.reason;
  IF FOUND THEN
    -- An inactive member is routine; a rule conflict needs attention.
    PERFORM iam.mapping_event('assignment.mapped_skipped', CASE WHEN why = 'the user is not active' THEN 'info' ELSE 'high' END,
      'system:iam', m, uid, why);
  END IF;
  RETURN 'skipped';
END $$;

-- Every mapping of the group, for one member.
CREATE FUNCTION iam.mapping_reconcile_member(gid uuid, uid uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.mapping_reconcile(m.id, uid) FROM iam.group_role_mapping m
  WHERE m.grp_id = gid AND (m.removed_at IS NULL OR EXISTS (
    SELECT 1 FROM iam.assignment a WHERE a.mapping_id = m.id AND a.principal_id = uid AND a.revoked_at IS NULL));
$$;

CREATE FUNCTION iam.mapping_on_member() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'UPDATE') THEN
    PERFORM iam.mapping_reconcile_member(OLD.grp_id, OLD.user_id);
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    PERFORM iam.mapping_reconcile_member(NEW.grp_id, NEW.user_id);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER grp_member_mapping AFTER INSERT OR UPDATE OR DELETE ON iam.grp_member
  FOR EACH ROW EXECUTE FUNCTION iam.mapping_on_member();

-- A user leaving or regaining active status: their mapped assignments
-- follow (revoked and skipped while inactive, granted again after).
CREATE FUNCTION iam.mapping_on_status() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.mapping_reconcile_member(gm.grp_id, NEW.id) FROM iam.grp_member gm WHERE gm.user_id = NEW.id;
  RETURN NULL;
END $$;
CREATE TRIGGER app_user_mapping AFTER UPDATE OF status ON iam.app_user
  FOR EACH ROW WHEN ((OLD.status = 'active') IS DISTINCT FROM (NEW.status = 'active')) EXECUTE FUNCTION iam.mapping_on_status();

-- A group deleted through SCIM takes its mappings with it.
CREATE FUNCTION iam.mapping_on_group_deleted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  m iam.group_role_mapping;
BEGIN
  FOR m IN UPDATE iam.group_role_mapping x SET removed_at = now() WHERE x.grp_id = NEW.id AND x.removed_at IS NULL RETURNING * LOOP
    PERFORM iam.mapping_event('group_mapping.removed', 'high', 'system:iam', m, NULL, 'group deleted');
    PERFORM iam.mapping_reconcile(m.id, a.principal_id) FROM iam.assignment a WHERE a.mapping_id = m.id AND a.revoked_at IS NULL;
    DELETE FROM iam.group_mapping_skip s WHERE s.mapping_id = m.id;
  END LOOP;
  RETURN NULL;
END $$;
CREATE TRIGGER grp_deleted_mapping AFTER UPDATE OF scim_deleted_at ON iam.grp
  FOR EACH ROW WHEN (OLD.scim_deleted_at IS NULL AND NEW.scim_deleted_at IS NOT NULL) EXECUTE FUNCTION iam.mapping_on_group_deleted();

-- The API (signed context) ------------------------------------------------

CREATE FUNCTION iam.mapping_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'group mappings need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

-- AC-22 for mappings: access.map_groups at the BU (inside a restricted BU
-- only when granted there), and at the root for roles with admin permissions.
CREATE FUNCTION iam.mapping_authorize(actor uuid, role uuid, bu uuid) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r     iam.role;
  perms text[];
BEGIN
  IF NOT iam.user_has_permission(actor, 'access.map_groups', bu) THEN
    RAISE EXCEPTION 'access.map_groups is required at this BU' USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO r FROM iam.role x WHERE x.id = role;
  IF NOT FOUND OR r.status <> 'active' OR r.current_version = 0 THEN
    RAISE EXCEPTION 'the role is not assignable' USING ERRCODE = 'PF004';
  END IF;
  SELECT v.permissions INTO perms FROM iam.role_version v WHERE v.role_id = r.id AND v.version = r.current_version;
  IF EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = ANY (perms) AND p.action = 'admin')
     AND NOT iam.holds_permission(actor, 'access.map_groups', NULL) THEN
    RAISE EXCEPTION 'role "%" contains admin permissions; only root-level mappers may map it (AC-22)', r.name USING ERRCODE = 'PF008';
  END IF;
END $$;

CREATE FUNCTION iam.group_mapping_create(gid uuid, role uuid, bu uuid, reason text)
RETURNS TABLE (id uuid, assigned integer, skipped integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  actor uuid := iam.mapping_actor();
  m     iam.group_role_mapping;
  outcome text;
  a     integer := 0;
  s     integer := 0;
  uid   uuid;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.grp g WHERE g.id = gid AND g.scim_deleted_at IS NULL) THEN
    RAISE EXCEPTION 'no group %', gid USING ERRCODE = 'P0002';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'no BU %', bu USING ERRCODE = 'P0002';
  END IF;
  PERFORM iam.mapping_authorize(actor, role, bu);
  INSERT INTO iam.group_role_mapping (grp_id, role_id, bu_id, reason, created_by)
  VALUES (gid, role, bu, btrim(reason), actor) RETURNING * INTO m;
  PERFORM iam.mapping_event('group_mapping.created', 'high', actor::text, m, NULL, m.reason);
  FOR uid IN SELECT gm.user_id FROM iam.grp_member gm WHERE gm.grp_id = gid LOOP
    outcome := iam.mapping_reconcile(m.id, uid);
    a := a + (outcome = 'assigned')::integer;
    s := s + (outcome = 'skipped')::integer;
  END LOOP;
  RETURN QUERY SELECT m.id, a, s;
END $$;

CREATE FUNCTION iam.group_mapping_remove(mid uuid, reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.mapping_actor();
  m     iam.group_role_mapping;
  n     integer := 0;
  uid   uuid;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO m FROM iam.group_role_mapping x WHERE x.id = mid AND x.removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no mapping %', mid USING ERRCODE = 'P0002';
  END IF;
  PERFORM iam.mapping_authorize(actor, m.role_id, m.bu_id);
  UPDATE iam.group_role_mapping x SET removed_at = now(), removed_by = actor WHERE x.id = mid RETURNING * INTO m;
  PERFORM iam.mapping_event('group_mapping.removed', 'high', actor::text, m, NULL, btrim(reason));
  FOR uid IN SELECT a.principal_id FROM iam.assignment a WHERE a.mapping_id = mid AND a.revoked_at IS NULL LOOP
    PERFORM iam.mapping_reconcile(mid, uid);
    n := n + 1;
  END LOOP;
  DELETE FROM iam.group_mapping_skip s WHERE s.mapping_id = mid;
  RETURN n;
END $$;

-- Live mappings at BUs where the caller holds access.view.
CREATE FUNCTION iam.group_mapping_list(one uuid)
RETURNS TABLE (id uuid, group_id uuid, group_name text, role_id uuid, role_name text, bu_id uuid, bu_code text, reason text,
               created_by uuid, created_at timestamptz, assigned integer, skipped jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.mapping_actor();
BEGIN
  RETURN QUERY
  SELECT m.id, g.id, g.display_name, r.id, r.name, b.id, b.code, m.reason, m.created_by, m.created_at,
    (SELECT count(*)::integer FROM iam.assignment a WHERE a.mapping_id = m.id AND a.revoked_at IS NULL),
    coalesce((SELECT jsonb_agg(jsonb_build_object('user_id', s.user_id, 'reason', s.reason, 'at', s.at) ORDER BY s.at)
              FROM iam.group_mapping_skip s WHERE s.mapping_id = m.id), '[]')
  FROM iam.group_role_mapping m JOIN iam.grp g ON g.id = m.grp_id JOIN iam.role r ON r.id = m.role_id JOIN iam.bu b ON b.id = m.bu_id
  WHERE m.removed_at IS NULL AND (one IS NULL OR m.id = one) AND iam.user_has_permission(actor, 'access.view', m.bu_id)
  ORDER BY lower(g.display_name), r.name, b.code, m.id;
END $$;

REVOKE ALL ON FUNCTION iam.in_mapping_sync(), iam.mapping_event(text, text, text, iam.group_role_mapping, uuid, text),
  iam.mapping_reconcile(uuid, uuid), iam.mapping_reconcile_member(uuid, uuid), iam.mapping_on_member(), iam.mapping_on_status(),
  iam.mapping_on_group_deleted(), iam.mapping_actor(), iam.mapping_authorize(uuid, uuid, uuid),
  iam.group_mapping_create(uuid, uuid, uuid, text), iam.group_mapping_remove(uuid, text), iam.group_mapping_list(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.group_mapping_create(uuid, uuid, uuid, text), iam.group_mapping_remove(uuid, text),
  iam.group_mapping_list(uuid) TO app_rw;

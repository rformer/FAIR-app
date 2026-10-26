-- F-001 T-07 (AC-20, AC-21, AC-22, AC-28, AC-30): role assignments with
-- grantor checks enforced in the database.
--
-- Rules for a manual assignment of role R at BU B to principal P by grantor G
-- (decisions recorded in design.md, 2026-10-26):
--   * G is an active user and is not P, nor a member of group P (AC-28).
--   * G holds access.assign at B through an unblocked path, or G is a
--     root-level grantor (holds access.assign through an assignment at the
--     Enterprise root). Root-level grantors may assign into restricted BUs;
--     everyone else needs an assignment at or below the restricted BU (AC-22).
--   * If R contains any admin permission, G must be a root-level grantor (AC-22).
--   * No affected user may end up holding both admin and risk-data
--     permissions (AC-30). Until the dual-approval engine (T-26) exists, such
--     an assignment is refused.
--   * R is active, B is not archived, P exists.
-- Revocation follows the same authority and self rules. Assignments are never
-- deleted or otherwise edited. Mapped assignments arrive with T-24.
--
-- granted_by / revoked_by are trusted from the caller for now; T-09 binds
-- them to the signed database context. No application-role grants yet.

-- Identity: the subset of design §3 that assignments need. Directory tasks
-- (T-21 onward) extend these tables.
CREATE TYPE iam.user_status AS ENUM ('active', 'disabled', 'locked');
CREATE TYPE iam.user_source AS ENUM ('scim', 'jit', 'breakglass');

CREATE TABLE iam.app_user (
  id               uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
  idp_id           uuid,                          -- FK to iam.idp once it exists (T-15/T-16)
  external_id      text,
  scim_id          text            UNIQUE,
  email            text            NOT NULL,
  display_name     text            NOT NULL DEFAULT '',
  status           iam.user_status NOT NULL DEFAULT 'active',
  source           iam.user_source NOT NULL DEFAULT 'scim',
  last_login_at    timestamptz,
  disabled_reason  text,
  created_at       timestamptz     NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX app_user_email ON iam.app_user (lower(email));

CREATE TABLE iam.grp (
  id            uuid  PRIMARY KEY DEFAULT gen_random_uuid(),
  scim_id       text  UNIQUE,
  external_id   text,
  display_name  text  NOT NULL
);

CREATE TABLE iam.grp_member (
  grp_id   uuid  NOT NULL REFERENCES iam.grp (id),
  user_id  uuid  NOT NULL REFERENCES iam.app_user (id),
  PRIMARY KEY (grp_id, user_id)
);
CREATE INDEX grp_member_user ON iam.grp_member (user_id);

CREATE TYPE iam.principal_kind AS ENUM ('user', 'group');
CREATE TYPE iam.assignment_source AS ENUM ('manual', 'mapped');

CREATE TABLE iam.assignment (
  id              uuid                  PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_kind  iam.principal_kind    NOT NULL,
  principal_id    uuid                  NOT NULL,
  role_id         uuid                  NOT NULL REFERENCES iam.role (id),
  bu_id           uuid                  NOT NULL REFERENCES iam.bu (id),
  source          iam.assignment_source NOT NULL DEFAULT 'manual',
  mapping_id      uuid,                                  -- FK to group_role_mapping (T-24)
  granted_by      uuid                  REFERENCES iam.app_user (id),  -- NULL = installer bootstrap
  granted_at      timestamptz           NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  revoked_at      timestamptz,
  revoked_by      uuid                  REFERENCES iam.app_user (id),  -- NULL with revoked_at = system (T-32)
  CHECK (expires_at IS NULL OR expires_at > granted_at),
  CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL),
  CHECK ((source = 'mapped') = (mapping_id IS NOT NULL))
);
-- One live assignment per (principal, role, BU).
CREATE UNIQUE INDEX assignment_live ON iam.assignment (principal_kind, principal_id, role_id, bu_id) WHERE revoked_at IS NULL;
CREATE INDEX assignment_principal ON iam.assignment (principal_id) WHERE revoked_at IS NULL;

-- Effective-access rule (design §3): u holds perm at target through a live
-- assignment, direct or via a group, whose role's current version contains
-- perm, on a path that is not blocked by a restricted BU (unless
-- cross_restricted). Disabled and locked users hold nothing.
CREATE FUNCTION iam.user_has_permission(u uuid, perm text, target uuid, cross_restricted boolean DEFAULT false)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM iam.app_user WHERE id = u AND status = 'active')
     AND EXISTS (
       SELECT 1
       FROM iam.assignment a
       JOIN iam.role r ON r.id = a.role_id AND r.status = 'active'
       JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
       JOIN iam.bu_closure c ON c.ancestor_id = a.bu_id AND c.descendant_id = target
       WHERE a.revoked_at IS NULL
         AND (a.expires_at IS NULL OR a.expires_at > now())
         AND perm = ANY (v.permissions)
         AND (NOT c.blocked OR cross_restricted)
         AND ((a.principal_kind = 'user' AND a.principal_id = u)
           OR (a.principal_kind = 'group' AND EXISTS (
                 SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = u))));
$$;

-- A root-level grantor holds access.assign through an assignment at the root.
CREATE FUNCTION iam.is_root_grantor(u uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(u, 'access.assign', (SELECT id FROM iam.bu WHERE parent_id IS NULL));
$$;

-- AC-22: may g create or revoke assignments at bu?
CREATE FUNCTION iam.can_assign_at(g uuid, bu uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(g, 'access.assign', bu) OR iam.is_root_grantor(g);
$$;

-- Users affected by an assignment to a principal.
CREATE FUNCTION iam.principal_users(kind iam.principal_kind, pid uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT pid WHERE kind = 'user'
  UNION
  SELECT user_id FROM iam.grp_member WHERE kind = 'group' AND grp_id = pid;
$$;

-- Every permission u holds anywhere, through live assignments.
CREATE FUNCTION iam.user_permissions(u uuid) RETURNS SETOF text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT p
  FROM iam.assignment a
  JOIN iam.role r ON r.id = a.role_id
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  CROSS JOIN LATERAL unnest(v.permissions) p
  WHERE a.revoked_at IS NULL
    AND (a.expires_at IS NULL OR a.expires_at > now())
    AND ((a.principal_kind = 'user' AND a.principal_id = u)
      OR (a.principal_kind = 'group' AND EXISTS (
            SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = u)));
$$;

CREATE FUNCTION iam.in_assignment_bootstrap() RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT current_user = 'fair_owner' AND coalesce(current_setting('iam.assignment_bootstrap', true), '') = 'on';
$$;

CREATE FUNCTION iam.assignment_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.role;
  perms text[];
  b iam.bu;
  u uuid;
BEGIN
  -- Serialize assignment writes so the AC-30 check sees every concurrent grant.
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  NEW.granted_at := now();
  NEW.revoked_at := NULL;
  NEW.revoked_by := NULL;

  IF NEW.source = 'mapped' THEN
    RAISE EXCEPTION 'assignment: mapped assignments are not available yet (F-001 T-24)' USING ERRCODE = 'feature_not_supported';
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

  IF NEW.granted_by IS NULL THEN
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

-- The only permitted change is a one-time revocation, under the same
-- authority and self rules as granting.
CREATE FUNCTION iam.assignment_before_update() RETURNS trigger
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

CREATE TRIGGER assignment_before_insert BEFORE INSERT ON iam.assignment
  FOR EACH ROW EXECUTE FUNCTION iam.assignment_before_insert();
CREATE TRIGGER assignment_before_update BEFORE UPDATE ON iam.assignment
  FOR EACH ROW EXECUTE FUNCTION iam.assignment_before_update();
CREATE TRIGGER assignment_no_delete BEFORE DELETE ON iam.assignment
  FOR EACH ROW EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER assignment_no_truncate BEFORE TRUNCATE ON iam.assignment
  FOR EACH STATEMENT EXECUTE FUNCTION iam.append_only();

-- Installer bootstrap: makes u the first Platform Admin when nobody can grant
-- it yet. Executable only as fair_owner (installer / migrator), and only
-- while there is no root-level grantor.
CREATE FUNCTION iam.bootstrap_platform_admin(u uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  new_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  IF NOT EXISTS (SELECT 1 FROM iam.app_user WHERE app_user.id = u AND status = 'active') THEN
    RAISE EXCEPTION 'bootstrap: user % is not an active user', u USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.app_user x WHERE iam.is_root_grantor(x.id)) THEN
    RAISE EXCEPTION 'bootstrap: a root-level grantor already exists; use a normal assignment' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM set_config('iam.assignment_bootstrap', 'on', true);
  INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id)
  SELECT 'user', u, r.id, b.id
  FROM iam.role r, iam.bu b
  WHERE r.name = 'Platform Admin' AND r.builtin AND b.parent_id IS NULL
  RETURNING assignment.id INTO new_id;
  PERFORM set_config('iam.assignment_bootstrap', 'off', true);
  IF new_id IS NULL THEN
    RAISE EXCEPTION 'bootstrap: Platform Admin role or root BU missing; run iam migrate first' USING ERRCODE = 'check_violation';
  END IF;
  RETURN new_id;
END $$;

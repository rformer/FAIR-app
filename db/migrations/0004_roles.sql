-- F-001 T-06 (AC-52, AC-55): permission catalog, roles and role versions.
--
-- * iam.permission mirrors the release catalog (permission-catalog.md). It is
--   written only by iam.sync_release, which the migration step calls with the
--   catalog embedded in the build (internal/access/catalog).
-- * Built-in roles are created and re-versioned only by iam.sync_release.
--   Nobody else can edit, version or delete them (AC-52).
-- * Role versions are append-only and numbered 1, 2, 3... per role; inserting
--   one advances role.current_version (AC-55).
-- * Roles are never deleted; custom roles are retired (T-28, AC-56).
-- * Removing or reclassifying a released permission is refused until T-29
--   settles the policy (design D-OQ5).
-- No privileges are granted to application roles yet (T-12 / T-28).

CREATE TYPE iam.permission_action AS ENUM ('read', 'write', 'approve', 'admin', 'export');
CREATE TYPE iam.role_status AS ENUM ('active', 'retired');

CREATE TABLE iam.permission_catalog (
  singleton   boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  version     integer     NOT NULL CHECK (version >= 1),
  synced_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.permission (
  key                    text                   PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
  resource_type          text                   NOT NULL CHECK (resource_type = split_part(key, '.', 1)),
  action                 iam.permission_action  NOT NULL,
  privileged             boolean                NOT NULL,
  risk_data              boolean                NOT NULL,
  introduced_in_version  integer                NOT NULL CHECK (introduced_in_version >= 1),
  CHECK (privileged OR action NOT IN ('approve', 'admin', 'export')),  -- AC-54
  CHECK (NOT (risk_data AND action = 'admin'))                         -- AC-30
);

CREATE TABLE iam.role (
  id               uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
  name             text            NOT NULL UNIQUE CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
  builtin          boolean         NOT NULL DEFAULT false,
  status           iam.role_status NOT NULL DEFAULT 'active',
  current_version  integer         NOT NULL DEFAULT 0 CHECK (current_version >= 0),  -- 0 until the first version
  created_at       timestamptz     NOT NULL DEFAULT now(),
  created_by       uuid,                                                            -- NULL = system
  CHECK (NOT builtin OR status = 'active')
);

CREATE TABLE iam.role_version (
  role_id        uuid        NOT NULL REFERENCES iam.role (id),
  version        integer     NOT NULL CHECK (version >= 1),
  permissions    text[]      NOT NULL,
  changed_by     uuid,                                            -- NULL = system
  change_reason  text        NOT NULL CHECK (char_length(btrim(change_reason)) >= 1),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_id, version)
);

-- True only inside iam.sync_release.
CREATE FUNCTION iam.in_release_sync() RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT current_user = 'fair_owner' AND coalesce(current_setting('iam.release_sync', true), '') = 'on';
$$;

CREATE FUNCTION iam.release_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT iam.in_release_sync() THEN
    RAISE EXCEPTION '%: written only by iam.sync_release', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION '%: rows are never changed or deleted', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END $$;

CREATE FUNCTION iam.role_before_write() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.builtin AND NOT iam.in_release_sync() THEN
      RAISE EXCEPTION 'role: built-in roles come only from the release catalog' USING ERRCODE = 'insufficient_privilege';
    END IF;
    NEW.current_version := 0;
    RETURN NEW;
  END IF;
  -- UPDATE
  IF NEW.id <> OLD.id OR NEW.builtin <> OLD.builtin THEN
    RAISE EXCEPTION 'role: id and builtin are immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.current_version <> OLD.current_version AND pg_trigger_depth() = 1 THEN
    RAISE EXCEPTION 'role: current_version advances only by inserting a role_version' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.builtin AND NOT iam.in_release_sync() THEN
    RAISE EXCEPTION 'role: built-in role "%" cannot be edited (clone it instead)', OLD.name USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.role_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.role;
  unknown text;
BEGIN
  SELECT * INTO r FROM iam.role WHERE id = NEW.role_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NEW;  -- the foreign key reports it
  END IF;
  IF r.builtin AND NOT iam.in_release_sync() THEN
    RAISE EXCEPTION 'role: built-in role "%" cannot be edited (clone it instead)', r.name USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.version <> r.current_version + 1 THEN
    RAISE EXCEPTION 'role_version: next version of "%" is %, got %', r.name, r.current_version + 1, NEW.version USING ERRCODE = 'check_violation';
  END IF;
  IF array_position(NEW.permissions, NULL) IS NOT NULL
     OR cardinality(NEW.permissions) <> (SELECT count(DISTINCT p) FROM unnest(NEW.permissions) p) THEN
    RAISE EXCEPTION 'role_version: permissions must be distinct and non-null' USING ERRCODE = 'check_violation';
  END IF;
  SELECT p INTO unknown FROM unnest(NEW.permissions) p
  WHERE NOT EXISTS (SELECT 1 FROM iam.permission WHERE key = p) LIMIT 1;
  IF unknown IS NOT NULL THEN
    RAISE EXCEPTION 'role_version: unknown permission %', unknown USING ERRCODE = 'foreign_key_violation';
  END IF;
  NEW.permissions := ARRAY(SELECT p FROM unnest(NEW.permissions) p ORDER BY p COLLATE "C");
  RETURN NEW;
END $$;

CREATE FUNCTION iam.role_version_after_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE iam.role SET current_version = NEW.version WHERE id = NEW.role_id;
  RETURN NULL;
END $$;

CREATE TRIGGER permission_catalog_release_only BEFORE INSERT OR UPDATE OR DELETE ON iam.permission_catalog
  FOR EACH ROW EXECUTE FUNCTION iam.release_only();
CREATE TRIGGER permission_release_only BEFORE INSERT ON iam.permission
  FOR EACH ROW EXECUTE FUNCTION iam.release_only();
CREATE TRIGGER permission_immutable BEFORE UPDATE OR DELETE ON iam.permission
  FOR EACH ROW EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER role_before_write BEFORE INSERT OR UPDATE ON iam.role
  FOR EACH ROW EXECUTE FUNCTION iam.role_before_write();
CREATE TRIGGER role_no_delete BEFORE DELETE ON iam.role
  FOR EACH ROW EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER role_version_before_insert BEFORE INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.role_version_before_insert();
CREATE TRIGGER role_version_after_insert AFTER INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.role_version_after_insert();
CREATE TRIGGER role_version_append_only BEFORE UPDATE OR DELETE ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER permission_catalog_no_truncate BEFORE TRUNCATE ON iam.permission_catalog
  FOR EACH STATEMENT EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER permission_no_truncate BEFORE TRUNCATE ON iam.permission
  FOR EACH STATEMENT EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER role_no_truncate BEFORE TRUNCATE ON iam.role
  FOR EACH STATEMENT EXECUTE FUNCTION iam.append_only();
CREATE TRIGGER role_version_no_truncate BEFORE TRUNCATE ON iam.role_version
  FOR EACH STATEMENT EXECUTE FUNCTION iam.append_only();

-- Applies a release catalog and its built-in roles (payload from
-- catalog.SyncPayload). Idempotent. Returns what changed so that upgrade
-- handling (T-29) can notify admins of new permissions (AC-57). Custom roles
-- are never touched: new permissions are not granted to them (AC-57).
CREATE FUNCTION iam.sync_release(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  new_version integer := (payload->>'version')::integer;
  old_version integer;
  p jsonb;
  existing iam.permission;
  rl jsonb;
  r iam.role;
  perms text[];
  cur text[];
  missing text;
  added text[] := '{}';
  created text[] := '{}';
  versioned text[] := '{}';
BEGIN
  IF new_version IS NULL OR new_version < 1 THEN
    RAISE EXCEPTION 'sync_release: payload has no valid version' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM set_config('iam.release_sync', 'on', true);
  LOCK TABLE iam.permission_catalog IN EXCLUSIVE MODE;

  SELECT version INTO old_version FROM iam.permission_catalog;
  old_version := coalesce(old_version, 0);
  IF new_version < old_version THEN
    RAISE EXCEPTION 'sync_release: catalog version % is older than installed %', new_version, old_version USING ERRCODE = 'check_violation';
  END IF;

  FOR p IN SELECT * FROM jsonb_array_elements(payload->'permissions') LOOP
    SELECT * INTO existing FROM iam.permission WHERE key = p->>'key';
    IF FOUND THEN
      IF existing.resource_type <> p->>'resource_type' OR existing.action::text <> p->>'action'
         OR existing.privileged <> (p->>'privileged')::boolean OR existing.risk_data <> (p->>'risk_data')::boolean
         OR existing.introduced_in_version <> (p->>'introduced_in')::integer THEN
        RAISE EXCEPTION 'sync_release: permission % changed; reclassification is not supported yet (D-OQ5, T-29)', existing.key
          USING ERRCODE = 'feature_not_supported';
      END IF;
    ELSE
      -- A new key belongs to a newer catalog than the installed one, so a
      -- changed catalog always carries a bumped version.
      IF (p->>'introduced_in')::integer > new_version
         OR (old_version > 0 AND (p->>'introduced_in')::integer <= old_version) THEN
        RAISE EXCEPTION 'sync_release: new permission % must be introduced in (%, %]', p->>'key', old_version, new_version USING ERRCODE = 'check_violation';
      END IF;
      INSERT INTO iam.permission (key, resource_type, action, privileged, risk_data, introduced_in_version)
      VALUES (p->>'key', p->>'resource_type', (p->>'action')::iam.permission_action,
              (p->>'privileged')::boolean, (p->>'risk_data')::boolean, (p->>'introduced_in')::integer);
      added := added || (p->>'key');
    END IF;
  END LOOP;

  SELECT min(key) INTO missing FROM iam.permission
  WHERE key NOT IN (SELECT e->>'key' FROM jsonb_array_elements(payload->'permissions') e);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'sync_release: permission % is missing from the release; removal is not supported yet (D-OQ5, T-29)', missing
      USING ERRCODE = 'feature_not_supported';
  END IF;

  INSERT INTO iam.permission_catalog (version) VALUES (new_version)
  ON CONFLICT (singleton) DO UPDATE SET version = EXCLUDED.version, synced_at = now();

  FOR rl IN SELECT * FROM jsonb_array_elements(payload->'roles') LOOP
    perms := ARRAY(SELECT x FROM jsonb_array_elements_text(rl->'permissions') x ORDER BY x COLLATE "C");
    SELECT * INTO r FROM iam.role WHERE name = rl->>'name';
    IF NOT FOUND THEN
      INSERT INTO iam.role (name, builtin) VALUES (rl->>'name', true) RETURNING * INTO r;
      created := created || r.name;
    ELSIF NOT r.builtin THEN
      RAISE EXCEPTION 'sync_release: built-in role name "%" is taken by a custom role', r.name USING ERRCODE = 'unique_violation';
    END IF;
    SELECT permissions INTO cur FROM iam.role_version WHERE role_id = r.id AND version = r.current_version;
    IF r.current_version = 0 OR cur IS DISTINCT FROM perms THEN
      INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
      VALUES (r.id, r.current_version + 1, perms, format('release catalog v%s', new_version));
      IF r.current_version > 0 THEN
        versioned := versioned || r.name;
      END IF;
    END IF;
  END LOOP;

  SELECT min(name) INTO missing FROM iam.role
  WHERE builtin AND name NOT IN (SELECT e->>'name' FROM jsonb_array_elements(payload->'roles') e);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'sync_release: built-in role "%" is missing from the release; removal is not supported', missing
      USING ERRCODE = 'feature_not_supported';
  END IF;

  PERFORM set_config('iam.release_sync', 'off', true);
  RETURN jsonb_build_object('version', new_version, 'previous_version', old_version,
    'added_permissions', to_jsonb(added), 'created_roles', to_jsonb(created), 'versioned_roles', to_jsonb(versioned));
END $$;

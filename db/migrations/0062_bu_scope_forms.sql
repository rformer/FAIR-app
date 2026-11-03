-- F-001 T-11d (ADR-007 amendment 1; AC-24, AC-25; NFR p95 <= 10 ms): BU
-- policies check the smaller of two sets, both computed when the statement
-- starts:
--   include form: bu_id = ANY (the caller's visible BUs), as before;
--   exclude form: bu_id <> ALL (every BU in iam.bu the caller cannot see),
--   when authz.scope_excludes says the caller sees most BUs.
-- `= ANY` compares each row with every element of a non-constant array, so a
-- caller who sees most of 2,000 BUs paid 2,000 comparisons per row. The two
-- forms admit the same rows: bu_id references iam.bu, and the hidden set is
-- iam.bu minus the visible set at statement time. It is not stored, so a BU
-- created after the caller's scope was computed is hidden, never visible by
-- default; for writes, archived BUs are not visible, so they are hidden.

GRANT CREATE ON SCHEMA authz TO authz_definer;
SET ROLE authz_definer;

-- The caller of a valid context token: its user and scope version, with
-- every check of ctx_scope (0009): format, a live key, the HMAC, the expiry
-- window, and a scope row at that version (stale tokens fail). NULLs
-- otherwise. It reads only the scope version, where ctx_scope returns (and
-- so unpacks) the whole scope row; the scope functions below read just the
-- column they need.
CREATE FUNCTION authz.ctx_user(OUT user_id uuid, OUT scope_version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  tok text := current_setting('authz.ctx', true);
  parts text[];
  k bytea;
  uid uuid;
  ver bigint;
  exp bigint;
BEGIN
  IF tok IS NULL OR tok = '' THEN
    RETURN;
  END IF;
  parts := string_to_array(tok, '.');
  IF cardinality(parts) <> 7 OR parts[1] <> 'v1' THEN
    RETURN;
  END IF;
  SELECT c.secret INTO k FROM authz.ctx_key c
  WHERE c.key_id = parts[2] AND (c.retired_at IS NULL OR c.retired_at > now());
  IF k IS NULL THEN
    RETURN;
  END IF;
  IF encode(authz.hmac(convert_to(array_to_string(parts[1:6], '.'), 'UTF8'), k, 'sha256'), 'hex') <> parts[7] THEN
    RETURN;
  END IF;
  BEGIN
    uid := parts[3]::uuid;
    ver := parts[4]::bigint;
    exp := parts[5]::bigint;
  EXCEPTION WHEN others THEN
    RETURN;
  END;
  IF exp <= extract(epoch FROM now()) OR exp > extract(epoch FROM now()) + authz.ctx_max_ttl() THEN
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM authz.user_scope u WHERE u.user_id = uid AND u.scope_version = ver) THEN
    RETURN;  -- no access, or a stale token
  END IF;
  user_id := uid;
  scope_version := ver;
END $$;

-- ctx_scope keeps its contract (the caller's scope row, or NULL) over ctx_user.
CREATE OR REPLACE FUNCTION authz.ctx_scope() RETURNS authz.user_scope
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.* FROM authz.ctx_user() c JOIN authz.user_scope u ON u.user_id = c.user_id AND u.scope_version = c.scope_version;
$$;

-- visible_bus as in 0054, reading only the scope column it needs.
CREATE OR REPLACE FUNCTION authz.visible_bus(resource_type text, mode text DEFAULT 'read') RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(ARRAY(
    SELECT b::uuid FROM authz.ctx_user() c
      JOIN authz.user_scope u ON u.user_id = c.user_id AND u.scope_version = c.scope_version,
      jsonb_array_elements_text(CASE mode WHEN 'read' THEN u.read_bus WHEN 'write' THEN u.write_bus END -> resource_type) b
    WHERE mode = 'read' OR NOT EXISTS (SELECT 1 FROM iam.bu x WHERE x.id = b::uuid AND x.archived_at IS NOT NULL)
  ), '{}');
$$;

-- Whether the caller's scope is better checked in the exclude form: they
-- see more than half of the BUs. Cheap (it counts the stored array; nothing
-- is parsed); false for a missing, invalid, expired or stale context. It
-- chooses a form only: both admit the same rows.
CREATE FUNCTION authz.scope_excludes(resource_type text, mode text DEFAULT 'read') RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((
    SELECT jsonb_array_length(CASE mode WHEN 'read' THEN u.read_bus WHEN 'write' THEN u.write_bus END -> resource_type)
    FROM authz.ctx_user() c JOIN authz.user_scope u ON u.user_id = c.user_id AND u.scope_version = c.scope_version), 0) * 2
    > (SELECT count(*) FROM iam.bu);
$$;

-- The BUs the caller cannot see: every BU in iam.bu outside the caller's
-- visible set (visible_bus), at this statement: for writes, archived BUs
-- too, as visible_bus leaves them out. One context check. NULL for a
-- missing, invalid, expired or stale context, so `bu_id <> ALL (NULL)` admits
-- nothing: never an empty set without a scope.
CREATE FUNCTION authz.scope_hides(resource_type text, mode text DEFAULT 'read') RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN mode NOT IN ('read', 'write') THEN NULL ELSE ARRAY(
    (SELECT b.id FROM iam.bu b
     EXCEPT
     SELECT v::uuid FROM jsonb_array_elements_text(CASE mode WHEN 'read' THEN u.read_bus ELSE u.write_bus END -> resource_type) v)
    UNION
    SELECT b.id FROM iam.bu b WHERE mode = 'write' AND b.archived_at IS NOT NULL) END
  FROM authz.ctx_user() c JOIN authz.user_scope u ON u.user_id = c.user_id AND u.scope_version = c.scope_version;
$$;

-- Privileges, as the owner (only the owner can change them): functions
-- created as authz_definer start with EXECUTE for PUBLIC. The definer
-- functions call ctx_user as its owner; nobody else needs it.
REVOKE ALL ON FUNCTION authz.ctx_user() FROM PUBLIC;
REVOKE ALL ON FUNCTION authz.scope_excludes(text, text), authz.scope_hides(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION authz.scope_excludes(text, text), authz.scope_hides(text, text) TO app_rw, app_engine, rollup_definer, bu_guard_definer;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;

-- The policy expression for a resource type and mode (read or write).
CREATE FUNCTION authz.bu_scope_expr(resource_type text, mode text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT format('CASE WHEN (SELECT authz.scope_excludes(%1$L, %2$L))'
                ' THEN bu_id <> ALL ((SELECT authz.scope_hides(%1$L, %2$L))::uuid[])'
                ' ELSE bu_id = ANY ((SELECT authz.visible_bus(%1$L, %2$L))::uuid[]) END', resource_type, mode);
$$;
REVOKE ALL ON FUNCTION authz.bu_scope_expr(text, text) FROM PUBLIC;

-- apply_bu_rls installs the scope-form policies; otherwise as in 0054.
CREATE OR REPLACE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text, inactive_column text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
  sch text := (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl);
  r text := authz.bu_scope_expr(resource_type, 'read');
  w text := authz.bu_scope_expr(resource_type, 'write');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type) THEN
    RAISE EXCEPTION 'apply_bu_rls: unknown resource type %', resource_type USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = 'bu_id'
                 AND a.atttypid = 'uuid'::regtype AND a.attnotnull AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: % needs a NOT NULL uuid column bu_id (AC-24)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF inactive_column IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = inactive_column
                 AND a.atttypid IN ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype) AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: the inactive column of % must be a timestamp or date column (AC-18)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = tbl
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup', 'bu_guard')) THEN
    RAISE EXCEPTION 'apply_bu_rls: % has other policies; BU tables carry only the BU policies', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid = tbl AND c.contype = 'f' AND c.confrelid = 'iam.bu'::regclass) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (bu_id) REFERENCES iam.bu (id)', tbl, rel || '_bu_fk');
  END IF;
  EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s (bu_id)', rel || '_bu_id', tbl);
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);

  EXECUTE format('DROP POLICY IF EXISTS bu_select ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_insert ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_update ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_delete ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_rollup ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_guard ON %s', tbl);
  -- Each (SELECT ...) is an InitPlan, evaluated once per statement.
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (%s)', tbl, r);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (%s)', tbl, w);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (%s) WITH CHECK (%s)', tbl, w, w);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (%s)', tbl, w);
  -- Roll-up functions only (T-30, AC-62).
  EXECUTE format('CREATE POLICY bu_rollup ON %s FOR SELECT TO rollup_definer'
                 ' USING (bu_id = ANY ((SELECT ARRAY(SELECT r.bu_id FROM authz.rollup_bus(%s) r WHERE r.mode = %L))::uuid[]))',
                 tbl, rt, 'aggregate');
  -- The archive guard's count only (T-31, AC-18).
  EXECUTE format('CREATE POLICY bu_guard ON %s FOR SELECT TO bu_guard_definer USING (true)', tbl);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO rollup_definer, bu_guard_definer', sch);
  EXECUTE format('GRANT SELECT ON %s TO rollup_definer, bu_guard_definer', tbl);

  INSERT INTO iam.bu_owned_tables (table_name, resource_type, inactive_column) VALUES (tbl, resource_type, inactive_column)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type, inactive_column = EXCLUDED.inactive_column;
END $$;

-- Tables registered before this migration get the scope-form policies.
SELECT authz.apply_bu_rls(t.table_name, t.resource_type, t.inactive_column) FROM iam.bu_owned_tables t;

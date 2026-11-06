-- F-003 T-01 (F-003-AC-08, AC-18; design §4.4, §11; ADR-007 amendment 2):
-- inherited read. Library entries and controls are shared down the BU tree:
-- a caller who can read a resource type at a BU also reads the rows of that
-- type owned by the BU's ancestors, as long as no restricted BU lies on the
-- path from the ancestor (exclusive) to the BU (inclusive), which is
-- iam.bu_closure.blocked. So a restricted BU inherits nothing from above,
-- and nothing above a restricted BU is inherited through it; inside a
-- restricted subtree, rows of the restricted BU itself are inherited by its
-- descendants.
--
-- Tables opt in with apply_bu_rls(..., shared_down => true): their SELECT
-- policy admits the inherited set as well as the scope form. Insert, update
-- and delete policies are unchanged, so an inherited row is never writable.

GRANT CREATE ON SCHEMA authz TO authz_definer;
GRANT SELECT ON iam.bu_closure TO authz_definer;
SET ROLE authz_definer;

-- The ancestors of the caller's read scope for the type, on unblocked paths,
-- that are not in the read scope already. NULL without a valid context (so
-- `bu_id = ANY (NULL)` admits nothing). Small: at most the tree depth for
-- each top of the caller's scope.
CREATE FUNCTION authz.inherited_bus(resource_type text) RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN c.user_id IS NULL THEN NULL ELSE ARRAY(
    SELECT DISTINCT cl.ancestor_id FROM iam.bu_closure cl
    WHERE cl.descendant_id = ANY (v.vis) AND cl.depth > 0 AND NOT cl.blocked
      AND NOT (cl.ancestor_id = ANY (v.vis))) END
  FROM authz.ctx_user() c
  LEFT JOIN LATERAL (
    SELECT ARRAY(SELECT b::uuid FROM jsonb_array_elements_text(u.read_bus -> resource_type) b) AS vis
    FROM authz.user_scope u WHERE u.user_id = c.user_id AND u.scope_version = c.scope_version) v ON true;
$$;
REVOKE ALL ON FUNCTION authz.inherited_bus(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION authz.inherited_bus(text) TO app_rw, app_engine, rollup_definer, bu_guard_definer;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;

-- The SELECT policy expression of a shared-down table.
CREATE FUNCTION authz.bu_inherited_expr(resource_type text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT format('(%s) OR bu_id = ANY ((SELECT authz.inherited_bus(%L))::uuid[])', authz.bu_scope_expr(resource_type, 'read'), resource_type);
$$;
REVOKE ALL ON FUNCTION authz.bu_inherited_expr(text) FROM PUBLIC;

ALTER TABLE iam.bu_owned_tables ADD COLUMN shared_down boolean NOT NULL DEFAULT false;

-- apply_bu_rls gains shared_down; otherwise as in 0062.
DROP FUNCTION authz.apply_bu_rls(regclass, text, text);
CREATE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text, inactive_column text DEFAULT NULL, shared_down boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
  sch text := (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl);
  r text := CASE WHEN shared_down THEN authz.bu_inherited_expr(resource_type) ELSE authz.bu_scope_expr(resource_type, 'read') END;
  w text := authz.bu_scope_expr(resource_type, 'write');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type) THEN
    RAISE EXCEPTION 'apply_bu_rls: unknown resource type %', resource_type USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF shared_down IS NULL THEN
    RAISE EXCEPTION 'apply_bu_rls: shared_down must be true or false' USING ERRCODE = 'invalid_parameter_value';
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

  INSERT INTO iam.bu_owned_tables (table_name, resource_type, inactive_column, shared_down) VALUES (tbl, resource_type, inactive_column, shared_down)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type, inactive_column = EXCLUDED.inactive_column,
    shared_down = EXCLUDED.shared_down;
END $$;

-- The nearest restricted BU at or above a BU, or NULL outside every
-- restricted subtree (F-003 design §6.4: a move must not leave it).
CREATE FUNCTION iam.restricted_root(bu uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.ancestor_id FROM iam.bu_closure c JOIN iam.bu a ON a.id = c.ancestor_id
  WHERE c.descendant_id = bu AND a.restricted
  ORDER BY c.depth LIMIT 1;
$$;
REVOKE ALL ON FUNCTION iam.restricted_root(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO app_rw;

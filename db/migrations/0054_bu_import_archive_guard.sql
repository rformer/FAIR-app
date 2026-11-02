-- F-001 T-31 (AC-18, AC-19; design §3 bu_owned_tables, §6 /bus/import,
-- /bus/export): the archive guard and BU import/export.
--
--   * Archive guard (AC-18; decided by Robert Former 2026-11-02): a BU is not
--     archived while a registered BU-owned table holds an active row in it.
--     Every row is active unless its table declares an "inactive" column
--     (apply_bu_rls's third argument): rows with it set do not block. RLS
--     hides rows from every existing role, so the count is taken by
--     iam.bu_active_records, owned by the NOLOGIN bootstrap role
--     bu_guard_definer: the only role the bu_guard policy admits to all rows,
--     holding SELECT only, returning counts per table, never rows.
--   * Archived BUs are read-only: authz.visible_bus leaves them out of write
--     scope at once (not only at the next scope recompute), so records are
--     not written into a BU after it is archived. The guard locks the BU row
--     and counts with a fresh snapshot, so writers that committed while it
--     waited are counted; a write whose policy check ran before the archive
--     committed and whose row commits after it can still land (the window is
--     one in-flight statement).
--   * Import/export (AC-19; decided by Robert Former 2026-11-02): fair.bus.v1
--     documents (JSON; CSV is converted by the API). Export: the BUs where
--     the caller holds bu.manage, and restricted BUs whose parent they
--     manage (metadata only, as in bu_list). Import: entries apply in order
--     (a parent exists or comes earlier); missing BUs are created (bu.manage
--     at the parent, or the parent was created earlier in the same import,
--     since new BUs are restricted by default), existing ones renamed (bu.manage at the BU or its
--     parent); moves, archived BUs, un-restricting and loosening roll-ups are
--     refused (they have their own audited flows); restricting and tightening
--     apply through iam.bu_set_restricted / bu_set_rollup. The API runs it
--     all or nothing, with a dry run.

-- Archive guard -----------------------------------------------------------------

ALTER TABLE iam.bu_owned_tables ADD COLUMN inactive_column name;

CREATE FUNCTION iam.bu_active_records(target uuid) RETURNS TABLE (table_name text, active bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t record;
  n bigint;
BEGIN
  FOR t IN SELECT o.table_name, o.inactive_column FROM iam.bu_owned_tables o ORDER BY o.table_name::text LOOP
    EXECUTE format('SELECT count(*) FROM %s WHERE bu_id = $1%s', t.table_name,
      CASE WHEN t.inactive_column IS NULL THEN '' ELSE format(' AND %I IS NULL', t.inactive_column) END)
      INTO n USING target;
    IF n > 0 THEN
      table_name := t.table_name::text;
      active := n;
      RETURN NEXT;
    END IF;
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION iam.bu_active_records(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA iam TO bu_guard_definer;
GRANT SELECT ON iam.bu_owned_tables TO bu_guard_definer;
GRANT CREATE ON SCHEMA iam TO bu_guard_definer;
ALTER FUNCTION iam.bu_active_records(uuid) OWNER TO bu_guard_definer;
REVOKE CREATE ON SCHEMA iam FROM bu_guard_definer;
-- Only the guard trigger (fair_owner) may count. Granted by the new owner: a
-- grant to fair_owner made before the change would pass to the new owner.
SET ROLE bu_guard_definer;
GRANT EXECUTE ON FUNCTION iam.bu_active_records(uuid) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- bu_guard_definer is subject to the other BU policies too (permissive
-- policies are OR-ed, and may all be evaluated), so it may call what they call.
GRANT USAGE ON SCHEMA authz TO bu_guard_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text) TO bu_guard_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

CREATE FUNCTION iam.bu_archive_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  blocking text;
BEGIN
  -- Wait for writers holding the row (their foreign key checks), then count
  -- with a fresh snapshot.
  PERFORM 1 FROM iam.bu b WHERE b.id = NEW.id FOR UPDATE;
  SELECT string_agg(a.table_name || ' (' || a.active || ')', ', ' ORDER BY a.table_name) INTO blocking
  FROM iam.bu_active_records(NEW.id) a;
  IF blocking IS NOT NULL THEN
    RAISE EXCEPTION 'BU % owns active records; reassign them before archiving: %', NEW.code, blocking USING ERRCODE = 'PF003';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam.bu_archive_guard() FROM PUBLIC;

CREATE TRIGGER bu_archive_guard BEFORE UPDATE OF archived_at ON iam.bu
  FOR EACH ROW WHEN (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL)
  EXECUTE FUNCTION iam.bu_archive_guard();

-- Archived BUs leave write scope at once.
GRANT SELECT ON iam.bu TO authz_definer;
GRANT CREATE ON SCHEMA authz TO authz_definer;
SET ROLE authz_definer;
CREATE OR REPLACE FUNCTION authz.visible_bus(resource_type text, mode text DEFAULT 'read') RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(ARRAY(
    SELECT b::uuid FROM authz.ctx_scope() s,
      jsonb_array_elements_text(CASE mode WHEN 'read' THEN s.read_bus WHEN 'write' THEN s.write_bus END -> resource_type) b
    WHERE mode = 'read' OR NOT EXISTS (SELECT 1 FROM iam.bu x WHERE x.id = b::uuid AND x.archived_at IS NOT NULL)
  ), '{}');
$$;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;

-- apply_bu_rls gains the inactive column and the bu_guard policy. The old
-- two-argument form is dropped: a second overload would make two-argument
-- calls ambiguous.
DROP FUNCTION authz.apply_bu_rls(regclass, text);
CREATE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text, inactive_column text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
  sch text := (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl);
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
  -- (SELECT ...) makes each call an InitPlan, evaluated once per statement; the
  -- ::uuid[] cast makes ANY take it as an array rather than a subquery.
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''read''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))'
                 ' WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt, rt);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);
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

-- Tables registered before this migration get the guard policy too.
SELECT authz.apply_bu_rls(t.table_name, t.resource_type) FROM iam.bu_owned_tables t;

-- Import and export --------------------------------------------------------------

-- The signed context's user, who must hold bu.manage somewhere.
CREATE FUNCTION iam.bu_manage_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'BU administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

-- Whether u manages b's metadata: bu.manage at b, or at b's parent (which
-- reaches a restricted b's own record, not what is inside it).
CREATE FUNCTION iam.bu_manages(u uuid, b iam.bu) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(u, 'bu.manage', b.id)
      OR (b.parent_id IS NOT NULL AND iam.user_has_permission(u, 'bu.manage', b.parent_id));
$$;

CREATE FUNCTION iam.bu_export() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.bu_manage_actor();
BEGIN
  RETURN jsonb_build_object('format', 'fair.bus.v1', 'bus', coalesce((
    SELECT jsonb_agg(jsonb_build_object('code', b.code, 'parent_code', p.code, 'name', b.name,
             'restricted', b.restricted, 'rollup_mode', b.rollup_mode) ORDER BY b.depth, b.code)
    FROM iam.bu b LEFT JOIN iam.bu p ON p.id = b.parent_id
    WHERE b.archived_at IS NULL AND iam.bu_manages(u, b)), '[]'));
END $$;

CREATE FUNCTION iam.bu_import(doc jsonb, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor   uuid := iam.bu_manage_actor();
  e       jsonb;
  ecode   text;
  pcode   text;
  ename   text;
  erestr  boolean;
  emode   iam.bu_rollup_mode;
  b       iam.bu;
  p       iam.bu;
  seen    text[] := '{}';
  created text[] := '{}';  -- created by this import: their creator may add children
  report  jsonb := '[]';
  errors  integer := 0;
  outcome text;
  changes jsonb;
BEGIN
  IF doc->>'format' IS DISTINCT FROM 'fair.bus.v1' OR jsonb_typeof(doc->'bus') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'not a fair.bus.v1 document' USING ERRCODE = 'PF004';
  END IF;
  IF jsonb_array_length(doc->'bus') > 5000 THEN
    RAISE EXCEPTION 'at most 5000 BUs per import' USING ERRCODE = 'PF004';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  FOR e IN SELECT * FROM jsonb_array_elements(doc->'bus') LOOP
    ecode := btrim(coalesce(e->>'code', ''));
    changes := '{}';
    BEGIN
      pcode := nullif(btrim(coalesce(e->>'parent_code', '')), '');
      ename := btrim(coalesce(e->>'name', ''));
      IF ecode = '' OR ename = '' THEN
        RAISE EXCEPTION 'each BU needs a code and a name' USING ERRCODE = 'PF004';
      END IF;
      IF ecode = ANY (seen) THEN
        RAISE EXCEPTION 'code % appears twice', ecode USING ERRCODE = 'PF004';
      END IF;
      seen := seen || ecode;
      IF jsonb_typeof(e->'restricted') NOT IN ('boolean', 'null') THEN
        RAISE EXCEPTION 'restricted is true or false' USING ERRCODE = 'PF004';
      END IF;
      erestr := (e->>'restricted')::boolean;
      IF coalesce(e->>'rollup_mode', '') NOT IN ('', 'excluded', 'aggregate', 'full') THEN
        RAISE EXCEPTION 'rollup_mode is excluded, aggregate or full' USING ERRCODE = 'PF004';
      END IF;
      emode := nullif(e->>'rollup_mode', '')::iam.bu_rollup_mode;

      SELECT * INTO b FROM iam.bu x WHERE x.code = ecode;
      IF FOUND AND NOT iam.bu_manages(actor, b) THEN
        RAISE EXCEPTION 'code % is already in use' , ecode USING ERRCODE = 'PF003';
      ELSIF FOUND THEN
        -- Existing: renamed; restricted and tightened through their own
        -- functions; everything else is another flow's.
        IF b.archived_at IS NOT NULL THEN
          RAISE EXCEPTION 'BU % is archived', ecode USING ERRCODE = 'PF003';
        END IF;
        IF pcode IS DISTINCT FROM (SELECT x.code FROM iam.bu x WHERE x.id = b.parent_id) THEN
          RAISE EXCEPTION 'BU % has another parent here; moves are not imported (use the BU API)', ecode USING ERRCODE = 'PF003';
        END IF;
        IF erestr IS FALSE AND b.restricted THEN
          RAISE EXCEPTION 'BU % is restricted here; un-restricting needs a second administrator''s approval (/bus/{id}/restriction)', ecode USING ERRCODE = 'PF003';
        END IF;
        IF emode IS NOT NULL AND iam.rollup_rank(emode) > iam.rollup_rank(b.rollup_mode) THEN
          RAISE EXCEPTION 'loosening BU %''s roll-up needs a second administrator''s approval (/bus/{id}/rollup-mode)', ecode USING ERRCODE = 'PF003';
        END IF;
        IF ename <> b.name THEN
          changes := changes || jsonb_build_object('name', jsonb_build_object('from', b.name, 'to', ename));
          UPDATE iam.bu x SET name = ename, updated_at = now(), updated_by = actor WHERE x.id = b.id RETURNING * INTO b;
          PERFORM iam.bu_event('bu.renamed', actor, b, reason, jsonb_build_object('from', changes->'name'->>'from', 'source', 'import'));
        END IF;
        IF erestr AND NOT b.restricted THEN
          changes := changes || '{"restricted": {"from": false, "to": true}}';
          PERFORM iam.bu_set_restricted(b.id, true, reason);
        END IF;
        IF emode IS NOT NULL AND emode <> b.rollup_mode THEN
          changes := changes || jsonb_build_object('rollup_mode', jsonb_build_object('from', b.rollup_mode, 'to', emode));
          PERFORM iam.bu_set_rollup(b.id, emode, reason);
        END IF;
        outcome := CASE WHEN changes = '{}' THEN 'unchanged' ELSE 'updated' END;
      ELSE
        -- New: under a parent that exists (or came earlier) and that the
        -- caller manages; restricted per the instance default unless the
        -- document tightens it.
        IF pcode IS NULL THEN
          RAISE EXCEPTION 'a new BU needs a parent_code' USING ERRCODE = 'PF004';
        END IF;
        SELECT * INTO p FROM iam.bu x WHERE x.code = pcode;
        IF NOT FOUND OR NOT (pcode = ANY (created) OR iam.bu_manages(actor, p)) THEN
          RAISE EXCEPTION 'parent % not found (parents come before their children)', pcode USING ERRCODE = 'PF004';
        END IF;
        IF NOT (pcode = ANY (created) OR iam.user_has_permission(actor, 'bu.manage', p.id)) THEN
          RAISE EXCEPTION 'bu.manage is required at %, the new BU''s parent', pcode USING ERRCODE = 'PF008';
        END IF;
        IF erestr IS FALSE AND iam.new_bu_restricted() THEN
          RAISE EXCEPTION 'new BUs are restricted here; un-restricting % needs a second administrator''s approval', ecode USING ERRCODE = 'PF003';
        END IF;
        IF emode IS NOT NULL AND emode <> 'excluded' THEN
          RAISE EXCEPTION 'a new BU''s roll-up starts excluded; loosening needs a second administrator''s approval' USING ERRCODE = 'PF003';
        END IF;
        INSERT INTO iam.bu (name, code, parent_id, restricted, created_by, updated_by)
        VALUES (ename, ecode, p.id, coalesce(erestr, iam.new_bu_restricted()), actor, actor) RETURNING * INTO b;
        PERFORM iam.bu_event('bu.created', actor, b, reason, jsonb_build_object('parent', pcode, 'source', 'import'));
        created := created || ecode;
        outcome := 'created';
      END IF;
      report := report || jsonb_build_array(jsonb_build_object('code', ecode, 'outcome', outcome, 'changes', changes));
    EXCEPTION WHEN OTHERS THEN
      errors := errors + 1;
      report := report || jsonb_build_array(jsonb_build_object('code', ecode, 'outcome', 'error', 'error', SQLERRM));
    END;
  END LOOP;
  RETURN jsonb_build_object('bus', report, 'errors', errors);
END $$;

REVOKE ALL ON FUNCTION iam.bu_manage_actor(), iam.bu_manages(uuid, iam.bu), iam.bu_export(), iam.bu_import(jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.bu_export(), iam.bu_import(jsonb, text) TO app_rw;

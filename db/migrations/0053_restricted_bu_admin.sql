-- F-001 T-30 (AC-26, AC-59 to AC-64; design §6 /bus/{id}/restriction,
-- /bus/{id}/rollup-mode): restricted BU administration.
--
--   * New BUs are restricted when bu.new_restricted_default is on (on in
--     every profile; Enterprise Baseline lets a Platform Admin turn it off):
--     the column default reads the setting in force (AC-61).
--   * Authority (decided by Robert Former 2026-10-29): bu.restrict held at
--     the BU's parent. Restriction is managed from outside the BU, so the
--     people inside a restricted BU cannot loosen their own walls. Root
--     administrators manage every BU whose parent they reach (not BUs inside
--     another restricted BU). The root cannot be restricted.
--   * Restricting, and tightening the roll-up mode (full > aggregate >
--     excluded), take effect at once (AC-63), audited high. Un-restricting
--     and loosening go through the T-26 engine (bu.unrestrict,
--     bu.rollup_loosen; approver authority at the parent), then are applied
--     by a bu.restrict holder, audited high.
--   * Roll-up definer functions (AC-26, AC-62): authz.rollup_bus gives the
--     caller's BUs for a resource type with how each may be shown ('full':
--     rows; 'aggregate': totals only); authz.rollup_coverage says, for a
--     subtree, which BUs are full, aggregate or excluded, so roll-ups can
--     say what they leave out. Features' aggregate functions use them.

CREATE FUNCTION iam.new_bu_restricted() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((iam.instance_setting('bu.new_restricted_default'))::boolean, true);
$$;
GRANT EXECUTE ON FUNCTION iam.new_bu_restricted() TO PUBLIC;
ALTER TABLE iam.bu ALTER COLUMN restricted SET DEFAULT iam.new_bu_restricted();

CREATE FUNCTION iam.bu_admin_actor(target uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u      uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
  parent uuid := (SELECT b.parent_id FROM iam.bu b WHERE b.id = target);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'BU administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = target AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'no BU %', target USING ERRCODE = 'P0002';
  END IF;
  IF parent IS NULL THEN
    RAISE EXCEPTION 'the root BU cannot be restricted' USING ERRCODE = 'PF003';
  END IF;
  IF NOT iam.user_has_permission(u, 'bu.restrict', parent) THEN
    RAISE EXCEPTION 'bu.restrict is required at the BU''s parent' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION iam.bu_event(event text, actor uuid, b iam.bu, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor::text, 'target', 'bu:' || b.id, 'reason', reason,
    'attributes', jsonb_build_object('code', b.code, 'restricted', b.restricted, 'rollup_mode', b.rollup_mode) || coalesce(attrs, '{}')));
$$;

CREATE FUNCTION iam.rollup_rank(m iam.bu_rollup_mode) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE m WHEN 'excluded' THEN 0 WHEN 'aggregate' THEN 1 ELSE 2 END;
$$;

-- Restrict at once (AC-63), or ask to un-restrict (returns the approval id).
CREATE FUNCTION iam.bu_set_restricted(target uuid, on_off boolean, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_admin_actor(target);
  b     iam.bu;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO b FROM iam.bu x WHERE x.id = target FOR UPDATE;
  IF b.restricted = on_off THEN
    RAISE EXCEPTION 'the BU is % already', CASE WHEN on_off THEN 'restricted' ELSE 'unrestricted' END USING ERRCODE = 'PF003';
  END IF;
  IF on_off THEN
    UPDATE iam.bu x SET restricted = true WHERE x.id = target RETURNING * INTO b;
    PERFORM iam.bu_event('bu.restricted', actor, b, btrim(reason), NULL);
    RETURN NULL;
  END IF;
  RETURN iam.request_approval('bu.unrestrict', 'bu:' || target, btrim(reason), jsonb_build_object('bu_id', target), b.parent_id);
END $$;

-- Set the roll-up mode: tightening at once; loosening asks for approval
-- (returns the approval id).
CREATE FUNCTION iam.bu_set_rollup(target uuid, mode iam.bu_rollup_mode, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_admin_actor(target);
  b     iam.bu;
  was   iam.bu_rollup_mode;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO b FROM iam.bu x WHERE x.id = target FOR UPDATE;
  was := b.rollup_mode;
  IF mode = was THEN
    RAISE EXCEPTION 'the roll-up mode is % already', mode USING ERRCODE = 'PF003';
  END IF;
  IF iam.rollup_rank(mode) < iam.rollup_rank(was) THEN
    UPDATE iam.bu x SET rollup_mode = mode WHERE x.id = target RETURNING * INTO b;
    PERFORM iam.bu_event('bu.rollup_tightened', actor, b, btrim(reason), jsonb_build_object('before', was));
    RETURN NULL;
  END IF;
  RETURN iam.request_approval('bu.rollup_loosen', 'bu:' || target || ':rollup:' || mode, btrim(reason),
    jsonb_build_object('bu_id', target, 'mode', mode), b.parent_id);
END $$;

-- Applies an approved un-restriction or roll-up loosening.
CREATE FUNCTION iam.bu_apply_approval(approval uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  req   iam.approval_request;
  used  jsonb;
  target uuid;
  actor uuid;
  b     iam.bu;
  was   iam.bu_rollup_mode;
BEGIN
  SELECT * INTO req FROM iam.approval_request a WHERE a.id = approval AND a.kind IN ('bu.unrestrict', 'bu.rollup_loosen');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no BU approval %', approval USING ERRCODE = 'P0002';
  END IF;
  target := (req.payload->>'bu_id')::uuid;
  actor := iam.bu_admin_actor(target);
  used := iam.consume_approval(approval, req.kind, req.target_ref);  -- {payload, requested_by, decided_by} (0018)
  SELECT * INTO b FROM iam.bu x WHERE x.id = target FOR UPDATE;
  IF req.kind = 'bu.unrestrict' THEN
    IF NOT b.restricted THEN
      RAISE EXCEPTION 'the BU is unrestricted already' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.bu x SET restricted = false WHERE x.id = target RETURNING * INTO b;
    PERFORM iam.bu_event('bu.unrestricted', actor, b, req.reason,
      jsonb_build_object('requested_by', used->>'requested_by', 'approved_by', used->>'decided_by', 'approval', approval));
    RETURN 'unrestricted';
  END IF;
  was := b.rollup_mode;
  IF iam.rollup_rank((used->'payload'->>'mode')::iam.bu_rollup_mode) <= iam.rollup_rank(was) THEN
    RAISE EXCEPTION 'the roll-up mode changed since the request (now %)', was USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.bu x SET rollup_mode = (used->'payload'->>'mode')::iam.bu_rollup_mode WHERE x.id = target RETURNING * INTO b;
  PERFORM iam.bu_event('bu.rollup_loosened', actor, b, req.reason,
    jsonb_build_object('before', was, 'requested_by', used->>'requested_by', 'approved_by', used->>'decided_by', 'approval', approval));
  RETURN b.rollup_mode::text;
END $$;

-- BUs the caller may see: where they hold bu.view, and the BUs whose
-- restriction they manage (bu.restrict at the parent; metadata only).
CREATE FUNCTION iam.bu_list(one uuid)
RETURNS TABLE (id uuid, parent_id uuid, code text, name text, depth integer, restricted boolean, rollup_mode text,
               archived_at timestamptz, manageable boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'BU administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN QUERY
  SELECT b.id, b.parent_id, b.code, b.name, b.depth::integer, b.restricted, b.rollup_mode::text, b.archived_at,
    b.parent_id IS NOT NULL AND iam.user_has_permission(u, 'bu.restrict', b.parent_id)
  FROM iam.bu b
  WHERE (one IS NULL OR b.id = one)
    AND (iam.user_has_permission(u, 'bu.view', b.id)
         OR (b.parent_id IS NOT NULL AND iam.user_has_permission(u, 'bu.restrict', b.parent_id)))
  ORDER BY b.depth, b.code;
END $$;

REVOKE ALL ON FUNCTION iam.bu_admin_actor(uuid), iam.bu_event(text, uuid, iam.bu, text, jsonb), iam.bu_set_restricted(uuid, boolean, text),
  iam.bu_set_rollup(uuid, iam.bu_rollup_mode, text), iam.bu_apply_approval(uuid), iam.bu_list(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.bu_set_restricted(uuid, boolean, text), iam.bu_set_rollup(uuid, iam.bu_rollup_mode, text),
  iam.bu_apply_approval(uuid), iam.bu_list(uuid) TO app_rw;

-- Roll-up definer functions (AC-26, AC-62) -------------------------------------

-- The caller's BUs for a resource type and how each may appear in a roll-up:
-- 'full' (rows, as RLS shows them) or 'aggregate' (totals only, never rows).
-- An aggregate definer function sums over these BUs; BUs absent here are
-- excluded and must not contribute.
CREATE FUNCTION authz.rollup_bus(resource_type text) RETURNS TABLE (bu_id uuid, mode text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b::uuid, 'full' FROM authz.ctx_scope() s, jsonb_array_elements_text(s.read_bus -> resource_type) b
  UNION
  SELECT b::uuid, 'aggregate' FROM authz.ctx_scope() s, jsonb_array_elements_text(s.rollup_aggregate_bus -> resource_type) b;
$$;

-- For the subtree under root, each BU's appearance in the caller's roll-ups:
-- full, aggregate or excluded (AC-26: roll-ups say what they leave out).
CREATE FUNCTION authz.rollup_coverage(resource_type text, root uuid) RETURNS TABLE (bu_id uuid, mode text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id, coalesce((SELECT r.mode FROM authz.rollup_bus(resource_type) r WHERE r.bu_id = c.descendant_id), 'excluded')
  FROM iam.bu_closure c WHERE c.ancestor_id = root;
$$;

REVOKE ALL ON FUNCTION authz.rollup_bus(text), authz.rollup_coverage(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION authz.rollup_bus(text), authz.rollup_coverage(text, uuid) TO app_rw, app_engine, rollup_definer;
-- authz_definer owns them, as visible_bus: they read only the materialized
-- scope (and the closure, for coverage).
GRANT SELECT ON iam.bu_closure TO authz_definer;
GRANT USAGE ON SCHEMA iam TO authz_definer;
GRANT CREATE ON SCHEMA authz TO authz_definer;
ALTER FUNCTION authz.rollup_bus(text) OWNER TO authz_definer;
ALTER FUNCTION authz.rollup_coverage(text, uuid) OWNER TO authz_definer;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;

-- rollup_definer (bootstrap, NOLOGIN) owns the features' roll-up functions.
-- It is subject to the BU policies like any reader (so it needs what they
-- call) and is the only role the bu_rollup policy below names.
GRANT USAGE ON SCHEMA authz TO rollup_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text) TO rollup_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- BU-owned tables gain one more policy (AC-62): for rollup_definer only, rows
-- in the caller's aggregate-only BUs are visible too. A feature's roll-up
-- function is a SECURITY DEFINER function owned by rollup_definer that
-- returns totals, never rows, and sums over authz.rollup_coverage. No caller
-- can become rollup_definer (NOLOGIN, granted to no login role), so neither
-- application roles nor other definer functions ever match the policy.
-- (A GUC marker would not do: a caller's session setting is visible inside
-- every definer function it calls.) rollup_definer gets SELECT and nothing
-- else on each table.
CREATE OR REPLACE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type) THEN
    RAISE EXCEPTION 'apply_bu_rls: unknown resource type %', resource_type USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = 'bu_id'
                 AND a.atttypid = 'uuid'::regtype AND a.attnotnull AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: % needs a NOT NULL uuid column bu_id (AC-24)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = tbl
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup')) THEN
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
  -- (SELECT ...) makes each call an InitPlan, evaluated once per statement; the
  -- ::uuid[] cast makes ANY take it as an array rather than a subquery.
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''read''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))'
                 ' WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt, rt);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_rollup ON %s FOR SELECT TO rollup_definer'
                 ' USING (bu_id = ANY ((SELECT ARRAY(SELECT r.bu_id FROM authz.rollup_bus(%s) r WHERE r.mode = %L))::uuid[]))',
                 tbl, rt, 'aggregate');
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO rollup_definer',
                 (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl));
  EXECUTE format('GRANT SELECT ON %s TO rollup_definer', tbl);

  INSERT INTO iam.bu_owned_tables (table_name, resource_type) VALUES (tbl, resource_type)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type;
END $$;

-- Tables registered before this migration get the roll-up policy too.
SELECT authz.apply_bu_rls(t.table_name, t.resource_type) FROM iam.bu_owned_tables t;

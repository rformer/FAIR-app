-- F-007 T-05 (F-007-AC-06 to AC-10; design §3.3, §5.2, §10): pins and
-- exposure.
--
--   * ADR-007 amendment 5 (2026-11-14): authz.allow_definer_insert(table,
--     role) gives one named definer role a registered INSERT policy
--     (bu_definer_insert) on a BU-owned table, for its functions alone; the
--     role is recorded in iam.bu_owned_tables.inserter. Applied to
--     analysis.aggregate and analysis.aggregate_member for register_definer:
--     a risk's exposure (and, from T-07, a roll-up) is requested with
--     register.edit (register.view), not analysis.run (design §5.2). The
--     member trigger still checks every member against the caller's own
--     analysis read scope, so only results the caller sees are aggregated.
--   * register.risk_scenario gains what staleness needs, so it is computed
--     for every reader of the risk whatever they see of scenarios and runs
--     (AC-08): the pinned run's scenario version and finish time (copied
--     when the pin is set, by the version trigger, which sees the run), and
--     the scenario's latest version and whether it is archived (kept by a
--     trigger on risk.scenario). register_definer becomes the links'
--     definer (allow_definer), so that trigger and the F-003 move check
--     reach every link.
--   * F-003 (design §10, OQ7): moving a scenario linked to an open risk
--     outside the risk's subtree is refused (PF026, hint linked_to_risk),
--     naming the risk only to a caller who sees it.
--   * register.request_exposure(risk, seed): with two or more pins, an F-005
--     aggregate with purpose 'exposure' of the pinned results at the risk's
--     BU, requested when the pins (or the BU) change; reused while they do
--     not. An aggregate the caller cannot make (a pinned run they no longer
--     see) leaves the exposure unavailable, which status reports.
--   * register.exposure_status(risk): current, stale (reasons no_pin,
--     newer_version, too_old, archived, exposure_unavailable), unquantified
--     or computing.
--   * register.newer_runs(risk): succeeded runs of each pinned scenario
--     newer than the pinned run, at the register's iteration count, as the
--     caller sees them (AC-10).

-- ADR-007 amendment 5 ----------------------------------------------------------

ALTER TABLE iam.bu_owned_tables ADD COLUMN inserter regrole;

-- apply_bu_rls as in 0103, keeping a table's registered definer insert.
CREATE OR REPLACE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text, inactive_column text DEFAULT NULL, shared_down boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
  sch text := (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl);
  r text := CASE WHEN shared_down THEN authz.bu_inherited_expr(resource_type) ELSE authz.bu_scope_expr(resource_type, 'read') END;
  w text := authz.bu_scope_expr(resource_type, 'write');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type)
     AND NOT apply_bu_rls.resource_type = ANY (string_to_array(coalesce(current_setting('fair.release_resource_types', true), ''), ',')) THEN
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
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup', 'bu_guard', 'bu_definer_select', 'bu_definer_update',
                                   'bu_definer_insert', 'bu_restrict')) THEN
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
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (%s)', tbl, r);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (%s)', tbl, w);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (%s) WITH CHECK (%s)', tbl, w, w);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (%s)', tbl, w);
  EXECUTE format('CREATE POLICY bu_rollup ON %s FOR SELECT TO rollup_definer'
                 ' USING (bu_id = ANY ((SELECT ARRAY(SELECT r.bu_id FROM authz.rollup_bus(%s) r WHERE r.mode = %L))::uuid[]))',
                 tbl, rt, 'aggregate');
  EXECUTE format('CREATE POLICY bu_guard ON %s FOR SELECT TO bu_guard_definer USING (true)', tbl);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO rollup_definer, bu_guard_definer', sch);
  EXECUTE format('GRANT SELECT ON %s TO rollup_definer, bu_guard_definer', tbl);

  INSERT INTO iam.bu_owned_tables (table_name, resource_type, inactive_column, shared_down) VALUES (tbl, resource_type, inactive_column, shared_down)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type, inactive_column = EXCLUDED.inactive_column,
    shared_down = EXCLUDED.shared_down;
END $$;

-- ADR-007 amendment 5: one named definer role inserts rows of a registered
-- BU-owned table, for its functions alone, which check the caller.
CREATE FUNCTION authz.allow_definer_insert(tbl regclass, role regrole) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE r pg_roles;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE oid = role;
  IF NOT EXISTS (SELECT 1 FROM iam.bu_owned_tables b WHERE b.table_name = tbl) THEN
    RAISE EXCEPTION 'allow_definer_insert: % is not a BU-owned table (apply_bu_rls first)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF r.rolcanlogin OR r.rolbypassrls OR r.rolsuper OR r.rolname NOT LIKE '%\_definer'
     OR r.rolname IN ('rollup_definer', 'bu_guard_definer')
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles l ON l.oid = m.member WHERE m.roleid = role AND l.rolcanlogin) THEN
    RAISE EXCEPTION 'allow_definer_insert: % must be a NOLOGIN, NOBYPASSRLS *_definer role granted to no login role', role USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.bu_owned_tables b WHERE b.table_name = tbl AND b.inserter IS NOT NULL AND b.inserter <> role) THEN
    RAISE EXCEPTION 'allow_definer_insert: % already has a definer insert', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  EXECUTE format('DROP POLICY IF EXISTS bu_definer_insert ON %s', tbl);
  EXECUTE format('CREATE POLICY bu_definer_insert ON %s FOR INSERT TO %I WITH CHECK (true)', tbl, r.rolname);
  UPDATE iam.bu_owned_tables SET inserter = role WHERE table_name = tbl;
END $$;
REVOKE ALL ON FUNCTION authz.allow_definer_insert(regclass, regrole) FROM PUBLIC;

SELECT authz.allow_definer_insert('analysis.aggregate', 'register_definer');
SELECT authz.allow_definer_insert('analysis.aggregate_member', 'register_definer');
GRANT INSERT (id, bu_id, name, seed, iterations, purpose) ON analysis.aggregate TO register_definer;
GRANT INSERT (aggregate_id, bu_id, position, run_id, control_set, member_aggregate_id) ON analysis.aggregate_member TO register_definer;

-- The links' definer: the scenario trigger and the move check reach every
-- link. Links are still inserted and deleted under the caller's write
-- scope (bu_insert, bu_delete): there is no definer insert on them.
SELECT authz.allow_definer('register.risk_scenario', 'register_definer');

-- The exposure's state, for the register's status (readers of a risk may
-- not see its exposure aggregate).
GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;
CREATE FUNCTION analysis.exposure_state(id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.state FROM analysis.aggregate a WHERE a.id = exposure_state.id AND a.purpose <> 'analysis'
$$;
REVOKE ALL ON FUNCTION analysis.exposure_state(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.exposure_state(uuid), analysis.emit_created(uuid) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

-- The links' projection -----------------------------------------------------------

ALTER TABLE register.risk_scenario
  ADD COLUMN run_scenario_version integer,
  ADD COLUMN run_finished_at      timestamptz,
  ADD COLUMN scenario_version     integer,
  ADD COLUMN scenario_archived    boolean NOT NULL DEFAULT false;
-- Rows from before this migration carry no copies; the checks hold for new ones.
ALTER TABLE register.risk_scenario ADD CONSTRAINT pin_copies CHECK ((run_id IS NULL) = (run_scenario_version IS NULL) AND (run_id IS NULL) = (run_finished_at IS NULL)) NOT VALID;
CREATE INDEX risk_scenario_scenario ON register.risk_scenario (scenario_id);

ALTER TABLE register.risk ADD COLUMN exposure_key text;
GRANT UPDATE (exposure_aggregate_id, exposure_key) ON register.risk TO register_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

-- As in 0108, the links also copying what staleness needs.
CREATE OR REPLACE FUNCTION register.risk_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  d jsonb;
  prev jsonb;
  problems text[];
  s jsonb;
  open boolean;
  sid uuid;
  run uuid;
  sc record;
  rv integer;
  rf timestamptz;
BEGIN
  NEW.author := register.actor();
  NEW.created_at := now();
  SELECT * INTO h FROM register.risk x WHERE x.id = NEW.risk_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register.risk_version: no such risk %', NEW.risk_id USING ERRCODE = 'PF026';
  END IF;
  IF NEW.version IS DISTINCT FROM h.current_version + 1 THEN
    RAISE EXCEPTION 'register.risk_version: version % of % is stale; the current version is %', NEW.version, NEW.risk_id, h.current_version
      USING ERRCODE = 'PF026', HINT = 'stale_version';
  END IF;
  NEW.bu_id := h.bu_id;
  IF NEW.digest IS DISTINCT FROM encode(sha256(NEW.document), 'hex') THEN
    RAISE EXCEPTION 'register.risk_version: the digest does not match the document' USING ERRCODE = 'PF026';
  END IF;
  BEGIN
    d := convert_from(NEW.document, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'register.risk_version: the document is not JSON' USING ERRCODE = 'PF026', DETAIL = '/: is not JSON';
  END;
  IF h.current_version > 0 THEN
    SELECT convert_from(v.document, 'UTF8')::jsonb INTO prev FROM register.risk_version v WHERE v.risk_id = h.id AND v.version = h.current_version;
  END IF;
  problems := register.check_risk(d, h.bu_id, prev);
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'register.risk_version: invalid risk document' USING ERRCODE = 'PF026', DETAIL = array_to_string(problems, E'\n');
  END IF;
  open := d ->> 'state' = 'open';
  UPDATE register.risk x SET current_version = NEW.version, state = d ->> 'state', title = d ->> 'title', owner = (d ->> 'owner')::uuid,
    category_id = nullif(d ->> 'category', '')::uuid WHERE x.id = h.id;
  -- The links: as the document says; a changed pin records this version.
  DELETE FROM register.risk_scenario l WHERE l.risk_id = h.id
    AND NOT l.scenario_id IN (SELECT (x ->> 'scenario_id')::uuid FROM jsonb_array_elements(d -> 'scenarios') x);
  FOR s IN SELECT x FROM jsonb_array_elements(d -> 'scenarios') x LOOP
    sid := (s ->> 'scenario_id')::uuid;
    run := (s -> 'pin' ->> 'run_id')::uuid;
    -- Both seen by the author: check_risk has just checked them.
    SELECT x.current_version, x.archived_at IS NOT NULL AS archived INTO sc FROM risk.scenario x WHERE x.id = sid;
    rv := NULL;
    rf := NULL;
    IF run IS NOT NULL THEN
      SELECT x.scenario_version, x.finished_at INTO rv, rf FROM analysis.run x WHERE x.id = run;
    END IF;
    BEGIN
      INSERT INTO register.risk_scenario AS l (risk_id, scenario_id, bu_id, open, run_id, control_set, pinned_version, run_scenario_version, run_finished_at,
                                               scenario_version, scenario_archived)
      VALUES (h.id, sid, h.bu_id, open, run, s -> 'pin' ->> 'control_set', CASE WHEN run IS NULL THEN NULL ELSE NEW.version END,
              rv, rf, sc.current_version, coalesce(sc.archived, false))
      ON CONFLICT (risk_id, scenario_id) DO UPDATE SET open = EXCLUDED.open, bu_id = EXCLUDED.bu_id, run_id = EXCLUDED.run_id,
        control_set = EXCLUDED.control_set,
        pinned_version = CASE WHEN EXCLUDED.run_id IS NULL THEN NULL
                              WHEN EXCLUDED.run_id IS NOT DISTINCT FROM l.run_id AND EXCLUDED.control_set IS NOT DISTINCT FROM l.control_set
                              THEN l.pinned_version ELSE NEW.version END,
        run_scenario_version = EXCLUDED.run_scenario_version, run_finished_at = EXCLUDED.run_finished_at,
        scenario_version = EXCLUDED.scenario_version, scenario_archived = EXCLUDED.scenario_archived;
    EXCEPTION WHEN unique_violation THEN
      RAISE EXCEPTION 'register.risk_version: a scenario is linked to another open risk' USING ERRCODE = 'PF026',
        DETAIL = '/scenarios: ' || (s ->> 'scenario_id') || ' is linked to another open risk', HINT = 'scenario_linked';
    END;
  END LOOP;
  RETURN NEW;
END $$;

-- A scenario's new version, archive, restore or move: the links follow;
-- a move that would take a scenario out of its open risk's subtree is
-- refused (F-003, design §10).
CREATE FUNCTION register.scenario_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE k record;
BEGIN
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    SELECT r.id, r.title, r.bu_id = ANY (authz.visible_bus('register', 'read')) AS seen INTO k
    FROM register.risk_scenario l JOIN register.risk r ON r.id = l.risk_id
    WHERE l.scenario_id = NEW.id AND l.open
      AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = r.bu_id AND c.descendant_id = NEW.bu_id)
    LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'risk: the scenario is linked to an open register risk that would not hold it there; unlink it first'
        USING ERRCODE = 'PF026', HINT = 'linked_to_risk',
        DETAIL = CASE WHEN k.seen THEN jsonb_build_object('risk_id', k.id, 'title', k.title)::text ELSE '' END;
    END IF;
  END IF;
  IF NEW.current_version IS DISTINCT FROM OLD.current_version OR (NEW.archived_at IS NULL) IS DISTINCT FROM (OLD.archived_at IS NULL) THEN
    UPDATE register.risk_scenario l SET scenario_version = NEW.current_version, scenario_archived = NEW.archived_at IS NOT NULL
    WHERE l.scenario_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

-- Requests the exposure aggregate of a risk with two or more pins (design
-- §3.3); returns it, or null when none is needed or it is unchanged.
CREATE FUNCTION register.request_exposure(risk uuid, seed numeric) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  k text;
  n integer;
  agg uuid := gen_random_uuid();
  iters integer;
  l record;
  pos integer := 0;
BEGIN
  PERFORM register.actor();
  SELECT * INTO h FROM register.risk x WHERE x.id = request_exposure.risk FOR UPDATE;
  IF NOT FOUND OR NOT h.bu_id = ANY (authz.visible_bus('register', 'write')) THEN
    RAISE EXCEPTION 'register: no such risk %', risk USING ERRCODE = 'P0002';
  END IF;
  SELECT count(*), h.bu_id || '|' || string_agg(x.scenario_id || ':' || x.run_id || ':' || x.control_set, ',' ORDER BY x.scenario_id)
    INTO n, k FROM register.risk_scenario x WHERE x.risk_id = h.id AND x.run_id IS NOT NULL;
  IF n < 2 THEN
    IF h.exposure_aggregate_id IS NOT NULL OR h.exposure_key IS NOT NULL THEN
      UPDATE register.risk x SET exposure_aggregate_id = NULL, exposure_key = NULL WHERE x.id = h.id;
    END IF;
    RETURN NULL;
  END IF;
  IF k = h.exposure_key AND h.exposure_aggregate_id IS NOT NULL AND analysis.exposure_state(h.exposure_aggregate_id) IS DISTINCT FROM 'failed' THEN
    RETURN NULL;
  END IF;
  BEGIN
    SELECT r.iterations INTO iters FROM analysis.run r
    WHERE r.id = (SELECT x.run_id FROM register.risk_scenario x WHERE x.risk_id = h.id AND x.run_id IS NOT NULL ORDER BY x.scenario_id LIMIT 1);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'register: a pinned run is not one the caller sees' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations, purpose)
    VALUES (agg, h.bu_id, left('Exposure: ' || coalesce(h.title, h.id::text), 200), seed, iters, 'exposure');
    FOR l IN SELECT x.run_id, x.control_set FROM register.risk_scenario x WHERE x.risk_id = h.id AND x.run_id IS NOT NULL ORDER BY x.scenario_id LOOP
      INSERT INTO analysis.aggregate_member (aggregate_id, bu_id, position, run_id, control_set) VALUES (agg, h.bu_id, pos, l.run_id, l.control_set);
      pos := pos + 1;
    END LOOP;
    PERFORM analysis.emit_created(agg);
  EXCEPTION WHEN SQLSTATE 'PF024' OR SQLSTATE 'P0002' THEN
    -- A member the caller cannot aggregate: the exposure is unavailable
    -- until someone who can changes the pins or saves the risk.
    UPDATE register.risk x SET exposure_aggregate_id = NULL, exposure_key = k WHERE x.id = h.id;
    RETURN NULL;
  END;
  UPDATE register.risk x SET exposure_aggregate_id = agg, exposure_key = k WHERE x.id = h.id;
  RETURN agg;
END $$;

-- A risk's exposure status (AC-08), for a risk the caller sees; null
-- otherwise.
CREATE FUNCTION register.exposure_status(risk uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  l record;
  reasons jsonb := '[]';
  n integer := 0;
  pins integer := 0;
  max_age integer := (iam.instance_setting('register.analysis_max_age_days') #>> '{}')::integer;
  st text;
BEGIN
  SELECT * INTO h FROM register.risk x WHERE x.id = exposure_status.risk AND x.bu_id = ANY (authz.visible_bus('register', 'read'));
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  FOR l IN SELECT * FROM register.risk_scenario x WHERE x.risk_id = h.id ORDER BY x.scenario_id LOOP
    n := n + 1;
    IF l.scenario_archived THEN
      reasons := reasons || jsonb_build_object('reason', 'archived', 'scenario_id', l.scenario_id);
    END IF;
    IF l.run_id IS NULL THEN
      reasons := reasons || jsonb_build_object('reason', 'no_pin', 'scenario_id', l.scenario_id);
      CONTINUE;
    END IF;
    pins := pins + 1;
    IF l.run_scenario_version IS NULL OR l.run_scenario_version < l.scenario_version THEN
      reasons := reasons || jsonb_build_object('reason', 'newer_version', 'scenario_id', l.scenario_id);
    END IF;
    IF max_age IS NOT NULL AND (l.run_finished_at IS NULL OR l.run_finished_at < now() - make_interval(days => max_age)) THEN
      reasons := reasons || jsonb_build_object('reason', 'too_old', 'scenario_id', l.scenario_id);
    END IF;
  END LOOP;
  IF n = 0 THEN
    RETURN jsonb_build_object('status', 'unquantified', 'reasons', '[]'::jsonb);
  END IF;
  IF pins >= 2 THEN
    st := analysis.exposure_state(h.exposure_aggregate_id);
    IF st IS NULL OR st = 'failed' THEN
      reasons := reasons || jsonb_build_object('reason', 'exposure_unavailable');
    ELSIF st <> 'succeeded' AND reasons = '[]' THEN
      RETURN jsonb_build_object('status', 'computing', 'reasons', '[]'::jsonb);
    END IF;
  END IF;
  IF reasons <> '[]' THEN
    RETURN jsonb_build_object('status', 'stale', 'reasons', reasons);
  END IF;
  RETURN jsonb_build_object('status', 'current', 'reasons', '[]'::jsonb);
END $$;

-- Newer succeeded runs of each pinned scenario at the register's iteration
-- count, as the caller sees them (AC-10), newest first.
CREATE FUNCTION register.newer_runs(risk uuid)
RETURNS TABLE (scenario_id uuid, run_id uuid, scenario_version integer, finished_at timestamptz, control_sets text[])
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT l.scenario_id, r.id, r.scenario_version, r.finished_at, r.control_sets
  FROM register.risk_scenario l
  JOIN analysis.run p ON p.id = l.run_id
  JOIN analysis.run r ON r.scenario_id = l.scenario_id AND r.seq > p.seq AND r.state = 'succeeded' AND r.iterations = register.iterations()
  WHERE l.risk_id = newer_runs.risk
  ORDER BY l.scenario_id, r.seq DESC
$$;

REVOKE ALL ON FUNCTION register.scenario_after_update(), register.request_exposure(uuid, numeric), register.exposure_status(uuid),
  register.newer_runs(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.request_exposure(uuid, numeric), register.exposure_status(uuid), register.newer_runs(uuid), register.iterations() TO app_rw;
GRANT EXECUTE ON FUNCTION register.scenario_after_update() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

CREATE TRIGGER register_links AFTER UPDATE OF bu_id, current_version, archived_at ON risk.scenario
  FOR EACH ROW EXECUTE FUNCTION register.scenario_after_update();

-- F-005 T-02 (F-005-AC-01 to AC-06, AC-15, AC-16, AC-18, AC-19, AC-22,
-- AC-23; design §4; ADR-007 amendment 4): schema analysis.
--
-- * Runs, their per-control-set results and series, aggregates and their
--   members are analysis data: BU-owned (resource type analysis). Analysts
--   insert them as app_rw through analysis.request_run and
--   analysis.request_aggregate (invoker functions), which insert a run with
--   one empty result and series row per control set, or an aggregate with
--   its members. Triggers of analysis_definer set the requester, times and
--   states from the signed context, check the scenario under the caller's
--   RLS, and enforce the limits.
-- * The risk service's worker fills them through analysis_definer's
--   functions (start, progress, put_series, finish, fail), which need the
--   attempt token that start returned; cancel checks the caller. app_rw
--   never updates or deletes. Finished runs and aggregates, results and
--   series are immutable for every role, the superuser included (PF023);
--   limits and states are PF024. Moving a scenario moves its runs.
-- * An aggregate and its members are visible only to a reader who can see
--   every member run: a RESTRICTIVE select policy for app_rw calling
--   analysis.members_visible (ADR-007 amendment 4).
-- * Events are recorded in the change's transaction (design §9).

-- ADR-007 amendment 4 ----------------------------------------------------------

ALTER TABLE iam.bu_owned_tables ADD COLUMN restriction text;

-- apply_bu_rls as in 0094, keeping a table's registered restriction.
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
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup', 'bu_guard', 'bu_definer_select', 'bu_definer_update', 'bu_restrict')) THEN
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

-- ADR-007 amendment 4: one RESTRICTIVE select policy narrows what the BU
-- policies let the application role read; it can never widen it.
CREATE FUNCTION authz.restrict_select(tbl regclass, expr text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu_owned_tables b WHERE b.table_name = tbl) THEN
    RAISE EXCEPTION 'restrict_select: % is not a BU-owned table (apply_bu_rls first)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF expr IS NULL OR btrim(expr) = '' THEN
    RAISE EXCEPTION 'restrict_select: an expression is required' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  EXECUTE format('DROP POLICY IF EXISTS bu_restrict ON %s', tbl);
  EXECUTE format('CREATE POLICY bu_restrict ON %s AS RESTRICTIVE FOR SELECT TO app_rw USING (%s)', tbl, expr);
  UPDATE iam.bu_owned_tables SET restriction = expr WHERE table_name = tbl;
END $$;
REVOKE ALL ON FUNCTION authz.restrict_select(regclass, text) FROM PUBLIC;

-- The schema -----------------------------------------------------------------

CREATE SCHEMA analysis;
REVOKE ALL ON SCHEMA analysis FROM PUBLIC;
GRANT USAGE ON SCHEMA analysis TO app_rw, analysis_definer;

CREATE TABLE analysis.run (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id              uuid        NOT NULL,
  scenario_id        uuid        NOT NULL REFERENCES risk.scenario (id),
  scenario_version   integer     NOT NULL CHECK (scenario_version >= 1),
  bundle_digest      text        NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  seed               numeric(20) NOT NULL CHECK (seed >= 0 AND seed <= 18446744073709551615),
  iterations         integer     NOT NULL CHECK (iterations BETWEEN 1000 AND 2000000),
  control_sets       text[]      NOT NULL CHECK (cardinality(control_sets) BETWEEN 1 AND 20),
  requested_by       uuid        NOT NULL REFERENCES iam.app_user (id),
  requested_at       timestamptz NOT NULL DEFAULT now(),
  state              text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  progress           numeric     NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 1),
  attempt            text,       -- SHA-256 of the running attempt's token
  started_at         timestamptz,
  finished_at        timestamptz,
  cancel_reason      text        CHECK (char_length(btrim(cancel_reason)) BETWEEN 1 AND 1000),
  failure            text        CHECK (failure ~ '^[a-z_]{1,64}$'),
  failure_detail     text        CHECK (char_length(failure_detail) <= 1000),
  engine_version     text        CHECK (char_length(engine_version) BETWEEN 1 AND 64),
  architecture       text        CHECK (architecture IN ('amd64', 'arm64')),
  image_digest       text        CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  validation         jsonb       CHECK (jsonb_typeof(validation) = 'object'),
  warnings           jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(warnings) = 'array'),
  result_digest      text        CHECK (result_digest ~ '^[0-9a-f]{64}$'),
  reproduces         uuid        REFERENCES analysis.run (id),
  reproduction       text        CHECK (reproduction IN ('match', 'mismatch', 'other_version', 'other_architecture')),
  seq                bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  CHECK (iterations::bigint * cardinality(control_sets) <= 20000000),
  CHECK ((state = 'succeeded') = (result_digest IS NOT NULL)),
  CHECK ((state IN ('succeeded', 'failed', 'cancelled')) = (finished_at IS NOT NULL)),
  CHECK ((state = 'failed') = (failure IS NOT NULL)),
  CHECK ((state = 'cancelled') = (cancel_reason IS NOT NULL))
);
CREATE INDEX run_scenario ON analysis.run (scenario_id, seq);
CREATE INDEX run_active ON analysis.run (requested_by) WHERE state IN ('queued', 'running');

CREATE TABLE analysis.result (
  run_id      uuid  NOT NULL REFERENCES analysis.run (id),
  bu_id       uuid  NOT NULL,
  control_set text  NOT NULL CHECK (char_length(control_set) BETWEEN 1 AND 200),
  summary     jsonb CHECK (jsonb_typeof(summary) = 'object'),
  PRIMARY KEY (run_id, control_set)
);

CREATE TABLE analysis.series (
  run_id      uuid  NOT NULL REFERENCES analysis.run (id),
  bu_id       uuid  NOT NULL,
  control_set text  NOT NULL,
  ale         bytea,
  PRIMARY KEY (run_id, control_set),
  FOREIGN KEY (run_id, control_set) REFERENCES analysis.result (run_id, control_set)
);
ALTER TABLE analysis.series ALTER COLUMN ale SET STORAGE EXTERNAL; -- float64 noise does not compress

CREATE TABLE analysis.aggregate (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id           uuid        NOT NULL,
  name            text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  seed            numeric(20) NOT NULL CHECK (seed >= 0 AND seed <= 18446744073709551615),
  iterations      integer     NOT NULL CHECK (iterations BETWEEN 1000 AND 2000000),
  requested_by    uuid        NOT NULL REFERENCES iam.app_user (id),
  requested_at    timestamptz NOT NULL DEFAULT now(),
  state           text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
  attempt         text,
  started_at      timestamptz,
  finished_at     timestamptz,
  failure         text        CHECK (failure ~ '^[a-z_]{1,64}$'),
  failure_detail  text        CHECK (char_length(failure_detail) <= 1000),
  engine_version  text        CHECK (char_length(engine_version) BETWEEN 1 AND 64),
  architecture    text        CHECK (architecture IN ('amd64', 'arm64')),
  summary         jsonb       CHECK (jsonb_typeof(summary) = 'object'),
  ale             bytea,
  result_digest   text        CHECK (result_digest ~ '^[0-9a-f]{64}$'),
  seq             bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  CHECK ((state = 'succeeded') = (result_digest IS NOT NULL AND summary IS NOT NULL AND ale IS NOT NULL)),
  CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
  CHECK ((state = 'failed') = (failure IS NOT NULL))
);
ALTER TABLE analysis.aggregate ALTER COLUMN ale SET STORAGE EXTERNAL;

CREATE TABLE analysis.aggregate_member (
  aggregate_id uuid    NOT NULL REFERENCES analysis.aggregate (id),
  bu_id        uuid    NOT NULL,
  position     integer NOT NULL CHECK (position BETWEEN 0 AND 199),
  run_id       uuid    NOT NULL REFERENCES analysis.run (id),
  control_set  text    NOT NULL,
  engine_version text,
  PRIMARY KEY (aggregate_id, position),
  UNIQUE (aggregate_id, run_id, control_set),
  FOREIGN KEY (run_id, control_set) REFERENCES analysis.result (run_id, control_set)
);
CREATE INDEX aggregate_member_run ON analysis.aggregate_member (run_id);

-- BU ownership, the sanctioned definer access and the aggregate restriction.
SELECT authz.apply_bu_rls('analysis.run', 'analysis');
SELECT authz.apply_bu_rls('analysis.result', 'analysis');
SELECT authz.apply_bu_rls('analysis.series', 'analysis');
SELECT authz.apply_bu_rls('analysis.aggregate', 'analysis');
SELECT authz.apply_bu_rls('analysis.aggregate_member', 'analysis');
SELECT authz.allow_definer('analysis.run', 'analysis_definer');
SELECT authz.allow_definer('analysis.result', 'analysis_definer');
SELECT authz.allow_definer('analysis.series', 'analysis_definer');
SELECT authz.allow_definer('analysis.aggregate', 'analysis_definer');
SELECT authz.allow_definer('analysis.aggregate_member', 'analysis_definer');

GRANT SELECT ON analysis.run, analysis.result, analysis.series, analysis.aggregate, analysis.aggregate_member TO app_rw;
GRANT INSERT (id, bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets, reproduces) ON analysis.run TO app_rw;
GRANT INSERT (run_id, bu_id, control_set) ON analysis.result, analysis.series TO app_rw;
GRANT INSERT (id, bu_id, name, seed, iterations) ON analysis.aggregate TO app_rw;
GRANT INSERT (aggregate_id, bu_id, position, run_id, control_set) ON analysis.aggregate_member TO app_rw;

-- analysis_definer runs under RLS with the caller's context on risk's
-- tables and its own: it needs the policies' functions, the context, the
-- permission check, the BU tree and the outbox.
GRANT USAGE ON SCHEMA authz, iam, risk TO analysis_definer;
GRANT SELECT ON risk.scenario TO analysis_definer;
GRANT SELECT ON iam.bu_closure TO analysis_definer;
GRANT INSERT ON iam.event_outbox TO analysis_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO analysis_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO analysis_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text),
  authz.scope_hides(text, text), authz.inherited_bus(text) TO analysis_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Functions --------------------------------------------------------------------

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

-- The signed context's user, or an error: every request is attributed.
CREATE FUNCTION analysis.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'analysis data needs a valid signed database context' USING ERRCODE = 'PF024';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION analysis.emit(type text, actor text, target text, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'low', 'actor', actor, 'target', target, 'bu_id', bu, 'attributes', attrs));
$$;

-- A run: attributed, queued, its scenario seen under the caller's RLS, not
-- archived, of a version it has, in the scenario's BU.
CREATE FUNCTION analysis.run_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s record;
BEGIN
  NEW.requested_by := analysis.actor();
  NEW.requested_at := now();
  NEW.state := 'queued';
  NEW.progress := 0;
  NEW.attempt := NULL; NEW.started_at := NULL; NEW.finished_at := NULL; NEW.cancel_reason := NULL;
  NEW.failure := NULL; NEW.failure_detail := NULL; NEW.engine_version := NULL; NEW.architecture := NULL;
  NEW.image_digest := NULL; NEW.validation := NULL; NEW.warnings := '[]'; NEW.result_digest := NULL; NEW.reproduction := NULL;
  SELECT sc.bu_id, sc.current_version, sc.archived_at INTO s FROM risk.scenario sc WHERE sc.id = NEW.scenario_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis.run: no such scenario %', NEW.scenario_id USING ERRCODE = 'P0002';
  END IF;
  IF s.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'analysis.run: the scenario is archived' USING ERRCODE = 'PF024', HINT = 'archived';
  END IF;
  IF NEW.scenario_version > s.current_version THEN
    RAISE EXCEPTION 'analysis.run: the scenario has no version %', NEW.scenario_version USING ERRCODE = 'PF024';
  END IF;
  IF NEW.bu_id IS DISTINCT FROM s.bu_id THEN
    RAISE EXCEPTION 'analysis.run: a run belongs to its scenario''s business unit' USING ERRCODE = 'PF024';
  END IF;
  IF (SELECT count(*) FROM unnest(NEW.control_sets) x) <> (SELECT count(DISTINCT x) FROM unnest(NEW.control_sets) x) THEN
    RAISE EXCEPTION 'analysis.run: control sets are named once' USING ERRCODE = 'PF024';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION analysis.run_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM analysis.emit('analysis.run_requested', NEW.requested_by::text, 'analysis_run:' || NEW.id, NEW.bu_id,
    jsonb_build_object('scenario', NEW.scenario_id::text, 'version', NEW.scenario_version::text, 'bundle_digest', NEW.bundle_digest,
      'iterations', NEW.iterations::text, 'control_sets', cardinality(NEW.control_sets)::text));
  RETURN NULL;
END $$;

-- A run's state changes only through the functions below; a finished run
-- never changes, except for the BU of a moved scenario (PF023).
CREATE FUNCTION analysis.run_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_user <> 'analysis_definer' THEN
    RAISE EXCEPTION 'analysis.%: changed only by the analysis functions', TG_TABLE_NAME USING ERRCODE = 'PF023';
  END IF;
  IF (to_jsonb(NEW) - 'bu_id') = (to_jsonb(OLD) - 'bu_id') THEN
    RETURN NEW; -- a move
  END IF;
  IF OLD.state IN ('succeeded', 'failed', 'cancelled') OR NEW.bu_id IS DISTINCT FROM OLD.bu_id
     OR (to_jsonb(NEW) - ARRAY['state', 'progress', 'attempt', 'started_at', 'finished_at', 'cancel_reason', 'failure', 'failure_detail',
         'engine_version', 'architecture', 'image_digest', 'validation', 'warnings', 'result_digest', 'reproduction'])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state', 'progress', 'attempt', 'started_at', 'finished_at', 'cancel_reason', 'failure', 'failure_detail',
         'engine_version', 'architecture', 'image_digest', 'validation', 'warnings', 'result_digest', 'reproduction']) THEN
    RAISE EXCEPTION 'analysis.%: a finished run, and a run''s inputs, never change', TG_TABLE_NAME USING ERRCODE = 'PF023';
  END IF;
  RETURN NEW;
END $$;

-- Results and series: inserted empty with their run, in its creating
-- transaction; filled once, while it runs; never changed after.
CREATE FUNCTION analysis.part_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record;
BEGIN
  SELECT x.bu_id, x.state, x.requested_at, x.control_sets INTO r FROM analysis.run x WHERE x.id = NEW.run_id;
  IF NOT FOUND OR r.state <> 'queued' OR r.requested_at <> now() THEN
    RAISE EXCEPTION 'analysis.%: added only with its run', TG_TABLE_NAME USING ERRCODE = 'PF024';
  END IF;
  IF NOT NEW.control_set = ANY (r.control_sets) THEN
    RAISE EXCEPTION 'analysis.%: % is not a control set of the run', TG_TABLE_NAME, NEW.control_set USING ERRCODE = 'PF024';
  END IF;
  NEW.bu_id := r.bu_id;
  IF TG_TABLE_NAME = 'result' THEN NEW.summary := NULL; ELSE NEW.ale := NULL; END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION analysis.part_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE empty boolean;
BEGIN
  IF current_user <> 'analysis_definer' THEN
    RAISE EXCEPTION 'analysis.%: changed only by the analysis functions', TG_TABLE_NAME USING ERRCODE = 'PF023';
  END IF;
  IF (to_jsonb(NEW) - 'bu_id') = (to_jsonb(OLD) - 'bu_id') THEN
    RETURN NEW; -- a move
  END IF;
  empty := CASE TG_TABLE_NAME WHEN 'result' THEN (to_jsonb(OLD) -> 'summary') = 'null' ELSE (to_jsonb(OLD) -> 'ale') = 'null' END;
  IF NOT empty OR NEW.bu_id IS DISTINCT FROM OLD.bu_id OR NEW.run_id <> OLD.run_id OR NEW.control_set <> OLD.control_set THEN
    RAISE EXCEPTION 'analysis.%: results are written once', TG_TABLE_NAME USING ERRCODE = 'PF023';
  END IF;
  RETURN NEW;
END $$;

-- An aggregate: attributed, queued; its members inserted with it.
CREATE FUNCTION analysis.aggregate_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  NEW.requested_by := analysis.actor();
  NEW.requested_at := now();
  NEW.state := 'queued';
  NEW.attempt := NULL; NEW.started_at := NULL; NEW.finished_at := NULL; NEW.failure := NULL; NEW.failure_detail := NULL;
  NEW.engine_version := NULL; NEW.architecture := NULL; NEW.summary := NULL; NEW.ale := NULL; NEW.result_digest := NULL;
  RETURN NEW;
END $$;

CREATE FUNCTION analysis.aggregate_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_user <> 'analysis_definer' THEN
    RAISE EXCEPTION 'analysis.aggregate: changed only by the analysis functions' USING ERRCODE = 'PF023';
  END IF;
  IF OLD.state IN ('succeeded', 'failed') OR NEW.bu_id IS DISTINCT FROM OLD.bu_id
     OR (to_jsonb(NEW) - ARRAY['state', 'attempt', 'started_at', 'finished_at', 'failure', 'failure_detail', 'engine_version', 'architecture',
         'summary', 'ale', 'result_digest'])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state', 'attempt', 'started_at', 'finished_at', 'failure', 'failure_detail', 'engine_version',
         'architecture', 'summary', 'ale', 'result_digest']) THEN
    RAISE EXCEPTION 'analysis.aggregate: a finished aggregate, and an aggregate''s inputs, never change' USING ERRCODE = 'PF023';
  END IF;
  RETURN NEW;
END $$;

-- A member: a succeeded run's control set the caller can see (under RLS),
-- in the aggregate's subtree, of the aggregate's iterations; added in the
-- aggregate's creating transaction.
CREATE FUNCTION analysis.member_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record; r record;
BEGIN
  SELECT x.bu_id, x.state, x.requested_at, x.iterations INTO a FROM analysis.aggregate x WHERE x.id = NEW.aggregate_id;
  IF NOT FOUND OR a.state <> 'queued' OR a.requested_at <> now() THEN
    RAISE EXCEPTION 'analysis.aggregate_member: added only with its aggregate' USING ERRCODE = 'PF024';
  END IF;
  -- Under the caller's read scope: the definer's own policy would see every
  -- run, so visibility is checked against the caller's scope explicitly.
  SELECT x.bu_id, x.state, x.iterations, x.control_sets, x.engine_version INTO r FROM analysis.run x
  WHERE x.id = NEW.run_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis.aggregate_member: no such run %', NEW.run_id USING ERRCODE = 'P0002';
  END IF;
  IF r.state <> 'succeeded' OR NOT NEW.control_set = ANY (r.control_sets) THEN
    RAISE EXCEPTION 'analysis.aggregate_member: members are control sets of succeeded runs' USING ERRCODE = 'PF024';
  END IF;
  IF r.iterations <> a.iterations THEN
    RAISE EXCEPTION 'analysis.aggregate_member: members have the aggregate''s iterations (%)', a.iterations USING ERRCODE = 'PF024';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = a.bu_id AND c.descendant_id = r.bu_id) THEN
    RAISE EXCEPTION 'analysis.aggregate_member: run % is outside the aggregate''s business unit', NEW.run_id USING ERRCODE = 'PF024';
  END IF;
  NEW.bu_id := a.bu_id;
  NEW.engine_version := r.engine_version;
  RETURN NEW;
END $$;

-- Rows are never deleted (PF023).
CREATE FUNCTION analysis.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'analysis.%: % refused; analysis data is kept', TG_TABLE_NAME, TG_OP USING ERRCODE = 'PF023';
END $$;

CREATE FUNCTION analysis.member_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'analysis.aggregate_member: members never change' USING ERRCODE = 'PF023';
END $$;

-- Moving a scenario moves its runs, results and series (F-003-AC-19).
CREATE FUNCTION analysis.scenario_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    UPDATE analysis.run SET bu_id = NEW.bu_id WHERE scenario_id = NEW.id;
    UPDATE analysis.result SET bu_id = NEW.bu_id WHERE run_id IN (SELECT id FROM analysis.run WHERE scenario_id = NEW.id);
    UPDATE analysis.series SET bu_id = NEW.bu_id WHERE run_id IN (SELECT id FROM analysis.run WHERE scenario_id = NEW.id);
  END IF;
  RETURN NULL;
END $$;

-- Whether every member run of an aggregate is in the caller's read scope
-- (the run table's read policy, for the caller's signed context): the
-- aggregates' restriction (ADR-007 amendment 4). A definer function, so the
-- two tables' policies do not refer to each other.
CREATE FUNCTION analysis.members_visible(aggregate uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NOT EXISTS (SELECT 1 FROM analysis.aggregate_member m JOIN analysis.run r ON r.id = m.run_id
                     WHERE m.aggregate_id = members_visible.aggregate AND NOT r.bu_id = ANY (authz.visible_bus('analysis', 'read')));
$$;

-- The requester's queued and running runs (every row: the definer's policy).
CREATE FUNCTION analysis.active_runs(u uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(*)::int FROM analysis.run r WHERE r.requested_by = u AND r.state IN ('queued', 'running');
$$;

-- The worker's attempt token check.
CREATE FUNCTION analysis.check_attempt(stored text, token text, what text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF stored IS NULL OR token IS NULL OR stored <> encode(sha256(convert_to(token, 'UTF8')), 'hex') THEN
    RAISE EXCEPTION 'analysis: % is not held by this attempt', what USING ERRCODE = 'PF024';
  END IF;
END $$;

-- The worker: a queued run starts (or a crashed attempt restarts), with a
-- fresh token that the other calls must present.
CREATE FUNCTION analysis.start_run(id uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE token text := encode(sha256(convert_to(gen_random_uuid()::text || clock_timestamp()::text, 'UTF8')), 'hex');
BEGIN
  UPDATE analysis.run r SET state = 'running', progress = 0, started_at = now(), attempt = encode(sha256(convert_to(token, 'UTF8')), 'hex')
  WHERE r.id = start_run.id AND r.state IN ('queued', 'running');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: run % is not queued or running', id USING ERRCODE = 'PF024';
  END IF;
  RETURN token;
END $$;

CREATE FUNCTION analysis.progress(id uuid, token text, p numeric) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = progress.id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'analysis: no such run %', id USING ERRCODE = 'P0002'; END IF;
  IF r.state <> 'running' THEN RETURN r.state; END IF; -- cancelled: the worker stops
  PERFORM analysis.check_attempt(r.attempt, token, 'the run');
  UPDATE analysis.run x SET progress = least(greatest(p, 0), 1) WHERE x.id = r.id;
  RETURN 'running';
END $$;

CREATE FUNCTION analysis.put_series(id uuid, token text, set text, ale bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = put_series.id FOR UPDATE;
  IF NOT FOUND OR r.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: run % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(r.attempt, token, 'the run');
  IF ale IS NULL OR length(ale) <> r.iterations * 8 THEN
    RAISE EXCEPTION 'analysis: a series holds % float64 values', r.iterations USING ERRCODE = 'PF024';
  END IF;
  UPDATE analysis.series s SET ale = put_series.ale WHERE s.run_id = r.id AND s.control_set = put_series.set;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: % is not a control set of the run', set USING ERRCODE = 'PF024';
  END IF;
END $$;

-- The worker: a running run succeeds with every set's summary (its series
-- already put), the engine's record, the warnings and the results digest. A
-- reproduction compares itself with the run it reproduces.
CREATE FUNCTION analysis.finish_run(id uuid, token text, engine jsonb, warnings jsonb, summaries jsonb, result_digest text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run; o analysis.run; s text; outcome text;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = finish_run.id FOR UPDATE;
  IF NOT FOUND OR r.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: run % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(r.attempt, token, 'the run');
  IF jsonb_typeof(summaries) <> 'object' OR (SELECT count(*) FROM jsonb_object_keys(summaries)) <> cardinality(r.control_sets) THEN
    RAISE EXCEPTION 'analysis: a summary for every control set is required' USING ERRCODE = 'PF024';
  END IF;
  FOREACH s IN ARRAY r.control_sets LOOP
    IF jsonb_typeof(summaries -> s) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'analysis: no summary for control set %', s USING ERRCODE = 'PF024';
    END IF;
    IF (SELECT x.ale IS NULL FROM analysis.series x WHERE x.run_id = r.id AND x.control_set = s) THEN
      RAISE EXCEPTION 'analysis: no series for control set %', s USING ERRCODE = 'PF024';
    END IF;
    UPDATE analysis.result x SET summary = summaries -> s WHERE x.run_id = r.id AND x.control_set = s;
  END LOOP;
  IF r.reproduces IS NOT NULL THEN
    SELECT * INTO o FROM analysis.run x WHERE x.id = r.reproduces;
    outcome := CASE WHEN o.engine_version IS DISTINCT FROM engine ->> 'version' THEN 'other_version'
                    WHEN o.architecture IS DISTINCT FROM engine ->> 'architecture' THEN 'other_architecture'
                    WHEN o.result_digest = finish_run.result_digest THEN 'match' ELSE 'mismatch' END;
  END IF;
  UPDATE analysis.run x SET state = 'succeeded', progress = 1, finished_at = now(), attempt = NULL,
    engine_version = engine ->> 'version', architecture = engine ->> 'architecture', image_digest = engine ->> 'image_digest',
    validation = engine -> 'validation', warnings = coalesce(finish_run.warnings, '[]'), result_digest = finish_run.result_digest,
    reproduction = outcome
  WHERE x.id = r.id;
  PERFORM analysis.emit('analysis.run_succeeded', 'system:risk', 'analysis_run:' || r.id, r.bu_id,
    jsonb_build_object('scenario', r.scenario_id::text, 'version', r.scenario_version::text, 'bundle_digest', r.bundle_digest,
      'result_digest', result_digest, 'engine_version', engine ->> 'version', 'requested_by', r.requested_by::text));
  IF outcome IS NOT NULL THEN
    PERFORM analysis.emit('analysis.run_reproduced', 'system:risk', 'analysis_run:' || r.reproduces, r.bu_id,
      jsonb_build_object('outcome', outcome, 'reproduction', r.id::text, 'result_digest', result_digest, 'requested_by', r.requested_by::text));
  END IF;
  RETURN coalesce(outcome, 'succeeded');
END $$;

-- The worker: a queued or running run fails (no partial results: series
-- and summaries of a failed run are never read).
CREATE FUNCTION analysis.fail_run(id uuid, token text, failure text, detail text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = fail_run.id FOR UPDATE;
  IF NOT FOUND OR r.state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'analysis: run % is not queued or running', id USING ERRCODE = 'PF024';
  END IF;
  IF r.state = 'running' THEN PERFORM analysis.check_attempt(r.attempt, token, 'the run'); END IF;
  UPDATE analysis.run x SET state = 'failed', finished_at = now(), attempt = NULL, failure = fail_run.failure, failure_detail = left(detail, 1000)
  WHERE x.id = r.id;
  PERFORM analysis.emit('analysis.run_failed', 'system:risk', 'analysis_run:' || r.id, r.bu_id,
    jsonb_build_object('scenario', r.scenario_id::text, 'bundle_digest', r.bundle_digest, 'failure', fail_run.failure, 'requested_by', r.requested_by::text));
END $$;

-- Cancel: the requester, or a holder of analysis.run at the run's BU, while
-- it is queued or running (the worker stops at its next progress call).
CREATE FUNCTION analysis.cancel_run(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := analysis.actor(); r analysis.run;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = cancel_run.id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read')) FOR UPDATE;
  IF NOT FOUND OR (r.requested_by <> u AND NOT iam.holds_permission(u, 'analysis.run', r.bu_id)) THEN
    RAISE EXCEPTION 'analysis: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  IF r.state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'analysis: run % is %', id, r.state USING ERRCODE = 'PF024', HINT = 'finished';
  END IF;
  UPDATE analysis.run x SET state = 'cancelled', finished_at = now(), attempt = NULL, cancel_reason = reason WHERE x.id = r.id;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'analysis.run_cancelled', 'severity', 'low', 'actor', u::text, 'target', 'analysis_run:' || r.id,
    'bu_id', r.bu_id, 'reason', reason, 'attributes', jsonb_build_object('scenario', r.scenario_id::text, 'bundle_digest', r.bundle_digest)));
END $$;

-- The worker's aggregate calls, as the run's.
CREATE FUNCTION analysis.start_aggregate(id uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE token text := encode(sha256(convert_to(gen_random_uuid()::text || clock_timestamp()::text, 'UTF8')), 'hex');
BEGIN
  UPDATE analysis.aggregate a SET state = 'running', started_at = now(), attempt = encode(sha256(convert_to(token, 'UTF8')), 'hex')
  WHERE a.id = start_aggregate.id AND a.state IN ('queued', 'running');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: aggregate % is not queued or running', id USING ERRCODE = 'PF024';
  END IF;
  RETURN token;
END $$;

CREATE FUNCTION analysis.finish_aggregate(id uuid, token text, engine jsonb, summary jsonb, ale bytea, result_digest text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = finish_aggregate.id FOR UPDATE;
  IF NOT FOUND OR a.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: aggregate % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate');
  IF ale IS NULL OR length(ale) <> a.iterations * 8 OR jsonb_typeof(summary) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'analysis: an aggregate holds a summary and % float64 values', a.iterations USING ERRCODE = 'PF024';
  END IF;
  UPDATE analysis.aggregate x SET state = 'succeeded', finished_at = now(), attempt = NULL, engine_version = engine ->> 'version',
    architecture = engine ->> 'architecture', summary = finish_aggregate.summary, ale = finish_aggregate.ale, result_digest = finish_aggregate.result_digest
  WHERE x.id = a.id;
  PERFORM analysis.emit('analysis.aggregate_succeeded', 'system:risk', 'analysis_aggregate:' || a.id, a.bu_id,
    jsonb_build_object('result_digest', result_digest, 'members', (SELECT count(*) FROM analysis.aggregate_member m WHERE m.aggregate_id = a.id)::text,
      'requested_by', a.requested_by::text));
END $$;

CREATE FUNCTION analysis.fail_aggregate(id uuid, token text, failure text, detail text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = fail_aggregate.id FOR UPDATE;
  IF NOT FOUND OR a.state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'analysis: aggregate % is not queued or running', id USING ERRCODE = 'PF024';
  END IF;
  IF a.state = 'running' THEN PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate'); END IF;
  UPDATE analysis.aggregate x SET state = 'failed', finished_at = now(), attempt = NULL, failure = fail_aggregate.failure, failure_detail = left(detail, 1000)
  WHERE x.id = a.id;
  PERFORM analysis.emit('analysis.aggregate_failed', 'system:risk', 'analysis_aggregate:' || a.id, a.bu_id,
    jsonb_build_object('failure', fail_aggregate.failure, 'requested_by', a.requested_by::text));
END $$;

REVOKE ALL ON FUNCTION analysis.actor(), analysis.emit(text, text, text, uuid, jsonb), analysis.run_before_insert(), analysis.run_after_insert(),
  analysis.run_before_update(), analysis.part_before_insert(), analysis.part_before_update(), analysis.aggregate_before_insert(),
  analysis.aggregate_before_update(), analysis.member_before_insert(), analysis.refuse_change(), analysis.member_before_update(),
  analysis.scenario_after_update(), analysis.members_visible(uuid), analysis.active_runs(uuid), analysis.check_attempt(text, text, text), analysis.start_run(uuid),
  analysis.progress(uuid, text, numeric), analysis.put_series(uuid, text, text, bytea), analysis.finish_run(uuid, text, jsonb, jsonb, jsonb, text),
  analysis.fail_run(uuid, text, text, text), analysis.cancel_run(uuid, text), analysis.start_aggregate(uuid),
  analysis.finish_aggregate(uuid, text, jsonb, jsonb, bytea, text), analysis.fail_aggregate(uuid, text, text, text) FROM PUBLIC;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION analysis.run_before_insert(), analysis.run_after_insert(), analysis.run_before_update(), analysis.part_before_insert(),
  analysis.part_before_update(), analysis.aggregate_before_insert(), analysis.aggregate_before_update(), analysis.member_before_insert(),
  analysis.refuse_change(), analysis.member_before_update(), analysis.scenario_after_update() TO fair_owner;
GRANT EXECUTE ON FUNCTION analysis.members_visible(uuid), analysis.active_runs(uuid), analysis.start_run(uuid), analysis.progress(uuid, text, numeric),
  analysis.put_series(uuid, text, text, bytea), analysis.finish_run(uuid, text, jsonb, jsonb, jsonb, text), analysis.fail_run(uuid, text, text, text),
  analysis.cancel_run(uuid, text), analysis.start_aggregate(uuid), analysis.finish_aggregate(uuid, text, jsonb, jsonb, bytea, text),
  analysis.fail_aggregate(uuid, text, text, text) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- The analyst's requests (invoker functions, as app_rw under its context).
-- request_run inserts a run with an empty result and series per control
-- set, checking the iteration bounds and the active-run limit the service
-- passes from its settings (F-015) and, for a reproduction, the original's
-- inputs.
CREATE FUNCTION analysis.request_run(scenario uuid, version integer, bundle_digest text, seed numeric, iterations integer, sets text[],
  reproduces uuid, iterations_min integer, iterations_max integer, max_active integer) RETURNS uuid
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE id uuid := gen_random_uuid(); bu uuid; o record; s text;
BEGIN
  IF iterations IS NULL OR iterations < iterations_min OR iterations > iterations_max THEN
    RAISE EXCEPTION 'analysis: iterations are between % and %', iterations_min, iterations_max USING ERRCODE = 'PF024', HINT = 'iterations';
  END IF;
  IF analysis.active_runs(analysis.actor()) >= max_active THEN
    RAISE EXCEPTION 'analysis: at most % runs queued or running at once', max_active USING ERRCODE = 'PF024', HINT = 'too_many_runs';
  END IF;
  IF request_run.reproduces IS NOT NULL THEN
    SELECT r.scenario_id, r.scenario_version, r.bundle_digest, r.seed, r.iterations, r.control_sets, r.state INTO o FROM analysis.run r WHERE r.id = request_run.reproduces;
    IF NOT FOUND OR o.state <> 'succeeded' THEN
      RAISE EXCEPTION 'analysis: run % is not a succeeded run', request_run.reproduces USING ERRCODE = 'P0002';
    END IF;
    IF (o.scenario_id, o.scenario_version, o.seed, o.iterations, o.control_sets) IS DISTINCT FROM (scenario, version, seed, iterations, sets) THEN
      RAISE EXCEPTION 'analysis: a reproduction has the original''s inputs' USING ERRCODE = 'PF024';
    END IF;
    IF o.bundle_digest <> request_run.bundle_digest THEN
      RAISE EXCEPTION 'analysis: the input bundle no longer has the original''s digest' USING ERRCODE = 'PF024', HINT = 'bundle_changed';
    END IF;
  END IF;
  SELECT sc.bu_id INTO bu FROM risk.scenario sc WHERE sc.id = scenario;
  INSERT INTO analysis.run (id, bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets, reproduces)
  VALUES (id, bu, scenario, version, request_run.bundle_digest, request_run.seed, request_run.iterations, sets, request_run.reproduces);
  FOREACH s IN ARRAY sets LOOP
    INSERT INTO analysis.result (run_id, bu_id, control_set) VALUES (id, bu, s);
    INSERT INTO analysis.series (run_id, bu_id, control_set) VALUES (id, bu, s);
  END LOOP;
  RETURN id;
END $$;

-- request_aggregate inserts an aggregate at bu with its members, in order.
CREATE FUNCTION analysis.request_aggregate(bu uuid, name text, seed numeric, members jsonb) RETURNS uuid
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE id uuid := gen_random_uuid(); m record; n integer; iters integer;
BEGIN
  IF jsonb_typeof(members) <> 'array' OR jsonb_array_length(members) NOT BETWEEN 2 AND 200 THEN
    RAISE EXCEPTION 'analysis: an aggregate has 2 to 200 members' USING ERRCODE = 'PF024';
  END IF;
  SELECT r.iterations INTO iters FROM analysis.run r WHERE r.id = (members -> 0 ->> 'run_id')::uuid;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: no such run %', members -> 0 ->> 'run_id' USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations) VALUES (id, bu, name, seed, iters);
  n := 0;
  FOR m IN SELECT x ->> 'run_id' AS run_id, x ->> 'control_set' AS control_set FROM jsonb_array_elements(members) x LOOP
    INSERT INTO analysis.aggregate_member (aggregate_id, bu_id, position, run_id, control_set) VALUES (id, bu, n, m.run_id::uuid, m.control_set);
    n := n + 1;
  END LOOP;
  PERFORM analysis.emit_created(id);
  RETURN id;
END $$;

SET ROLE analysis_definer;
-- The aggregate's creation event (requester and members from the rows).
CREATE FUNCTION analysis.emit_created(id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = emit_created.id AND x.state = 'queued' AND x.requested_at = now();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: aggregate % was not created here', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.emit('analysis.aggregate_created', a.requested_by::text, 'analysis_aggregate:' || a.id, a.bu_id,
    jsonb_build_object('members', (SELECT count(*) FROM analysis.aggregate_member m WHERE m.aggregate_id = a.id)::text,
      'iterations', a.iterations::text, 'name', a.name));
END $$;
REVOKE ALL ON FUNCTION analysis.emit_created(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.emit_created(uuid), analysis.actor() TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT EXECUTE ON FUNCTION analysis.request_run(uuid, integer, text, numeric, integer, text[], uuid, integer, integer, integer),
  analysis.request_aggregate(uuid, text, numeric, jsonb) TO app_rw;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

CREATE TRIGGER run_before_insert BEFORE INSERT ON analysis.run FOR EACH ROW EXECUTE FUNCTION analysis.run_before_insert();
CREATE TRIGGER run_after_insert AFTER INSERT ON analysis.run FOR EACH ROW EXECUTE FUNCTION analysis.run_after_insert();
CREATE TRIGGER run_before_update BEFORE UPDATE ON analysis.run FOR EACH ROW EXECUTE FUNCTION analysis.run_before_update();
CREATE TRIGGER part_before_insert BEFORE INSERT ON analysis.result FOR EACH ROW EXECUTE FUNCTION analysis.part_before_insert();
CREATE TRIGGER part_before_insert BEFORE INSERT ON analysis.series FOR EACH ROW EXECUTE FUNCTION analysis.part_before_insert();
CREATE TRIGGER part_before_update BEFORE UPDATE ON analysis.result FOR EACH ROW EXECUTE FUNCTION analysis.part_before_update();
CREATE TRIGGER part_before_update BEFORE UPDATE ON analysis.series FOR EACH ROW EXECUTE FUNCTION analysis.part_before_update();
CREATE TRIGGER aggregate_before_insert BEFORE INSERT ON analysis.aggregate FOR EACH ROW EXECUTE FUNCTION analysis.aggregate_before_insert();
CREATE TRIGGER aggregate_before_update BEFORE UPDATE ON analysis.aggregate FOR EACH ROW EXECUTE FUNCTION analysis.aggregate_before_update();
CREATE TRIGGER member_before_insert BEFORE INSERT ON analysis.aggregate_member FOR EACH ROW EXECUTE FUNCTION analysis.member_before_insert();
CREATE TRIGGER member_before_update BEFORE UPDATE ON analysis.aggregate_member FOR EACH ROW EXECUTE FUNCTION analysis.member_before_update();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.run FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.result FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.series FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.aggregate FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.aggregate_member FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.run FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.result FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.series FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.aggregate FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.aggregate_member FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER analysis_moved AFTER UPDATE OF bu_id ON risk.scenario FOR EACH ROW EXECUTE FUNCTION analysis.scenario_after_update();

-- Every member run visible to the reader (ADR-007 amendment 4).
SELECT authz.restrict_select('analysis.aggregate', 'analysis.members_visible(id)');
SELECT authz.restrict_select('analysis.aggregate_member', 'analysis.members_visible(aggregate_id)');

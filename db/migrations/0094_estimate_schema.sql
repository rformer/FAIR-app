-- F-004 T-04 (F-004-AC-07, AC-09; design §4.1, §4.4; ADR-007 amendment 3):
-- schema estimate.
--
-- * Requests and their factors, estimators and pinned reference classes are
--   scenario data: BU-owned under the BU policies (resource type scenario).
--   Analysts insert them as app_rw, in the request's creating transaction
--   (estimators while it is open); triggers set the creator, the BU and the
--   copies, and enforce the limits. app_rw never updates or deletes them.
-- * estimate_definer (bootstrap role, NOLOGIN) reads and updates them for
--   estimators and the risk service's jobs, through the sanctioned definer
--   policies (authz.allow_definer): the functions that do so follow in
--   F-004 T-06 and T-07 and check the caller on every call.
-- * Answers, the notice outbox and the calibration tables are reached only
--   through estimate_definer's functions: app_rw holds no privileges on
--   them. Answers and pinned references are append-only for every role
--   (PF021); limits and states are PF022.
--
-- authz.apply_bu_rls keeps the definer policies when it re-applies a
-- table's BU policies; iam.bu_owned_tables records the definer.

ALTER TABLE iam.bu_owned_tables ADD COLUMN definer regrole;

-- apply_bu_rls as in 0085, keeping a table's sanctioned definer policies.
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
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup', 'bu_guard', 'bu_definer_select', 'bu_definer_update')) THEN
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

-- ADR-007 amendment 3: one named definer role reads and updates every row
-- of a registered BU-owned table, for its functions alone.
CREATE FUNCTION authz.allow_definer(tbl regclass, role regrole) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE r pg_roles;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE oid = role;
  IF NOT EXISTS (SELECT 1 FROM iam.bu_owned_tables b WHERE b.table_name = tbl) THEN
    RAISE EXCEPTION 'allow_definer: % is not a BU-owned table (apply_bu_rls first)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF r.rolcanlogin OR r.rolbypassrls OR r.rolsuper OR r.rolname NOT LIKE '%\_definer'
     OR r.rolname IN ('rollup_definer', 'bu_guard_definer')
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles l ON l.oid = m.member WHERE m.roleid = role AND l.rolcanlogin) THEN
    RAISE EXCEPTION 'allow_definer: % must be a NOLOGIN, NOBYPASSRLS *_definer role granted to no login role', role USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.bu_owned_tables b WHERE b.table_name = tbl AND b.definer IS NOT NULL AND b.definer <> role) THEN
    RAISE EXCEPTION 'allow_definer: % already has a definer', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  EXECUTE format('DROP POLICY IF EXISTS bu_definer_select ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_definer_update ON %s', tbl);
  EXECUTE format('CREATE POLICY bu_definer_select ON %s FOR SELECT TO %I USING (true)', tbl, r.rolname);
  EXECUTE format('CREATE POLICY bu_definer_update ON %s FOR UPDATE TO %I USING (true) WITH CHECK (true)', tbl, r.rolname);
  EXECUTE format('GRANT SELECT, UPDATE ON %s TO %I', tbl, r.rolname);
  UPDATE iam.bu_owned_tables SET definer = role WHERE table_name = tbl;
END $$;
REVOKE ALL ON FUNCTION authz.allow_definer(regclass, regrole) FROM PUBLIC;

-- The schema -----------------------------------------------------------------

CREATE SCHEMA estimate;
REVOKE ALL ON SCHEMA estimate FROM PUBLIC;
GRANT USAGE ON SCHEMA estimate TO app_rw, estimate_definer;

CREATE TABLE estimate.request (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id            uuid        NOT NULL,
  scenario_id      uuid        NOT NULL REFERENCES risk.scenario (id),
  scenario_version integer     NOT NULL CHECK (scenario_version >= 1),
  title            text        NOT NULL CHECK (char_length(btrim(title)) BETWEEN 1 AND 200),
  instructions     text        NOT NULL DEFAULT '' CHECK (char_length(instructions) <= 10000),
  confidence       numeric     NOT NULL DEFAULT 0.9 CHECK (confidence > 0 AND confidence < 1),
  due_at           timestamptz NOT NULL,
  status           text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'complete', 'closed', 'cancelled')),
  affected         text        CHECK (affected IN ('moved', 'archived', 'factor_changed')),
  cancel_reason    text        CHECK (char_length(btrim(cancel_reason)) BETWEEN 1 AND 1000),
  context          jsonb       NOT NULL CHECK (jsonb_typeof(context) = 'object'),
  created_by       uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at       timestamptz NOT NULL DEFAULT now(),
  ended_at         timestamptz,
  seq              bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  CHECK ((status = 'open') = (ended_at IS NULL)),
  CHECK ((status = 'cancelled') = (cancel_reason IS NOT NULL))
);
CREATE INDEX request_scenario ON estimate.request (scenario_id, seq);

CREATE TABLE estimate.request_factor (
  request_id       uuid        NOT NULL REFERENCES estimate.request (id),
  bu_id            uuid        NOT NULL,
  pointer          text        NOT NULL CHECK (pointer ~ '^(/[a-z0-9_]+)+$' AND char_length(pointer) <= 200),
  factor           text        NOT NULL CHECK (char_length(factor) BETWEEN 1 AND 200),
  unit             text        NOT NULL CHECK (unit IN ('events_per_year', 'probability', 'currency', 'percentile', 'fraction')),
  definition       text        NOT NULL CHECK (char_length(definition) BETWEEN 1 AND 10000),
  accepted_version integer     CHECK (accepted_version >= 1),
  accepted_at      timestamptz,
  PRIMARY KEY (request_id, pointer),
  CHECK ((accepted_version IS NULL) = (accepted_at IS NULL))
);

CREATE TABLE estimate.request_estimator (
  request_id  uuid        NOT NULL REFERENCES estimate.request (id),
  bu_id       uuid        NOT NULL,
  user_id     uuid        NOT NULL REFERENCES iam.app_user (id),
  added_by    uuid        NOT NULL REFERENCES iam.app_user (id),
  added_at    timestamptz NOT NULL DEFAULT now(),
  removed_at  timestamptz,
  finished_at timestamptz,
  PRIMARY KEY (request_id, user_id)
);
CREATE INDEX request_estimator_user ON estimate.request_estimator (user_id) WHERE removed_at IS NULL;

CREATE TABLE estimate.request_reference (
  request_id uuid    NOT NULL REFERENCES estimate.request (id),
  bu_id      uuid    NOT NULL,
  entry_id   uuid    NOT NULL REFERENCES risk.library_entry (id),
  version    integer NOT NULL CHECK (version >= 1),
  digest     text    NOT NULL,
  document   bytea   NOT NULL,
  PRIMARY KEY (request_id, entry_id)
);

-- Answers: one row per revision (design §3.3), reached only through
-- estimate_definer's functions.
CREATE TABLE estimate.answer (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id  uuid        NOT NULL,
  bu_id       uuid        NOT NULL REFERENCES iam.bu (id),
  estimator   uuid        NOT NULL REFERENCES iam.app_user (id),
  pointer     text        NOT NULL,
  revision    integer     NOT NULL CHECK (revision BETWEEN 1 AND 100),
  state       text        NOT NULL CHECK (state IN ('draft', 'submitted')),
  estimate    jsonb       CHECK (jsonb_typeof(estimate) = 'object'),
  declined    text        CHECK (char_length(btrim(declined)) BETWEEN 1 AND 1000),
  calibration jsonb       NOT NULL CHECK (jsonb_typeof(calibration) = 'object'),
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (request_id, pointer) REFERENCES estimate.request_factor (request_id, pointer),
  FOREIGN KEY (request_id, estimator) REFERENCES estimate.request_estimator (request_id, user_id),
  UNIQUE (request_id, estimator, pointer, revision),
  CHECK (num_nonnulls(estimate, declined) = 1)
);

-- Notices for F-009 (design §6.7).
CREATE TABLE estimate.notice_outbox (
  id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind         text        NOT NULL CHECK (kind IN ('assigned', 'reminder', 'finished', 'closed')),
  user_id      uuid        NOT NULL REFERENCES iam.app_user (id),
  request_id   uuid        NOT NULL REFERENCES estimate.request (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE INDEX notice_outbox_pending ON estimate.notice_outbox (id) WHERE delivered_at IS NULL;

-- Calibration (design §3.6, §6.5, §6.6): installation-wide question sets,
-- and each person's exercises and scores. Not BU-owned.
CREATE TABLE estimate.question_set (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  origin      text        NOT NULL CHECK (origin IN ('shipped', 'custom')),
  name        text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 10000),
  status      text        NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
  release     text        CHECK (char_length(release) BETWEEN 1 AND 100),
  created_by  uuid        REFERENCES iam.app_user (id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  CHECK ((origin = 'shipped') = (release IS NOT NULL)),
  CHECK ((origin = 'custom') = (created_by IS NOT NULL))
);

CREATE TABLE estimate.question (
  id         uuid        NOT NULL,
  version    integer     NOT NULL CHECK (version >= 1),
  set_id     uuid        NOT NULL REFERENCES estimate.question_set (id),
  kind       text        NOT NULL CHECK (kind IN ('range', 'binary')),
  text       text        NOT NULL CHECK (char_length(btrim(text)) BETWEEN 1 AND 1000),
  unit       text        CHECK (char_length(btrim(unit)) BETWEEN 1 AND 100),
  answer     text        NOT NULL,
  source     text        NOT NULL CHECK (char_length(btrim(source)) BETWEEN 1 AND 1000),
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, version),
  CHECK (CASE kind WHEN 'binary' THEN answer IN ('true', 'false') AND unit IS NULL
                   ELSE answer ~ '^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$' AND unit IS NOT NULL END)
);
CREATE INDEX question_by_set ON estimate.question (set_id);

CREATE TABLE estimate.exercise (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid        NOT NULL REFERENCES iam.app_user (id),
  started_at   timestamptz NOT NULL DEFAULT now(),
  submitted_at timestamptz,
  questions    jsonb       NOT NULL CHECK (jsonb_typeof(questions) = 'array' AND jsonb_array_length(questions) BETWEEN 10 AND 50)
);
CREATE INDEX exercise_user ON estimate.exercise (user_id, started_at);

CREATE TABLE estimate.exercise_answer (
  exercise_id uuid    NOT NULL REFERENCES estimate.exercise (id) ON DELETE CASCADE,
  question_id uuid    NOT NULL,
  version     integer NOT NULL,
  low         numeric,
  high        numeric,
  choice      boolean,
  confidence  numeric CHECK (confidence >= 0.5 AND confidence <= 1),
  correct     boolean NOT NULL,
  PRIMARY KEY (exercise_id, question_id),
  FOREIGN KEY (question_id, version) REFERENCES estimate.question (id, version),
  CHECK ((low IS NOT NULL AND high IS NOT NULL AND low <= high AND choice IS NULL AND confidence IS NULL)
      OR (low IS NULL AND high IS NULL AND choice IS NOT NULL AND confidence IS NOT NULL))
);

CREATE TABLE estimate.score (
  user_id     uuid        NOT NULL REFERENCES iam.app_user (id),
  computed_at timestamptz NOT NULL DEFAULT now(),
  score       jsonb       NOT NULL CHECK (jsonb_typeof(score) = 'object'),
  PRIMARY KEY (user_id, computed_at)
);

-- BU ownership and the sanctioned definer access.
SELECT authz.apply_bu_rls('estimate.request', 'scenario');
SELECT authz.apply_bu_rls('estimate.request_factor', 'scenario');
SELECT authz.apply_bu_rls('estimate.request_estimator', 'scenario');
SELECT authz.apply_bu_rls('estimate.request_reference', 'scenario');
SELECT authz.allow_definer('estimate.request', 'estimate_definer');
SELECT authz.allow_definer('estimate.request_factor', 'estimate_definer');
SELECT authz.allow_definer('estimate.request_estimator', 'estimate_definer');
SELECT authz.allow_definer('estimate.request_reference', 'estimate_definer');

-- Privileges -----------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA estimate FROM PUBLIC;
GRANT SELECT ON estimate.request, estimate.request_factor, estimate.request_estimator, estimate.request_reference TO app_rw;
GRANT INSERT (id, bu_id, scenario_id, scenario_version, title, instructions, confidence, due_at, context) ON estimate.request TO app_rw;
GRANT INSERT (request_id, pointer, factor, unit, definition) ON estimate.request_factor TO app_rw;
GRANT INSERT (request_id, user_id) ON estimate.request_estimator TO app_rw;
GRANT INSERT (request_id, entry_id, version) ON estimate.request_reference TO app_rw;
GRANT SELECT, INSERT ON estimate.answer TO estimate_definer;
GRANT SELECT, INSERT, UPDATE (delivered_at) ON estimate.notice_outbox TO estimate_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON estimate.question_set, estimate.question, estimate.exercise, estimate.exercise_answer, estimate.score TO estimate_definer;

-- estimate_definer runs under RLS with the caller's context on the request
-- tables (and risk's): it needs the policies' functions, the context, the
-- permission check and the secrets check.
GRANT USAGE ON SCHEMA authz, iam, risk, audit TO estimate_definer;
GRANT SELECT ON risk.scenario, risk.library_entry, risk.library_version TO estimate_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO estimate_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text),
  authz.scope_hides(text, text), authz.inherited_bus(text) TO estimate_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.looks_secret(text) TO estimate_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Triggers ---------------------------------------------------------------------

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- The signed context's user, or an error: every write is attributed.
CREATE FUNCTION estimate.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'estimate data needs a valid signed database context' USING ERRCODE = 'PF022';
  END IF;
  RETURN u;
END $$;

-- A new request: its creator, its scenario's BU, an existing version, a
-- due date ahead, at most 20 open requests per scenario (design §4.4).
CREATE FUNCTION estimate.request_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s record;
BEGIN
  NEW.created_by := estimate.actor();
  NEW.created_at := now();
  NEW.status := 'open';
  NEW.affected := NULL;
  NEW.cancel_reason := NULL;
  NEW.ended_at := NULL;
  -- Under the caller's RLS: a scenario they cannot see is not found.
  SELECT sc.bu_id, sc.current_version, sc.archived_at INTO s FROM risk.scenario sc WHERE sc.id = NEW.scenario_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate.request: no such scenario %', NEW.scenario_id USING ERRCODE = 'PF022';
  END IF;
  IF s.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'estimate.request: the scenario is archived' USING ERRCODE = 'PF022';
  END IF;
  IF NEW.scenario_version > s.current_version THEN
    RAISE EXCEPTION 'estimate.request: the scenario has no version %', NEW.scenario_version USING ERRCODE = 'PF022';
  END IF;
  IF NEW.bu_id IS DISTINCT FROM s.bu_id THEN
    RAISE EXCEPTION 'estimate.request: a request belongs to its scenario''s business unit' USING ERRCODE = 'PF022';
  END IF;
  IF NEW.due_at <= now() THEN
    RAISE EXCEPTION 'estimate.request: the due date must be ahead' USING ERRCODE = 'PF022';
  END IF;
  IF (SELECT count(*) FROM estimate.request r WHERE r.scenario_id = NEW.scenario_id AND r.status = 'open') >= 20 THEN
    RAISE EXCEPTION 'estimate.request: at most 20 open requests per scenario' USING ERRCODE = 'PF022';
  END IF;
  RETURN NEW;
END $$;

-- A request's factors, estimators and references take its BU. Factors and
-- references are added only in the request's creating transaction;
-- estimators while it is open. Limits: 60 factors, 50 estimators, 20
-- references (design §4.4).
CREATE FUNCTION estimate.child_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n integer; v record;
BEGIN
  SELECT q.bu_id, q.status, q.created_at INTO r FROM estimate.request q WHERE q.id = NEW.request_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate.%: no such request %', TG_TABLE_NAME, NEW.request_id USING ERRCODE = 'PF022';
  END IF;
  NEW.bu_id := r.bu_id;
  CASE TG_TABLE_NAME
  WHEN 'request_factor' THEN
    IF r.created_at <> now() THEN
      RAISE EXCEPTION 'estimate.request_factor: factors are named when the request is created' USING ERRCODE = 'PF022';
    END IF;
    NEW.accepted_version := NULL;
    NEW.accepted_at := NULL;
    SELECT count(*) INTO n FROM estimate.request_factor f WHERE f.request_id = NEW.request_id;
    IF n >= 60 THEN RAISE EXCEPTION 'estimate.request_factor: at most 60 factors' USING ERRCODE = 'PF022'; END IF;
  WHEN 'request_estimator' THEN
    IF r.status <> 'open' THEN
      RAISE EXCEPTION 'estimate.request_estimator: the request is %', r.status USING ERRCODE = 'PF022';
    END IF;
    NEW.added_by := estimate.actor();
    NEW.added_at := now();
    NEW.removed_at := NULL;
    NEW.finished_at := NULL;
    IF NOT iam.holds_permission(NEW.user_id, 'estimate.submit', r.bu_id) THEN
      RAISE EXCEPTION 'estimate.request_estimator: the estimator does not hold estimate.submit at the business unit' USING ERRCODE = 'PF022';
    END IF;
    SELECT count(*) INTO n FROM estimate.request_estimator e WHERE e.request_id = NEW.request_id;
    IF n >= 50 THEN RAISE EXCEPTION 'estimate.request_estimator: at most 50 estimators' USING ERRCODE = 'PF022'; END IF;
  WHEN 'request_reference' THEN
    IF r.created_at <> now() THEN
      RAISE EXCEPTION 'estimate.request_reference: references are attached when the request is created' USING ERRCODE = 'PF022';
    END IF;
    -- The pinned version, as the caller sees it (inherited read included),
    -- copied as F-003 copies pinned versions.
    SELECT lv.digest, lv.document INTO v FROM risk.library_version lv JOIN risk.library_entry e ON e.id = lv.entry_id
    WHERE lv.entry_id = NEW.entry_id AND lv.version = NEW.version AND e.kind = 'reference_class';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'estimate.request_reference: reference class % version % does not exist or is not visible', NEW.entry_id, NEW.version
        USING ERRCODE = 'PF022';
    END IF;
    NEW.digest := v.digest;
    NEW.document := v.document;
    SELECT count(*) INTO n FROM estimate.request_reference x WHERE x.request_id = NEW.request_id;
    IF n >= 20 THEN RAISE EXCEPTION 'estimate.request_reference: at most 20 references' USING ERRCODE = 'PF022'; END IF;
  END CASE;
  RETURN NEW;
END $$;

-- Answers, references and question versions never change; answers are never
-- deleted (PF021).
CREATE FUNCTION estimate.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'estimate.%: % refused; it is append-only', TG_TABLE_NAME, TG_OP USING ERRCODE = 'PF021';
END $$;

-- A question version changes only to be retired.
CREATE FUNCTION estimate.question_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM (to_jsonb(OLD) - 'retired_at') OR OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'estimate.question: a question version changes only to be retired, once' USING ERRCODE = 'PF021';
  END IF;
  RETURN NEW;
END $$;

-- A custom question set holds at most 1,000 questions (design §4.4).
CREATE FUNCTION estimate.question_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (SELECT count(DISTINCT q.id) FROM estimate.question q WHERE q.set_id = NEW.set_id AND q.id <> NEW.id) >= 1000 THEN
    RAISE EXCEPTION 'estimate.question: at most 1000 questions in a set' USING ERRCODE = 'PF022';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION estimate.actor(), estimate.request_before_insert(), estimate.child_before_insert(), estimate.refuse_change(),
  estimate.question_before_update(), estimate.question_before_insert() FROM PUBLIC;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION estimate.request_before_insert(), estimate.child_before_insert(), estimate.refuse_change(),
  estimate.question_before_update(), estimate.question_before_insert() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;

CREATE TRIGGER request_before_insert BEFORE INSERT ON estimate.request FOR EACH ROW EXECUTE FUNCTION estimate.request_before_insert();
CREATE TRIGGER child_before_insert BEFORE INSERT ON estimate.request_factor FOR EACH ROW EXECUTE FUNCTION estimate.child_before_insert();
CREATE TRIGGER child_before_insert BEFORE INSERT ON estimate.request_estimator FOR EACH ROW EXECUTE FUNCTION estimate.child_before_insert();
CREATE TRIGGER child_before_insert BEFORE INSERT ON estimate.request_reference FOR EACH ROW EXECUTE FUNCTION estimate.child_before_insert();
CREATE TRIGGER refuse_change BEFORE UPDATE OR DELETE ON estimate.answer FOR EACH ROW EXECUTE FUNCTION estimate.refuse_change();
CREATE TRIGGER refuse_change BEFORE UPDATE OR DELETE ON estimate.request_reference FOR EACH ROW EXECUTE FUNCTION estimate.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON estimate.request FOR EACH ROW EXECUTE FUNCTION estimate.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON estimate.request_factor FOR EACH ROW EXECUTE FUNCTION estimate.refuse_change();
CREATE TRIGGER refuse_delete BEFORE DELETE ON estimate.request_estimator FOR EACH ROW EXECUTE FUNCTION estimate.refuse_change();
CREATE TRIGGER question_before_update BEFORE UPDATE ON estimate.question FOR EACH ROW EXECUTE FUNCTION estimate.question_before_update();
CREATE TRIGGER question_before_insert BEFORE INSERT ON estimate.question FOR EACH ROW EXECUTE FUNCTION estimate.question_before_insert();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON estimate.answer FOR EACH STATEMENT EXECUTE FUNCTION estimate.refuse_change();

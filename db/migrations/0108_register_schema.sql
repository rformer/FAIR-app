-- F-007 T-03 (F-007-AC-01 to AC-06, AC-15, AC-17, AC-21; design §3, §5.1):
-- the register schema. Risks and their treatment are heads with
-- append-only versions; each version holds one canonical JSON document
-- (internal/risk/canon) and its SHA-256 digest, as F-003's documents do.
--
--   * register.risk (type 'register'): app_rw inserts (id, bu_id); the
--     version trigger keeps its summary columns (state, title, owner,
--     category) and current_version. exposure_aggregate_id is set by the
--     register's exposure functions (T-05).
--   * register.risk_version: app_rw inserts (risk_id, version, document,
--     digest, change_note). The trigger takes bu_id from the head and the
--     author from the signed context, requires version = current + 1 and
--     the digest to match, and checks the document (register.check_risk):
--       - schema_version 1; title (1 to 200); description (to 5,000);
--         category (an existing category; a newly chosen one not archived);
--       - owner: a user who holds register.view at the risk's business unit,
--         read from their materialized scope (authz.user_scope: what RLS
--         enforces, groups, mappings and restricted BUs included);
--       - state open or closed, close_reason when closed only;
--       - scenarios (at most 200, each once): visible to the author (scenario
--         read scope) and in the risk's subtree; a pin, if any, is a
--         succeeded run of that scenario the author sees, with the
--         register's iteration count (register.iterations, in force), and
--         one of its control sets; a set other than the run's current one
--         needs a reason (OQ2);
--       - a closed risk changes only by reopening, unchanged otherwise, and
--         closing changes nothing else (AC-04).
--     Refusals are PF026, problems by JSON pointer in the DETAIL.
--   * register.risk_scenario: the current links, kept by the version
--     trigger; UNIQUE (scenario_id) WHERE open: one open risk per scenario
--     (AC-02). Closing a risk frees its scenarios.
--   * register.treatment (type 'treatment', one per risk, its risk's BU)
--     and register.treatment_version, checked by register.check_treatment:
--     decision (mitigate, transfer, avoid, accept or none) with a rationale;
--     targets (for mitigate: a control set of each linked scenario's latest
--     version); actions (at most 200: id, title, owner, due date, state,
--     cancel_reason when cancelled). A closed risk's treatment does not
--     change.
--   * Versions are append-only for every role (PF025); heads are never
--     deleted, and change only through the version triggers (and, from T-04
--     and T-05, the register's functions).
--   * register.category: not BU-owned; the default list; changed by
--     register.edit at the root (T-04).
--
-- The trigger and check functions are SECURITY DEFINER, owned by
-- register_definer (a bootstrap role): they write what app_rw cannot (head
-- summaries, links) and read what the checks need. RLS applies to them
-- under the caller's context, except where allow_definer admits them.

CREATE SCHEMA register;
REVOKE ALL ON SCHEMA register FROM PUBLIC;
GRANT USAGE ON SCHEMA register TO app_rw, register_definer;

-- Categories (OQ3) ------------------------------------------------------------

CREATE TABLE register.category (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  archived_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX category_name ON register.category (lower(name)) WHERE archived_at IS NULL;
INSERT INTO register.category (name) VALUES ('Cyber'), ('Operational'), ('Third party'), ('Data privacy'), ('Business continuity'),
  ('Regulatory'), ('Fraud');
GRANT SELECT ON register.category TO app_rw, register_definer;

-- Risks -----------------------------------------------------------------------

CREATE TABLE register.risk (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id                 uuid        NOT NULL,
  current_version       integer     NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  state                 text        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
  title                 text,
  owner                 uuid,
  category_id           uuid        REFERENCES register.category (id),
  exposure_aggregate_id uuid        REFERENCES analysis.aggregate (id),
  created_at            timestamptz NOT NULL DEFAULT now(),
  created_by            uuid        NOT NULL,
  seq                   bigint      GENERATED ALWAYS AS IDENTITY UNIQUE
);
CREATE INDEX risk_bu ON register.risk (bu_id, seq);
CREATE INDEX risk_owner ON register.risk (owner);

CREATE TABLE register.risk_version (
  risk_id     uuid        NOT NULL REFERENCES register.risk (id),
  version     integer     NOT NULL CHECK (version >= 1),
  bu_id       uuid        NOT NULL,
  document    bytea       NOT NULL CHECK (length(document) <= 262144),
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  change_note text        NOT NULL CHECK (char_length(change_note) BETWEEN 1 AND 1000),
  author      uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (risk_id, version)
);

-- The current links: one row per linked scenario, open while the risk is.
CREATE TABLE register.risk_scenario (
  risk_id        uuid    NOT NULL REFERENCES register.risk (id),
  scenario_id    uuid    NOT NULL REFERENCES risk.scenario (id),
  bu_id          uuid    NOT NULL,
  open           boolean NOT NULL,
  run_id         uuid    REFERENCES analysis.run (id),
  control_set    text,
  pinned_version integer,
  PRIMARY KEY (risk_id, scenario_id),
  CHECK ((run_id IS NULL) = (control_set IS NULL) AND (run_id IS NULL) = (pinned_version IS NULL))
);
CREATE UNIQUE INDEX risk_scenario_open ON register.risk_scenario (scenario_id) WHERE open;
CREATE INDEX risk_scenario_run ON register.risk_scenario (run_id);

-- Treatment -------------------------------------------------------------------

CREATE TABLE register.treatment (
  risk_id         uuid        PRIMARY KEY REFERENCES register.risk (id),
  bu_id           uuid        NOT NULL,
  current_version integer     NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  decision        text        CHECK (decision IN ('mitigate', 'transfer', 'avoid', 'accept')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      uuid        NOT NULL
);
CREATE TABLE register.treatment_version (
  risk_id     uuid        NOT NULL REFERENCES register.treatment (risk_id),
  version     integer     NOT NULL CHECK (version >= 1),
  bu_id       uuid        NOT NULL,
  document    bytea       NOT NULL CHECK (length(document) <= 262144),
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  change_note text        NOT NULL CHECK (char_length(change_note) BETWEEN 1 AND 1000),
  author      uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (risk_id, version)
);

SELECT authz.apply_bu_rls('register.risk', 'register');
SELECT authz.apply_bu_rls('register.risk_version', 'register');
SELECT authz.apply_bu_rls('register.risk_scenario', 'register');
SELECT authz.apply_bu_rls('register.treatment', 'treatment');
SELECT authz.apply_bu_rls('register.treatment_version', 'treatment');
-- The version triggers keep the heads (ADR-007 amendment 3: the definer
-- reads and updates them whatever the caller sees). Links are written in
-- the risk's BU under the caller's own write scope, so the definer needs no
-- such admission there; the one-open-risk index sees every row anyway.
SELECT authz.allow_definer('register.risk', 'register_definer');
SELECT authz.allow_definer('register.treatment', 'register_definer');

GRANT SELECT ON register.risk, register.risk_version, register.risk_scenario, register.treatment, register.treatment_version TO app_rw;
GRANT INSERT (id, bu_id) ON register.risk TO app_rw;
GRANT INSERT (risk_id, version, document, digest, change_note) ON register.risk_version TO app_rw;
GRANT INSERT (risk_id, bu_id) ON register.treatment TO app_rw;
GRANT INSERT (risk_id, version, document, digest, change_note) ON register.treatment_version TO app_rw;
GRANT UPDATE (current_version, state, title, owner, category_id) ON register.risk TO register_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON register.risk_scenario TO register_definer;
GRANT UPDATE (current_version, decision) ON register.treatment TO register_definer;
GRANT SELECT ON register.risk_version, register.treatment_version TO register_definer;

-- What the checks read.
GRANT USAGE ON SCHEMA authz, iam, risk, analysis TO register_definer;
GRANT SELECT ON risk.scenario, risk.scenario_version TO register_definer;
GRANT SELECT ON analysis.run TO register_definer;
GRANT SELECT ON iam.bu_closure, iam.app_user TO register_definer;
GRANT SELECT ON authz.user_scope TO register_definer;
GRANT EXECUTE ON FUNCTION iam.instance_setting(text) TO register_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text),
  authz.scope_hides(text, text), authz.inherited_bus(text) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

-- The signed context's user, or an error: every write is attributed.
CREATE FUNCTION register.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'register data needs a valid signed database context' USING ERRCODE = 'PF026';
  END IF;
  RETURN u;
END $$;

-- A problem: "pointer: message".
CREATE FUNCTION register.p(ptr text, msg text) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT ARRAY[coalesce(nullif(ptr, ''), '/') || ': ' || msg] $$;

-- Keys of o beyond allowed.
CREATE FUNCTION register.unknown(o jsonb, ptr text, allowed text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(array_agg(ptr || '/' || k || ': is not a known field' ORDER BY k), '{}') FROM jsonb_object_keys(o) k WHERE NOT k = ANY (allowed)
$$;

-- A text field: a string of 1 to max characters (or absent/null when not required).
CREATE FUNCTION register.text(v jsonb, ptr text, max integer, required boolean) RETURNS text[]
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF v IS NULL OR v = 'null'::jsonb THEN
    RETURN CASE WHEN required THEN register.p(ptr, 'is required') ELSE '{}' END;
  END IF;
  IF jsonb_typeof(v) <> 'string' THEN
    RETURN register.p(ptr, 'is not text');
  END IF;
  IF char_length(btrim(v #>> '{}')) = 0 OR char_length(v #>> '{}') > max THEN
    RETURN register.p(ptr, format('is 1 to %s characters', max));
  END IF;
  RETURN '{}';
END $$;

CREATE FUNCTION register.is_uuid(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_typeof(v) = 'string' AND (v #>> '{}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
$$;

-- A calendar date written YYYY-MM-DD.
CREATE FUNCTION register.is_date(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF jsonb_typeof(v) IS DISTINCT FROM 'string' OR (v #>> '{}') !~ '^\d{4}-\d{2}-\d{2}$' THEN
    RETURN false;
  END IF;
  RETURN to_char(make_date(substr(v #>> '{}', 1, 4)::int, substr(v #>> '{}', 6, 2)::int, substr(v #>> '{}', 9, 2)::int), 'YYYY-MM-DD') = (v #>> '{}');
EXCEPTION WHEN others THEN
  RETURN false;
END $$;

-- The register's iteration count in force (register.iterations).
CREATE FUNCTION register.iterations() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT (iam.instance_setting('register.iterations') #>> '{}')::integer
$$;

-- A risk document's problems (design §3.1); prev is the previous version's
-- document (null for version 1).
CREATE FUNCTION register.check_risk(d jsonb, bu uuid, prev jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  out text[] := '{}';
  s jsonb;
  i integer := 0;
  ptr text;
  seen uuid[] := '{}';
  sid uuid;
  sc record;
  r record;
  iters integer;
  closed boolean;
BEGIN
  IF jsonb_typeof(d) IS DISTINCT FROM 'object' THEN
    RETURN register.p('', 'is not a JSON object');
  END IF;
  out := out || register.unknown(d, '', ARRAY['schema_version', 'title', 'description', 'owner', 'category', 'state', 'close_reason', 'scenarios']);
  IF d -> 'schema_version' IS DISTINCT FROM '1'::jsonb THEN
    out := out || register.p('/schema_version', 'is 1');
  END IF;
  out := out || register.text(d -> 'title', '/title', 200, true) || register.text(d -> 'description', '/description', 5000, false);
  -- The owner: a user who sees the risk (register.view at its BU, by
  -- their scope).
  IF NOT register.is_uuid(d -> 'owner') THEN
    out := out || register.p('/owner', 'is a user id');
  ELSIF NOT EXISTS (SELECT 1 FROM authz.user_scope u WHERE u.user_id = (d ->> 'owner')::uuid AND (u.read_bus -> 'register') ? bu::text) THEN
    out := out || register.p('/owner', 'is a user who holds register.view at the risk''s business unit');
  END IF;
  -- The category: an existing one; a newly chosen one not archived.
  IF d -> 'category' IS NOT NULL AND d -> 'category' <> 'null'::jsonb THEN
    IF NOT register.is_uuid(d -> 'category') THEN
      out := out || register.p('/category', 'is a category id');
    ELSIF NOT EXISTS (SELECT 1 FROM register.category c WHERE c.id = (d ->> 'category')::uuid
                        AND (c.archived_at IS NULL OR (prev ->> 'category') IS NOT DISTINCT FROM (d ->> 'category'))) THEN
      out := out || register.p('/category', 'is not a category in use');
    END IF;
  END IF;
  -- State.
  IF NOT coalesce(d ->> 'state' IN ('open', 'closed'), false) THEN
    out := out || register.p('/state', 'is open or closed');
  END IF;
  closed := d ->> 'state' = 'closed';
  IF closed THEN
    out := out || register.text(d -> 'close_reason', '/close_reason', 1000, true);
  ELSIF d ? 'close_reason' AND d -> 'close_reason' <> 'null'::jsonb THEN
    out := out || register.p('/close_reason', 'is given only when the risk is closed');
  END IF;
  IF prev IS NOT NULL THEN
    IF prev ->> 'state' = 'closed' AND (d ->> 'state' <> 'open' OR (d - 'state' - 'close_reason') IS DISTINCT FROM (prev - 'state' - 'close_reason')) THEN
      out := out || register.p('/state', 'a closed risk changes only by being reopened, as it was');
    ELSIF prev ->> 'state' = 'open' AND closed AND (d - 'state' - 'close_reason') IS DISTINCT FROM (prev - 'state' - 'close_reason') THEN
      out := out || register.p('/state', 'closing a risk changes nothing else');
    END IF;
  END IF;
  -- Scenarios and pins.
  IF jsonb_typeof(d -> 'scenarios') IS DISTINCT FROM 'array' THEN
    RETURN out || register.p('/scenarios', 'is a list');
  END IF;
  IF jsonb_array_length(d -> 'scenarios') > 200 THEN
    RETURN out || register.p('/scenarios', 'has at most 200 scenarios');
  END IF;
  FOR s IN SELECT x FROM jsonb_array_elements(d -> 'scenarios') x LOOP
    ptr := '/scenarios/' || i;
    i := i + 1;
    IF jsonb_typeof(s) IS DISTINCT FROM 'object' THEN
      out := out || register.p(ptr, 'is an object');
      CONTINUE;
    END IF;
    out := out || register.unknown(s, ptr, ARRAY['scenario_id', 'pin']);
    IF NOT register.is_uuid(s -> 'scenario_id') THEN
      out := out || register.p(ptr || '/scenario_id', 'is a scenario id');
      CONTINUE;
    END IF;
    sid := (s ->> 'scenario_id')::uuid;
    IF sid = ANY (seen) THEN
      out := out || register.p(ptr || '/scenario_id', 'is linked twice');
      CONTINUE;
    END IF;
    seen := seen || sid;
    -- Visible to the author (the scenario read scope), in the risk's subtree.
    SELECT x.bu_id INTO sc FROM risk.scenario x WHERE x.id = sid AND x.bu_id = ANY (authz.visible_bus('scenario', 'read'));
    IF NOT FOUND THEN
      out := out || register.p(ptr || '/scenario_id', 'is not a scenario you can see');
      CONTINUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = bu AND c.descendant_id = sc.bu_id) THEN
      out := out || register.p(ptr || '/scenario_id', 'is outside the risk''s business unit');
      CONTINUE;
    END IF;
    IF s -> 'pin' IS NULL OR s -> 'pin' = 'null'::jsonb THEN
      CONTINUE;
    END IF;
    IF jsonb_typeof(s -> 'pin') <> 'object' THEN
      out := out || register.p(ptr || '/pin', 'is an object');
      CONTINUE;
    END IF;
    out := out || register.unknown(s -> 'pin', ptr || '/pin', ARRAY['run_id', 'control_set', 'reason']);
    IF NOT register.is_uuid(s -> 'pin' -> 'run_id') THEN
      out := out || register.p(ptr || '/pin/run_id', 'is a run id');
      CONTINUE;
    END IF;
    SELECT x.scenario_id, x.state, x.iterations, x.control_sets INTO r FROM analysis.run x
    WHERE x.id = (s -> 'pin' ->> 'run_id')::uuid AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'));
    IF NOT FOUND OR r.scenario_id <> sid THEN
      out := out || register.p(ptr || '/pin/run_id', 'is not a run of this scenario you can see');
      CONTINUE;
    END IF;
    IF r.state <> 'succeeded' THEN
      out := out || register.p(ptr || '/pin/run_id', 'is not a succeeded run');
    END IF;
    iters := register.iterations();
    IF iters IS NULL OR r.iterations <> iters THEN
      out := out || register.p(ptr || '/pin/run_id', format('has %s iterations; pinned runs have the register''s %s', r.iterations, coalesce(iters::text, '(unset)')));
    END IF;
    IF NOT coalesce((s -> 'pin' ->> 'control_set') = ANY (r.control_sets), false) THEN
      out := out || register.p(ptr || '/pin/control_set', 'is not a control set of the run');
    ELSIF (s -> 'pin' ->> 'control_set') <> r.control_sets[1] THEN
      out := out || register.text(s -> 'pin' -> 'reason', ptr || '/pin/reason', 1000, true);
    ELSE
      out := out || register.text(s -> 'pin' -> 'reason', ptr || '/pin/reason', 1000, false);
    END IF;
  END LOOP;
  RETURN out;
END $$;

-- A treatment document's problems (design §3.2) for risk.
CREATE FUNCTION register.check_treatment(d jsonb, risk uuid) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  out text[] := '{}';
  t jsonb;
  a jsonb;
  i integer := 0;
  ptr text;
  seen uuid[] := '{}';
  ids uuid[] := '{}';
  sid uuid;
BEGIN
  IF jsonb_typeof(d) IS DISTINCT FROM 'object' THEN
    RETURN register.p('', 'is not a JSON object');
  END IF;
  out := out || register.unknown(d, '', ARRAY['schema_version', 'decision', 'rationale', 'targets', 'actions']);
  IF d -> 'schema_version' IS DISTINCT FROM '1'::jsonb THEN
    out := out || register.p('/schema_version', 'is 1');
  END IF;
  IF d -> 'decision' IS NULL OR d -> 'decision' = 'null'::jsonb THEN
    out := out || register.text(d -> 'rationale', '/rationale', 5000, false);
  ELSIF NOT coalesce(d ->> 'decision' IN ('mitigate', 'transfer', 'avoid', 'accept'), false) THEN
    out := out || register.p('/decision', 'is mitigate, transfer, avoid or accept');
  ELSE
    out := out || register.text(d -> 'rationale', '/rationale', 5000, true);
  END IF;
  -- Targets: for mitigate, a control set of each linked scenario's latest version.
  IF d ? 'targets' AND d -> 'targets' <> '[]'::jsonb THEN
    IF d ->> 'decision' IS DISTINCT FROM 'mitigate' THEN
      out := out || register.p('/targets', 'are given only when the decision is mitigate');
    ELSIF jsonb_typeof(d -> 'targets') <> 'array' OR jsonb_array_length(d -> 'targets') > 200 THEN
      out := out || register.p('/targets', 'is a list of at most 200');
    ELSE
      FOR t IN SELECT x FROM jsonb_array_elements(d -> 'targets') x LOOP
        ptr := '/targets/' || i;
        i := i + 1;
        out := out || register.unknown(t, ptr, ARRAY['scenario_id', 'control_set']);
        IF NOT register.is_uuid(t -> 'scenario_id') THEN
          out := out || register.p(ptr || '/scenario_id', 'is a scenario id');
          CONTINUE;
        END IF;
        sid := (t ->> 'scenario_id')::uuid;
        IF sid = ANY (seen) THEN
          out := out || register.p(ptr || '/scenario_id', 'has one target');
          CONTINUE;
        END IF;
        seen := seen || sid;
        IF NOT EXISTS (SELECT 1 FROM register.risk_scenario l WHERE l.risk_id = risk AND l.scenario_id = sid AND l.open) THEN
          out := out || register.p(ptr || '/scenario_id', 'is not a scenario of the risk');
        ELSIF NOT EXISTS (SELECT 1 FROM risk.scenario s JOIN risk.scenario_version v ON v.scenario_id = s.id AND v.version = s.current_version,
                            jsonb_array_elements(convert_from(v.document, 'UTF8')::jsonb -> 'control_sets') cs
                          WHERE s.id = sid AND cs ->> 'name' = t ->> 'control_set') THEN
          out := out || register.p(ptr || '/control_set', 'is not a control set of the scenario''s latest version');
        END IF;
      END LOOP;
    END IF;
  END IF;
  -- Actions.
  IF d ? 'actions' THEN
    IF jsonb_typeof(d -> 'actions') <> 'array' OR jsonb_array_length(d -> 'actions') > 200 THEN
      RETURN out || register.p('/actions', 'is a list of at most 200');
    END IF;
    i := 0;
    FOR a IN SELECT x FROM jsonb_array_elements(d -> 'actions') x LOOP
      ptr := '/actions/' || i;
      i := i + 1;
      IF jsonb_typeof(a) IS DISTINCT FROM 'object' THEN
        out := out || register.p(ptr, 'is an object');
        CONTINUE;
      END IF;
      out := out || register.unknown(a, ptr, ARRAY['id', 'title', 'owner', 'due', 'state', 'cancel_reason']);
      IF NOT register.is_uuid(a -> 'id') THEN
        out := out || register.p(ptr || '/id', 'is an action id');
      ELSIF (a ->> 'id')::uuid = ANY (ids) THEN
        out := out || register.p(ptr || '/id', 'is used twice');
      ELSE
        ids := ids || (a ->> 'id')::uuid;
      END IF;
      out := out || register.text(a -> 'title', ptr || '/title', 200, true);
      IF NOT register.is_uuid(a -> 'owner') OR NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = (a ->> 'owner')::uuid) THEN
        out := out || register.p(ptr || '/owner', 'is a user');
      END IF;
      IF NOT register.is_date(a -> 'due') THEN
        out := out || register.p(ptr || '/due', 'is a date (YYYY-MM-DD)');
      END IF;
      IF NOT coalesce(a ->> 'state' IN ('planned', 'in_progress', 'done', 'cancelled'), false) THEN
        out := out || register.p(ptr || '/state', 'is planned, in_progress, done or cancelled');
      ELSIF a ->> 'state' = 'cancelled' THEN
        out := out || register.text(a -> 'cancel_reason', ptr || '/cancel_reason', 1000, true);
      ELSIF a ? 'cancel_reason' AND a -> 'cancel_reason' <> 'null'::jsonb THEN
        out := out || register.p(ptr || '/cancel_reason', 'is given only when the action is cancelled');
      END IF;
    END LOOP;
  END IF;
  RETURN out;
END $$;

CREATE FUNCTION register.head_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  NEW.created_by := register.actor();
  NEW.created_at := now();
  NEW.current_version := 0;
  IF TG_TABLE_NAME = 'risk' THEN
    NEW.state := 'open';
    NEW.title := NULL; NEW.owner := NULL; NEW.category_id := NULL; NEW.exposure_aggregate_id := NULL;
  ELSE
    -- A treatment belongs to its risk's BU; one per risk.
    SELECT r.bu_id INTO NEW.bu_id FROM register.risk r WHERE r.id = NEW.risk_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'register.treatment: no such risk %', NEW.risk_id USING ERRCODE = 'PF026';
    END IF;
    NEW.decision := NULL;
  END IF;
  RETURN NEW;
END $$;

-- A risk's new version: checked, the head's summary and links kept.
CREATE FUNCTION register.risk_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  d jsonb;
  prev jsonb;
  problems text[];
  s jsonb;
  open boolean;
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
    BEGIN
      INSERT INTO register.risk_scenario AS l (risk_id, scenario_id, bu_id, open, run_id, control_set, pinned_version)
      VALUES (h.id, (s ->> 'scenario_id')::uuid, h.bu_id, open, (s -> 'pin' ->> 'run_id')::uuid, s -> 'pin' ->> 'control_set',
              CASE WHEN s -> 'pin' ->> 'run_id' IS NULL THEN NULL ELSE NEW.version END)
      ON CONFLICT (risk_id, scenario_id) DO UPDATE SET open = EXCLUDED.open, bu_id = EXCLUDED.bu_id, run_id = EXCLUDED.run_id,
        control_set = EXCLUDED.control_set,
        pinned_version = CASE WHEN EXCLUDED.run_id IS NULL THEN NULL
                              WHEN EXCLUDED.run_id IS NOT DISTINCT FROM l.run_id AND EXCLUDED.control_set IS NOT DISTINCT FROM l.control_set
                              THEN l.pinned_version ELSE NEW.version END;
    EXCEPTION WHEN unique_violation THEN
      RAISE EXCEPTION 'register.risk_version: a scenario is linked to another open risk' USING ERRCODE = 'PF026',
        DETAIL = '/scenarios: ' || (s ->> 'scenario_id') || ' is linked to another open risk', HINT = 'scenario_linked';
    END;
  END LOOP;
  RETURN NEW;
END $$;

-- A treatment's new version: checked against its risk, the head kept.
CREATE FUNCTION register.treatment_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.treatment;
  d jsonb;
  problems text[];
BEGIN
  NEW.author := register.actor();
  NEW.created_at := now();
  SELECT * INTO h FROM register.treatment x WHERE x.risk_id = NEW.risk_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register.treatment_version: no treatment for risk %', NEW.risk_id USING ERRCODE = 'PF026';
  END IF;
  IF (SELECT r.state FROM register.risk r WHERE r.id = NEW.risk_id) = 'closed' THEN
    RAISE EXCEPTION 'register.treatment_version: the risk is closed; reopen it to change its treatment' USING ERRCODE = 'PF026', HINT = 'closed';
  END IF;
  IF NEW.version IS DISTINCT FROM h.current_version + 1 THEN
    RAISE EXCEPTION 'register.treatment_version: version % is stale; the current version is %', NEW.version, h.current_version
      USING ERRCODE = 'PF026', HINT = 'stale_version';
  END IF;
  NEW.bu_id := h.bu_id;
  IF NEW.digest IS DISTINCT FROM encode(sha256(NEW.document), 'hex') THEN
    RAISE EXCEPTION 'register.treatment_version: the digest does not match the document' USING ERRCODE = 'PF026';
  END IF;
  BEGIN
    d := convert_from(NEW.document, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'register.treatment_version: the document is not JSON' USING ERRCODE = 'PF026', DETAIL = '/: is not JSON';
  END;
  problems := register.check_treatment(d, NEW.risk_id);
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'register.treatment_version: invalid treatment document' USING ERRCODE = 'PF026', DETAIL = array_to_string(problems, E'\n');
  END IF;
  UPDATE register.treatment x SET current_version = NEW.version, decision = d ->> 'decision' WHERE x.risk_id = h.risk_id;
  RETURN NEW;
END $$;

-- Versions never change; heads are never deleted (PF025).
CREATE FUNCTION register.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'register.%: % refused; register versions are append-only and risks are closed, never deleted', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'PF025';
END $$;

-- Heads and links change only through the register's functions.
CREATE FUNCTION register.definer_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_user <> 'register_definer' THEN
    RAISE EXCEPTION 'register.%: changed only by the register''s functions', TG_TABLE_NAME USING ERRCODE = 'PF025';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION register.actor(), register.p(text, text), register.unknown(jsonb, text, text[]), register.text(jsonb, text, integer, boolean),
  register.is_uuid(jsonb), register.is_date(jsonb), register.iterations(), register.check_risk(jsonb, uuid, jsonb), register.check_treatment(jsonb, uuid),
  register.head_before_insert(), register.risk_version_before_insert(), register.treatment_version_before_insert(), register.refuse_change(),
  register.definer_only() FROM PUBLIC;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION register.head_before_insert(), register.risk_version_before_insert(), register.treatment_version_before_insert(),
  register.refuse_change(), register.definer_only() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

CREATE TRIGGER head_before_insert BEFORE INSERT ON register.risk FOR EACH ROW EXECUTE FUNCTION register.head_before_insert();
CREATE TRIGGER head_before_insert BEFORE INSERT ON register.treatment FOR EACH ROW EXECUTE FUNCTION register.head_before_insert();
CREATE TRIGGER version_before_insert BEFORE INSERT ON register.risk_version FOR EACH ROW EXECUTE FUNCTION register.risk_version_before_insert();
CREATE TRIGGER version_before_insert BEFORE INSERT ON register.treatment_version FOR EACH ROW EXECUTE FUNCTION register.treatment_version_before_insert();
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['risk_version', 'treatment_version'] LOOP
    EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON register.%I FOR EACH ROW EXECUTE FUNCTION register.refuse_change()', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON register.%I FOR EACH STATEMENT EXECUTE FUNCTION register.refuse_change()', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['risk', 'treatment', 'category'] LOOP
    EXECUTE format('CREATE TRIGGER never_deleted BEFORE DELETE ON register.%I FOR EACH ROW EXECUTE FUNCTION register.refuse_change()', t);
    EXECUTE format('CREATE TRIGGER never_truncated BEFORE TRUNCATE ON register.%I FOR EACH STATEMENT EXECUTE FUNCTION register.refuse_change()', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['risk', 'treatment'] LOOP
    EXECUTE format('CREATE TRIGGER definer_only BEFORE UPDATE ON register.%I FOR EACH ROW EXECUTE FUNCTION register.definer_only()', t);
  END LOOP;
  EXECUTE 'CREATE TRIGGER definer_only BEFORE INSERT OR UPDATE OR DELETE ON register.risk_scenario FOR EACH ROW EXECUTE FUNCTION register.definer_only()';
END $$;

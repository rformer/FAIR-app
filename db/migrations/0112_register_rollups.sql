-- F-007 T-07 (F-007-AC-11 to AC-14; design §3.4, §5.2): business unit
-- roll-ups.
--
--   * register.request_rollup(bu), for a holder of register.view at bu,
--     plans and requests the whole roll-up in the requester's transaction
--     (decided 2026-11-14), so every F-005 check runs under their signed
--     context:
--       - register.rollup_plan(bu): over authz.rollup_coverage('register',
--         bu), the open risks of the full BUs whose exposure is current and
--         whose pinned results (or exposure aggregate, with every leaf) the
--         requester sees, at the register's iteration count; the others
--         are counted by reason (stale, unquantified, computing,
--         not_visible, other_iterations, outside); excluded BUs counted;
--         aggregate-only BUs contribute one mean total through
--         register.rollup_means, owned by rollup_definer (totals, never
--         rows); a digest of what it includes, for staleness (AC-12).
--       - Nesting by BU (design §3.4): each risk's exposure sits at its
--         own BU (the run's or the exposure aggregate's); bottom up, a BU
--         the requester reads analyses at, with two or more members, gets
--         a node: an aggregate with purpose 'rollup' (split into parts of
--         at most 200); otherwise its members pass to its parent. Nodes
--         are keyed by a digest of their BU, iterations and members
--         (register.rollup_node) and reused unless failed.
--       - A node may have member aggregates still queued (purpose 'rollup'
--         only); the aggregate worker waits for them
--         (analysis.members_ready) and fails a node whose member failed.
--     Limits (OQ5): one queued roll-up per BU and requester (rollup_running),
--     one requested per BU per minute (rollup_rate), 2,000 risks
--     (rollup_too_large); PF026 with the hint.
--   * register.rollup: the record (requester, root, what it includes, what
--     it leaves out, the aggregate-only total, the plan's digest), shown to
--     its requester alone (decided 2026-11-14): a RESTRICTIVE select
--     (ADR-007 amendment 4) on register.is_mine(requested_by). Written by
--     register_definer (amendment 5); when its root aggregate finishes, a
--     trigger records the result (its summary copied) and the event.
--   * register.exposure_status gains register.status_of (no visibility
--     check), which the roll-up functions share.
--   * register.exposure_value(risk, path): a risk's exposure summary value
--     as the caller sees it, for the list's exposure sort (AC-14, AC-19).

-- Roll-up records -----------------------------------------------------------

CREATE TABLE register.rollup (
  id                uuid        PRIMARY KEY,
  bu_id             uuid        NOT NULL,
  requested_by      uuid        NOT NULL REFERENCES iam.app_user (id),
  requested_at      timestamptz NOT NULL DEFAULT now(),
  state             text        NOT NULL CHECK (state IN ('queued', 'succeeded', 'failed')),
  finished_at       timestamptz,
  failure           text,
  root_aggregate_id uuid        REFERENCES analysis.aggregate (id),
  root_run_id       uuid        REFERENCES analysis.run (id),
  root_control_set  text,
  summary           jsonb,
  digest            text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  included          jsonb       NOT NULL CHECK (jsonb_typeof(included) = 'array'),
  left_out          jsonb       NOT NULL CHECK (jsonb_typeof(left_out) = 'object'),
  excluded_bus      integer     NOT NULL,
  aggregate_only    jsonb,
  nodes             integer     NOT NULL,
  seq               bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  CHECK ((state = 'queued') = (finished_at IS NULL)),
  CHECK ((state = 'failed') = (failure IS NOT NULL))
);
CREATE INDEX rollup_bu ON register.rollup (bu_id, requested_at DESC);
CREATE INDEX rollup_root ON register.rollup (root_aggregate_id) WHERE state = 'queued';
SELECT authz.apply_bu_rls('register.rollup', 'register');
SELECT authz.allow_definer('register.rollup', 'register_definer');
SELECT authz.allow_definer_insert('register.rollup', 'register_definer');
GRANT SELECT ON register.rollup TO app_rw;
GRANT INSERT ON register.rollup TO register_definer;

-- Nodes by digest, for reuse; the register's functions alone.
CREATE TABLE register.rollup_node (
  digest       text        PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
  aggregate_id uuid        NOT NULL REFERENCES analysis.aggregate (id),
  created_at   timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON register.rollup_node FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON register.rollup_node TO register_definer;

GRANT SELECT ON analysis.result TO register_definer;
GRANT INSERT ON iam.event_outbox TO register_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO register_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.rollup_coverage(text, uuid) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Analysis: nodes with members still queued; reading an exposure ---------------

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

-- As 0107, but a roll-up node's member aggregates may still be queued or
-- running: the worker waits for them (analysis.members_ready).
CREATE OR REPLACE FUNCTION analysis.member_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record; r record;
BEGIN
  SELECT x.bu_id, x.state, x.requested_at, x.iterations, x.purpose INTO a FROM analysis.aggregate x WHERE x.id = NEW.aggregate_id;
  IF NOT FOUND OR a.state <> 'queued' OR a.requested_at <> now() THEN
    RAISE EXCEPTION 'analysis.aggregate_member: added only with its aggregate' USING ERRCODE = 'PF024';
  END IF;
  IF NEW.member_aggregate_id IS NOT NULL THEN
    -- Under the caller's read scope, with every member of its own.
    SELECT x.bu_id, x.state, x.iterations, x.engine_version INTO r FROM analysis.aggregate x
    WHERE x.id = NEW.member_aggregate_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'))
      AND analysis.members_visible(x.id);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'analysis.aggregate_member: no such aggregate %', NEW.member_aggregate_id USING ERRCODE = 'P0002';
    END IF;
    IF r.state <> 'succeeded' AND NOT (a.purpose = 'rollup' AND r.state IN ('queued', 'running')) THEN
      RAISE EXCEPTION 'analysis.aggregate_member: members are succeeded runs and aggregates' USING ERRCODE = 'PF024';
    END IF;
  ELSE
    -- Under the caller's read scope: the definer's own policy would see
    -- every run, so visibility is checked against the caller's scope.
    SELECT x.bu_id, x.state, x.iterations, x.control_sets, x.engine_version INTO r FROM analysis.run x
    WHERE x.id = NEW.run_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'));
    IF NOT FOUND THEN
      RAISE EXCEPTION 'analysis.aggregate_member: no such run %', NEW.run_id USING ERRCODE = 'P0002';
    END IF;
    IF r.state <> 'succeeded' OR NOT NEW.control_set = ANY (r.control_sets) THEN
      RAISE EXCEPTION 'analysis.aggregate_member: members are control sets of succeeded runs' USING ERRCODE = 'PF024';
    END IF;
  END IF;
  IF r.iterations <> a.iterations THEN
    RAISE EXCEPTION 'analysis.aggregate_member: members have the aggregate''s iterations (%)', a.iterations USING ERRCODE = 'PF024';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = a.bu_id AND c.descendant_id = r.bu_id) THEN
    RAISE EXCEPTION 'analysis.aggregate_member: % is outside the aggregate''s business unit', coalesce(NEW.run_id, NEW.member_aggregate_id)
      USING ERRCODE = 'PF024';
  END IF;
  NEW.bu_id := a.bu_id;
  NEW.engine_version := r.engine_version;
  RETURN NEW;
END $$;

-- Whether an aggregate's member aggregates have finished: ready, waiting
-- (one queued or running) or failed (one failed).
CREATE FUNCTION analysis.members_ready(id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN bool_or(g.state = 'failed') THEN 'failed' WHEN bool_or(g.state IN ('queued', 'running')) THEN 'waiting' ELSE 'ready' END
  FROM analysis.aggregate_member m JOIN analysis.aggregate g ON g.id = m.member_aggregate_id WHERE m.aggregate_id = members_ready.id
$$;

-- A register aggregate as the caller sees it (its BU in their read scope,
-- every leaf visible): its BU, iterations, state and summary; else null.
CREATE FUNCTION analysis.exposure_view(id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('bu_id', a.bu_id, 'iterations', a.iterations, 'state', a.state, 'summary', a.summary)
  FROM analysis.aggregate a
  WHERE a.id = exposure_view.id AND a.purpose <> 'analysis' AND a.bu_id = ANY (authz.visible_bus('analysis', 'read')) AND analysis.members_visible(a.id)
$$;

REVOKE ALL ON FUNCTION analysis.members_ready(uuid), analysis.exposure_view(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.members_ready(uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION analysis.exposure_view(uuid) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

-- The register's functions ----------------------------------------------------------

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

CREATE FUNCTION register.emit(type text, actor text, target text, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'low', 'actor', actor, 'target', target, 'bu_id', bu, 'attributes', attrs));
$$;

-- Whether u is the signed context's user (the roll-up restriction).
CREATE FUNCTION register.is_mine(u uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u = (authz.ctx_scope()).user_id
$$;

-- A risk's exposure status (AC-08), whoever asks: register.exposure_status
-- for callers, the roll-up functions within.
CREATE FUNCTION register.status_of(risk uuid) RETURNS jsonb
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
  SELECT * INTO h FROM register.risk x WHERE x.id = status_of.risk;
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

CREATE OR REPLACE FUNCTION register.exposure_status(risk uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT register.status_of(x.id) FROM register.risk x WHERE x.id = exposure_status.risk AND x.bu_id = ANY (authz.visible_bus('register', 'read'))
$$;

-- A risk's exposure summary value at path (e.g. {ale,mean}) as the caller
-- sees it: its exposure aggregate's with two or more pins, else its one
-- pinned result's. Invoker: RLS decides.
CREATE FUNCTION register.exposure_value(risk uuid, path text[]) RETURNS double precision
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN (SELECT count(*) FROM register.risk_scenario l WHERE l.risk_id = exposure_value.risk AND l.run_id IS NOT NULL) >= 2
    THEN (SELECT (a.summary #>> path)::double precision FROM register.risk r JOIN analysis.aggregate a ON a.id = r.exposure_aggregate_id
          WHERE r.id = exposure_value.risk)
    ELSE (SELECT (s.summary #>> path)::double precision FROM register.risk_scenario l
          JOIN analysis.result s ON s.run_id = l.run_id AND s.control_set = l.control_set WHERE l.risk_id = exposure_value.risk AND l.run_id IS NOT NULL) END
$$;

-- The limits (design §3.4): members of a node (F-005's), risks of a roll-up.
CREATE FUNCTION register.rollup_node_max() RETURNS integer LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 200 $$;
CREATE FUNCTION register.rollup_max_risks() RETURNS integer LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 2000 $$;

-- A random seed for a node (60 random bits of a version 4 UUID).
CREATE FUNCTION register.seed() RETURNS numeric
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
  SELECT (('x' || substr(replace(gen_random_uuid()::text, '-', ''), 18, 15))::bit(60)::bigint)::numeric
$$;

-- What a roll-up of target would include now, for the caller (design §3.4).
CREATE FUNCTION register.rollup_plan(target uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  iters integer := register.iterations();
  readable uuid[];
  excluded integer;
  r record;
  l record;
  st text;
  pins integer;
  home uuid;
  it integer;
  summary jsonb;
  v jsonb;
  ref jsonb;
  included jsonb := '[]';
  left_out jsonb := '{"stale": 0, "unquantified": 0, "computing": 0, "not_visible": 0, "other_iterations": 0, "outside": 0}';
  keys text := '';
  agg_only jsonb;
BEGIN
  SELECT coalesce(array_agg(c.bu_id) FILTER (WHERE c.mode = 'full'), '{}'), count(*) FILTER (WHERE c.mode = 'excluded')
    INTO readable, excluded FROM authz.rollup_coverage('register', target) c;
  FOR r IN SELECT x.id, x.bu_id, x.exposure_aggregate_id FROM register.risk x WHERE x.state = 'open' AND x.bu_id = ANY (readable) ORDER BY x.seq LOOP
    st := register.status_of(r.id) ->> 'status';
    IF st <> 'current' THEN
      left_out := jsonb_set(left_out, ARRAY[st], to_jsonb((left_out ->> st)::integer + 1));
      CONTINUE;
    END IF;
    SELECT count(*) INTO pins FROM register.risk_scenario x WHERE x.risk_id = r.id AND x.run_id IS NOT NULL;
    home := NULL;
    it := NULL;
    summary := NULL;
    IF pins = 1 THEN
      SELECT x.run_id, x.control_set INTO l FROM register.risk_scenario x WHERE x.risk_id = r.id AND x.run_id IS NOT NULL;
      SELECT x.bu_id, x.iterations INTO home, it FROM analysis.run x WHERE x.id = l.run_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'));
      SELECT s.summary INTO summary FROM analysis.result s WHERE s.run_id = l.run_id AND s.control_set = l.control_set;
      ref := jsonb_build_object('run_id', l.run_id, 'control_set', l.control_set);
    ELSE
      v := analysis.exposure_view(r.exposure_aggregate_id);
      home := (v ->> 'bu_id')::uuid;
      it := (v ->> 'iterations')::integer;
      summary := v -> 'summary';
      ref := jsonb_build_object('aggregate_id', r.exposure_aggregate_id);
    END IF;
    IF home IS NULL OR summary IS NULL OR summary = 'null'::jsonb THEN
      left_out := jsonb_set(left_out, '{not_visible}', to_jsonb((left_out ->> 'not_visible')::integer + 1));
    ELSIF it IS DISTINCT FROM iters THEN
      left_out := jsonb_set(left_out, '{other_iterations}', to_jsonb((left_out ->> 'other_iterations')::integer + 1));
    ELSIF NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = target AND c.descendant_id = home) THEN
      left_out := jsonb_set(left_out, '{outside}', to_jsonb((left_out ->> 'outside')::integer + 1));
    ELSE
      included := included || jsonb_build_object('risk_id', r.id, 'bu_id', r.bu_id, 'home', home, 'ref', ref,
        'mean', summary #> '{ale,mean}', 'p90', summary #> '{ale,percentiles,p90}');
      keys := keys || r.id || '=' || ref::text || ';';
    END IF;
  END LOOP;
  agg_only := register.rollup_means(target);
  RETURN jsonb_build_object('iterations', iters, 'included', included, 'left_out', left_out, 'excluded_bus', excluded, 'aggregate_only', agg_only,
    'digest', encode(sha256(convert_to(keys || '|' || coalesce(agg_only::text, ''), 'UTF8')), 'hex'));
END $$;

-- A node at bu of members (2 to 200 refs), reused by digest unless failed.
CREATE FUNCTION register.rollup_node(bu uuid, name text, iters integer, members jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d text := encode(sha256(convert_to(bu::text || '|' || iters || '|' || members::text, 'UTF8')), 'hex');
  agg uuid;
  m jsonb;
  pos integer := 0;
BEGIN
  SELECT n.aggregate_id INTO agg FROM register.rollup_node n WHERE n.digest = d;
  IF FOUND AND analysis.exposure_state(agg) IS DISTINCT FROM 'failed' THEN
    RETURN jsonb_build_object('ref', jsonb_build_object('aggregate_id', agg), 'created', false);
  END IF;
  agg := gen_random_uuid();
  INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations, purpose) VALUES (agg, bu, left(name, 200), register.seed(), iters, 'rollup');
  FOR m IN SELECT x FROM jsonb_array_elements(members) x LOOP
    INSERT INTO analysis.aggregate_member (aggregate_id, bu_id, position, run_id, control_set, member_aggregate_id)
    VALUES (agg, bu, pos, (m ->> 'run_id')::uuid, m ->> 'control_set', (m ->> 'aggregate_id')::uuid);
    pos := pos + 1;
  END LOOP;
  PERFORM analysis.emit_created(agg);
  INSERT INTO register.rollup_node AS n (digest, aggregate_id) VALUES (d, agg) ON CONFLICT (digest) DO UPDATE SET aggregate_id = EXCLUDED.aggregate_id, created_at = now();
  RETURN jsonb_build_object('ref', jsonb_build_object('aggregate_id', agg), 'created', true);
END $$;

-- A level's members at bu: parts of at most rollup_node_max (200), then one
-- node of two or more; returns {refs (what the level passes up), created
-- (new nodes)}.
CREATE FUNCTION register.rollup_group(bu uuid, name text, iters integer, list jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  created jsonb := '[]';
  parts jsonb;
  chunk jsonb;
  n jsonb;
  i integer := 0;
  k integer := 1;
  most integer := register.rollup_node_max();
BEGIN
  IF jsonb_array_length(list) > most THEN
    parts := '[]';
    WHILE i < jsonb_array_length(list) LOOP
      SELECT jsonb_agg(x ORDER BY o) INTO chunk FROM jsonb_array_elements(list) WITH ORDINALITY t(x, o) WHERE o > i AND o <= i + most;
      IF jsonb_array_length(chunk) = 1 THEN
        parts := parts || chunk;
      ELSE
        n := register.rollup_node(bu, name || ' (part ' || k || ')', iters, chunk);
        parts := parts || jsonb_build_array(n -> 'ref');
        IF (n ->> 'created')::boolean THEN
          created := created || jsonb_build_array(n -> 'ref' -> 'aggregate_id');
        END IF;
      END IF;
      i := i + most;
      k := k + 1;
    END LOOP;
    list := parts;
  END IF;
  IF jsonb_array_length(list) >= 2 THEN
    n := register.rollup_node(bu, name, iters, list);
    list := jsonb_build_array(n -> 'ref');
    IF (n ->> 'created')::boolean THEN
      created := created || jsonb_build_array(n -> 'ref' -> 'aggregate_id');
    END IF;
  END IF;
  RETURN jsonb_build_object('refs', list, 'created', created);
END $$;

-- Requests a roll-up of target for the caller (AC-11, AC-13): returns {id,
-- state, queue (the node aggregates to queue)}.
CREATE FUNCTION register.request_rollup(target uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := register.actor();
  plan jsonb;
  iters integer;
  levels jsonb := '{}';
  item jsonb;
  b record;
  list jsonb;
  g jsonb;
  queue jsonb := '[]';
  root jsonb;
  rid uuid := gen_random_uuid();
  st text := 'succeeded';
  summary jsonb;
  agg uuid;
  run uuid;
  cset text;
  tname text;
BEGIN
  SELECT x.name INTO tname FROM iam.bu x WHERE x.id = target;
  IF tname IS NULL OR NOT target = ANY (authz.visible_bus('register', 'read')) THEN
    RAISE EXCEPTION 'register: no such business unit %', target USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM register.rollup x WHERE x.bu_id = target AND x.requested_by = u AND x.state = 'queued') THEN
    RAISE EXCEPTION 'register: your roll-up of this business unit is still running' USING ERRCODE = 'PF026', HINT = 'rollup_running';
  END IF;
  IF EXISTS (SELECT 1 FROM register.rollup x WHERE x.bu_id = target AND x.requested_at > now() - interval '1 minute') THEN
    RAISE EXCEPTION 'register: this business unit was rolled up less than a minute ago' USING ERRCODE = 'PF026', HINT = 'rollup_rate';
  END IF;
  plan := register.rollup_plan(target);
  IF jsonb_array_length(plan -> 'included') > register.rollup_max_risks() THEN
    RAISE EXCEPTION 'register: a roll-up includes at most % risks; this one would include %', register.rollup_max_risks(), jsonb_array_length(plan -> 'included')
      USING ERRCODE = 'PF026', HINT = 'rollup_too_large';
  END IF;
  iters := (plan ->> 'iterations')::integer;
  -- Each exposure at its own BU; bottom up, a node where the caller reads
  -- analyses, else the members pass to the parent.
  FOR item IN SELECT y FROM jsonb_array_elements(plan -> 'included') y LOOP
    levels := jsonb_set(levels, ARRAY[item ->> 'home'], coalesce(levels -> (item ->> 'home'), '[]') || jsonb_build_array(item -> 'ref'));
  END LOOP;
  FOR b IN SELECT y.id, y.parent_id, y.name FROM iam.bu_closure c JOIN iam.bu y ON y.id = c.descendant_id
           WHERE c.ancestor_id = target AND y.id <> target ORDER BY y.depth DESC, y.id LOOP
    list := levels -> b.id::text;
    CONTINUE WHEN list IS NULL;
    IF b.id = ANY (authz.visible_bus('analysis', 'read')) THEN
      g := register.rollup_group(b.id, 'Roll-up: ' || b.name, iters, list);
      list := g -> 'refs';
      queue := queue || (g -> 'created');
    END IF;
    levels := jsonb_set(levels, ARRAY[b.parent_id::text], coalesce(levels -> b.parent_id::text, '[]') || list);
  END LOOP;
  g := register.rollup_group(target, 'Roll-up: ' || tname, iters, coalesce(levels -> target::text, '[]'));
  queue := queue || (g -> 'created');
  root := g -> 'refs' -> 0;
  IF root ? 'run_id' THEN
    run := (root ->> 'run_id')::uuid;
    cset := root ->> 'control_set';
    SELECT s.summary INTO summary FROM analysis.result s WHERE s.run_id = run AND s.control_set = cset;
  ELSIF root ? 'aggregate_id' THEN
    agg := (root ->> 'aggregate_id')::uuid;
    IF analysis.exposure_state(agg) = 'succeeded' THEN
      summary := analysis.exposure_view(agg) -> 'summary';
    ELSE
      st := 'queued';
    END IF;
  END IF;
  INSERT INTO register.rollup (id, bu_id, requested_by, state, finished_at, root_aggregate_id, root_run_id, root_control_set, summary, digest,
                               included, left_out, excluded_bus, aggregate_only, nodes)
  VALUES (rid, target, u, st, CASE WHEN st = 'succeeded' THEN now() END, agg, run, cset, summary, plan ->> 'digest',
          plan -> 'included', plan -> 'left_out', (plan ->> 'excluded_bus')::integer, plan -> 'aggregate_only', jsonb_array_length(queue));
  PERFORM register.emit('register.rollup_requested', u::text, 'register_rollup:' || rid, target,
    jsonb_build_object('rollup', rid::text, 'risks', jsonb_array_length(plan -> 'included')::text,
      'left_out', (SELECT sum(v::integer) FROM jsonb_each_text(plan -> 'left_out') e(k, v))::text,
      'excluded_bus', plan ->> 'excluded_bus', 'nodes', jsonb_array_length(queue)::text));
  IF st = 'succeeded' THEN
    PERFORM register.emit('register.rollup_computed', u::text, 'register_rollup:' || rid, target,
      jsonb_build_object('rollup', rid::text, 'requested_by', u::text));
  END IF;
  RETURN jsonb_build_object('id', rid, 'state', st, 'queue', queue);
END $$;

-- A roll-up's root aggregate finished: the roll-up records it (AC-11).
CREATE FUNCTION register.rollup_after_aggregate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT x.id, x.bu_id, x.requested_by FROM register.rollup x WHERE x.root_aggregate_id = NEW.id AND x.state = 'queued' FOR UPDATE LOOP
    IF NEW.state = 'succeeded' THEN
      UPDATE register.rollup x SET state = 'succeeded', finished_at = now(), summary = NEW.summary WHERE x.id = r.id;
      PERFORM register.emit('register.rollup_computed', 'system:risk', 'register_rollup:' || r.id, r.bu_id,
        jsonb_build_object('rollup', r.id::text, 'requested_by', r.requested_by::text));
    ELSE
      UPDATE register.rollup x SET state = 'failed', finished_at = now(), failure = NEW.failure WHERE x.id = r.id;
      PERFORM register.emit('register.rollup_failed', 'system:risk', 'register_rollup:' || r.id, r.bu_id,
        jsonb_build_object('rollup', r.id::text, 'requested_by', r.requested_by::text, 'failure', NEW.failure));
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION register.emit(text, text, text, uuid, jsonb), register.is_mine(uuid), register.status_of(uuid),
  register.exposure_value(uuid, text[]), register.seed(), register.rollup_node_max(), register.rollup_max_risks(), register.rollup_plan(uuid), register.rollup_node(uuid, text, integer, jsonb),
  register.rollup_group(uuid, text, integer, jsonb), register.request_rollup(uuid), register.rollup_after_aggregate() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.is_mine(uuid), register.exposure_value(uuid, text[]), register.rollup_plan(uuid), register.request_rollup(uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION register.status_of(uuid) TO rollup_definer;
GRANT EXECUTE ON FUNCTION register.rollup_after_aggregate() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- The aggregate-only total (AC-13, OQ6): rollup_definer reads the rows of
-- the caller's aggregate-only BUs (bu_rollup) and returns their open,
-- current risks' summed mean exposure and the number of such BUs; never a
-- row, a risk or a distribution.
GRANT CREATE ON SCHEMA register TO rollup_definer;
SET ROLE rollup_definer;
CREATE FUNCTION register.rollup_means(target uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bus uuid[];
  r record;
  pins integer;
  m double precision;
  total double precision := 0;
BEGIN
  SELECT coalesce(array_agg(c.bu_id), '{}') INTO bus FROM authz.rollup_coverage('register', target) c WHERE c.mode = 'aggregate';
  IF cardinality(bus) = 0 THEN
    RETURN NULL;
  END IF;
  FOR r IN SELECT x.id, x.exposure_aggregate_id FROM register.risk x WHERE x.state = 'open' AND x.bu_id = ANY (bus) LOOP
    IF register.status_of(r.id) ->> 'status' IS DISTINCT FROM 'current' THEN
      CONTINUE;
    END IF;
    SELECT count(*) INTO pins FROM register.risk_scenario x WHERE x.risk_id = r.id AND x.run_id IS NOT NULL;
    IF pins >= 2 THEN
      SELECT (a.summary #>> '{ale,mean}')::double precision INTO m FROM analysis.aggregate a WHERE a.id = r.exposure_aggregate_id;
    ELSE
      SELECT (s.summary #>> '{ale,mean}')::double precision INTO m FROM register.risk_scenario x
      JOIN analysis.result s ON s.run_id = x.run_id AND s.control_set = x.control_set WHERE x.risk_id = r.id AND x.run_id IS NOT NULL;
    END IF;
    total := total + coalesce(m, 0);
  END LOOP;
  RETURN jsonb_build_object('bus', cardinality(bus), 'mean_total', total, 'label', 'restricted business units (mean only)');
END $$;
REVOKE ALL ON FUNCTION register.rollup_means(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.rollup_means(uuid) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM rollup_definer;
REVOKE CREATE ON SCHEMA register FROM register_definer;

-- Requester-only reads (ADR-007 amendment 4); records change only by the
-- register's functions and are never deleted.
SELECT authz.restrict_select('register.rollup', 'register.is_mine(requested_by)');
CREATE TRIGGER definer_only BEFORE UPDATE ON register.rollup FOR EACH ROW EXECUTE FUNCTION register.definer_only();
CREATE TRIGGER never_deleted BEFORE DELETE ON register.rollup FOR EACH ROW EXECUTE FUNCTION register.refuse_change();
CREATE TRIGGER never_truncated BEFORE TRUNCATE ON register.rollup FOR EACH STATEMENT EXECUTE FUNCTION register.refuse_change();
CREATE TRIGGER register_rollup AFTER UPDATE OF state ON analysis.aggregate FOR EACH ROW
  WHEN (NEW.purpose <> 'analysis' AND OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('succeeded', 'failed'))
  EXECUTE FUNCTION register.rollup_after_aggregate();

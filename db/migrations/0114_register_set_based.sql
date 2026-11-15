-- F-007 T-10 (requirements NFR "Performance"; design §9): the register's
-- reads at scale, set-based. A definer function called per row re-reads
-- the caller's scope from the signed context on every call (thousands of
-- BUs), so the list, coverage and a roll-up's plan no longer call one per
-- risk:
--   * the list and coverage compute each risk's status from its links in
--     the query (the service's SQL; register.status_of's rules), reading
--     the setting once (register.max_age_days) and an exposure aggregate's
--     state (analysis.exposure_state, now open to app_rw: the state of a
--     register aggregate whose id the caller holds);
--   * owners' names come in one call per page (register.owner_names: only
--     owners of risks the caller sees);
--   * register.rollup_plan reads the caller's analysis scope once and plans
--     every risk in one query, with the same result and digest as 0112's;
--     register.request_rollup reads it once, not per business unit;
--   * analysis.members_visible reads it once per call, not per member row
--     (the same rule; a roll-up's nodes check every leaf as they are added).

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;
GRANT EXECUTE ON FUNCTION analysis.exposure_state(uuid) TO app_rw;

-- As 0107, the caller's scope read once per call, not once per member row:
-- the same rule (every run under the aggregate, and every aggregate on the
-- way, in the caller's read scope).
CREATE OR REPLACE FUNCTION analysis.members_visible(aggregate uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH RECURSIVE seen AS MATERIALIZED (
    SELECT authz.visible_bus('analysis', 'read') AS bus
  ), tree(id) AS (
    SELECT members_visible.aggregate
    UNION
    SELECT m.member_aggregate_id FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id WHERE m.member_aggregate_id IS NOT NULL
  )
  SELECT NOT EXISTS (SELECT 1 FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id JOIN analysis.run r ON r.id = m.run_id, seen
                     WHERE NOT r.bu_id = ANY (seen.bus))
     AND NOT EXISTS (SELECT 1 FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id
                     JOIN analysis.aggregate a ON a.id = m.member_aggregate_id, seen
                     WHERE NOT a.bu_id = ANY (seen.bus));
$$;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

-- register.analysis_max_age_days in force (null when unset).
CREATE FUNCTION register.max_age_days() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT (iam.instance_setting('register.analysis_max_age_days') #>> '{}')::integer
$$;

-- The names of the given users who own a risk the caller sees.
CREATE FUNCTION register.owner_names(ids uuid[]) RETURNS TABLE (user_id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH seen AS (SELECT authz.visible_bus('register', 'read') AS bus)
  SELECT u.id, coalesce(u.display_name, u.email) FROM iam.app_user u, seen
  WHERE u.id = ANY (owner_names.ids)
    AND EXISTS (SELECT 1 FROM register.risk r WHERE r.owner = u.id AND r.bu_id = ANY (seen.bus))
$$;

-- As 0112, set-based: the same plan, the same digest.
CREATE OR REPLACE FUNCTION register.rollup_plan(target uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  iters integer := register.iterations();
  max_age integer := register.max_age_days();
  ana uuid[] := authz.visible_bus('analysis', 'read');
  readable uuid[];
  excluded integer;
  included jsonb;
  keys text;
  left_out jsonb;
  agg_only jsonb;
BEGIN
  SELECT coalesce(array_agg(c.bu_id) FILTER (WHERE c.mode = 'full'), '{}'), count(*) FILTER (WHERE c.mode = 'excluded')
    INTO readable, excluded FROM authz.rollup_coverage('register', target) c;
  WITH rs AS (
    SELECT r.id, r.bu_id, r.seq, r.exposure_aggregate_id, st.pins,
      CASE WHEN st.n = 0 THEN 'unquantified'
           WHEN st.reasons THEN 'stale'
           WHEN st.pins >= 2 THEN CASE coalesce(analysis.exposure_state(r.exposure_aggregate_id), 'failed')
                                    WHEN 'failed' THEN 'stale' WHEN 'succeeded' THEN 'current' ELSE 'computing' END
           ELSE 'current' END AS status
    FROM register.risk r
    CROSS JOIN LATERAL (
      SELECT count(*) AS n, count(l.run_id) AS pins,
        coalesce(bool_or(l.scenario_archived OR l.run_id IS NULL OR l.run_scenario_version IS NULL OR l.run_scenario_version < l.scenario_version
          OR (l.run_id IS NOT NULL AND max_age IS NOT NULL AND (l.run_finished_at IS NULL OR l.run_finished_at < now() - make_interval(days => max_age)))), false) AS reasons
      FROM register.risk_scenario l WHERE l.risk_id = r.id) st
    WHERE r.state = 'open' AND r.bu_id = ANY (readable)
  ), mem AS (
    SELECT rs.id, rs.bu_id, rs.seq, rs.status,
      CASE WHEN rs.status <> 'current' THEN NULL
           WHEN rs.pins = 1 THEN (
             SELECT jsonb_build_object('home', x.bu_id, 'it', x.iterations, 'summary', s.summary,
               'ref', jsonb_build_object('run_id', l.run_id, 'control_set', l.control_set))
             FROM register.risk_scenario l JOIN analysis.run x ON x.id = l.run_id AND x.bu_id = ANY (ana)
             JOIN analysis.result s ON s.run_id = l.run_id AND s.control_set = l.control_set
             WHERE l.risk_id = rs.id AND l.run_id IS NOT NULL)
           ELSE (
             SELECT jsonb_build_object('home', v ->> 'bu_id', 'it', v -> 'iterations', 'summary', v -> 'summary',
               'ref', jsonb_build_object('aggregate_id', rs.exposure_aggregate_id))
             FROM analysis.exposure_view(rs.exposure_aggregate_id) v WHERE v IS NOT NULL) END AS m
    FROM rs
  ), cls AS (
    SELECT mem.*,
      CASE WHEN status <> 'current' THEN status
           WHEN m IS NULL OR m -> 'home' IS NULL OR m -> 'summary' IS NULL OR m -> 'summary' = 'null'::jsonb THEN 'not_visible'
           WHEN (m ->> 'it')::integer IS DISTINCT FROM iters THEN 'other_iterations'
           WHEN NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = target AND c.descendant_id = (m ->> 'home')::uuid) THEN 'outside'
           ELSE 'included' END AS cls
    FROM mem
  )
  SELECT
    coalesce(jsonb_agg(jsonb_build_object('risk_id', id, 'bu_id', bu_id, 'home', (m ->> 'home')::uuid, 'ref', m -> 'ref',
      'mean', m #> '{summary,ale,mean}', 'p90', m #> '{summary,ale,percentiles,p90}') ORDER BY seq) FILTER (WHERE cls = 'included'), '[]'),
    coalesce(string_agg(id || '=' || (m -> 'ref')::text || ';', '' ORDER BY seq) FILTER (WHERE cls = 'included'), ''),
    jsonb_build_object('stale', count(*) FILTER (WHERE cls = 'stale'), 'unquantified', count(*) FILTER (WHERE cls = 'unquantified'),
      'computing', count(*) FILTER (WHERE cls = 'computing'), 'not_visible', count(*) FILTER (WHERE cls = 'not_visible'),
      'other_iterations', count(*) FILTER (WHERE cls = 'other_iterations'), 'outside', count(*) FILTER (WHERE cls = 'outside'))
    INTO included, keys, left_out
  FROM cls;
  agg_only := register.rollup_means(target);
  RETURN jsonb_build_object('iterations', iters, 'included', included, 'left_out', left_out, 'excluded_bus', excluded, 'aggregate_only', agg_only,
    'digest', encode(sha256(convert_to(keys || '|' || coalesce(agg_only::text, ''), 'UTF8')), 'hex'));
END $$;

-- As 0112, the caller's analysis scope read once, not per business unit.
CREATE OR REPLACE FUNCTION register.request_rollup(target uuid) RETURNS jsonb
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
  ana uuid[] := authz.visible_bus('analysis', 'read'); -- read once (T-10)
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
    IF b.id = ANY (ana) THEN
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

REVOKE ALL ON FUNCTION register.max_age_days(), register.owner_names(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.max_age_days(), register.owner_names(uuid[]) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

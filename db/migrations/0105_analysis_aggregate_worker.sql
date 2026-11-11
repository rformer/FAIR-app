-- F-005 T-12 (F-005-AC-18, AC-19; design §3.5, §6.4): the aggregate worker's
-- reads. Like a run's (migration 0104), the worker has no DB context of its
-- own, so it reads a running aggregate's inputs and its members' series
-- through analysis_definer's functions, with its attempt token:
--
-- * analysis.aggregate_spec: the seed, the iterations and the members in
--   position order, each with its run's results digest;
-- * analysis.member_series: one member's per-year series.

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

CREATE FUNCTION analysis.aggregate_spec(id uuid, token text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = aggregate_spec.id;
  IF NOT FOUND OR a.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: aggregate % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate');
  RETURN jsonb_build_object('id', a.id, 'bu_id', a.bu_id, 'seed', a.seed::text, 'iterations', a.iterations,
    'members', (SELECT jsonb_agg(jsonb_build_object('position', m.position, 'run_id', m.run_id, 'control_set', m.control_set,
                  'engine_version', m.engine_version, 'result_digest', r.result_digest) ORDER BY m.position)
                FROM analysis.aggregate_member m JOIN analysis.run r ON r.id = m.run_id WHERE m.aggregate_id = a.id));
END $$;

CREATE FUNCTION analysis.member_series(id uuid, token text, member integer) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate; b bytea;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = member_series.id;
  IF NOT FOUND OR a.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: aggregate % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate');
  SELECT s.ale INTO b FROM analysis.aggregate_member m JOIN analysis.series s ON s.run_id = m.run_id AND s.control_set = m.control_set
  WHERE m.aggregate_id = a.id AND m.position = member;
  IF b IS NULL THEN
    RAISE EXCEPTION 'analysis: aggregate % has no member %', id, member USING ERRCODE = 'P0002';
  END IF;
  RETURN b;
END $$;

REVOKE ALL ON FUNCTION analysis.aggregate_spec(uuid, text), analysis.member_series(uuid, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.aggregate_spec(uuid, text), analysis.member_series(uuid, text, integer) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

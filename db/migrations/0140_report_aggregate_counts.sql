-- F-010 T-14 (F-010-AC-01, AC-04; design §3.1): restricted units on the
-- dashboard, by their roll-up mode (F-001-AC-62).
--
--   * report.aggregate_counts(target): owned by rollup_definer (the only
--     role the bu_rollup policy admits, so it reads the caller's
--     aggregate-only BUs' rows); for the aggregate-only BUs of target's
--     subtree (authz.rollup_coverage), their open risks' counts by exposure
--     status and the summed mean of those with an exposure; NULL when the
--     caller has none. Totals only: never a row, a risk or a distribution.
--     Set-based, with the register's status and exposure rules
--     (internal/register/sql.go: LinkStats, StatusSQL, ExposureSQL; a DB
--     test holds them equal).

SET ROLE analysis_definer;
GRANT EXECUTE ON FUNCTION analysis.exposure_state(uuid) TO rollup_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
SET ROLE register_definer;
GRANT EXECUTE ON FUNCTION register.max_age_days() TO rollup_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA report TO rollup_definer;

GRANT CREATE ON SCHEMA report TO rollup_definer;
SET ROLE rollup_definer;

CREATE FUNCTION report.aggregate_counts(target uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bus uuid[];
  out jsonb;
BEGIN
  SELECT coalesce(array_agg(c.bu_id), '{}') INTO bus FROM authz.rollup_coverage('register', target) c WHERE c.mode = 'aggregate';
  IF cardinality(bus) = 0 THEN
    RETURN NULL;
  END IF;
  WITH x AS (
    SELECT CASE WHEN st.n = 0 THEN 'unquantified'
             WHEN st.reasons THEN 'stale'
             WHEN st.pins >= 2 THEN CASE coalesce(analysis.exposure_state(r.exposure_aggregate_id), 'failed')
               WHEN 'failed' THEN 'stale' WHEN 'succeeded' THEN 'current' ELSE 'computing' END
             ELSE 'current' END AS status,
      CASE WHEN st.pins >= 2 THEN (SELECT (a.summary #>> '{ale,mean}')::float8 FROM analysis.aggregate a WHERE a.id = r.exposure_aggregate_id)
           WHEN st.pins = 1 THEN (SELECT (s.summary #>> '{ale,mean}')::float8 FROM register.risk_scenario l2
             JOIN analysis.result s ON s.run_id = l2.run_id AND s.control_set = l2.control_set WHERE l2.risk_id = r.id AND l2.run_id IS NOT NULL) END AS mean
    FROM register.risk r
    CROSS JOIN LATERAL (
      SELECT count(*) AS n, count(l.run_id) AS pins,
        coalesce(bool_or(l.scenario_archived OR l.run_id IS NULL OR l.run_scenario_version IS NULL OR l.run_scenario_version < l.scenario_version
          OR (l.run_id IS NOT NULL AND (SELECT register.max_age_days()) IS NOT NULL
              AND (l.run_finished_at IS NULL OR l.run_finished_at < now() - make_interval(days => (SELECT register.max_age_days()))))), false) AS reasons
      FROM register.risk_scenario l WHERE l.risk_id = r.id) st
    WHERE r.state = 'open' AND r.bu_id = ANY (bus))
  SELECT jsonb_build_object('units', cardinality(bus), 'open_risks', count(*),
    'current', count(*) FILTER (WHERE status = 'current'), 'stale', count(*) FILTER (WHERE status = 'stale'),
    'computing', count(*) FILTER (WHERE status = 'computing'), 'unquantified', count(*) FILTER (WHERE status = 'unquantified'),
    'mean_sum', coalesce(sum(mean), 0), 'label', 'restricted business units (totals only)')
  INTO out FROM x;
  RETURN out;
END $$;
REVOKE ALL ON FUNCTION report.aggregate_counts(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.aggregate_counts(uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM rollup_definer;

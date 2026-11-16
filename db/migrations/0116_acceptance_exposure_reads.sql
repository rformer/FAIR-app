-- F-008 T-03 (F-008-AC-13, AC-14; design §3.5, §10): a risk's exposure
-- read without a user, for the acceptance job (no signed context, so no
-- caller's scope applies). Each function is granted to one definer only:
--   * analysis.register_summary(aggregate): the summary of a register
--     aggregate (purpose exposure or rollup), for register_definer;
--   * analysis.pinned_summary(run, control_set): a run's result summary,
--     for register_definer;
--   * register.exposure_for(risk): {status, mean} of a risk (status as
--     register.status_of; the mean of its exposure aggregate with two or
--     more pins, else of its one pinned result), for acceptance_definer.

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

CREATE FUNCTION analysis.register_summary(aggregate uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.summary FROM analysis.aggregate a WHERE a.id = register_summary.aggregate AND a.purpose <> 'analysis' AND a.state = 'succeeded'
$$;

CREATE FUNCTION analysis.pinned_summary(run uuid, control_set text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.summary FROM analysis.result s JOIN analysis.run r ON r.id = s.run_id AND r.state = 'succeeded'
  WHERE s.run_id = pinned_summary.run AND s.control_set = pinned_summary.control_set
$$;

REVOKE ALL ON FUNCTION analysis.register_summary(uuid), analysis.pinned_summary(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.register_summary(uuid), analysis.pinned_summary(uuid, text) TO register_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

CREATE FUNCTION register.exposure_for(risk uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  pins integer;
  l record;
  summary jsonb;
BEGIN
  SELECT * INTO h FROM register.risk x WHERE x.id = exposure_for.risk;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT count(*) INTO pins FROM register.risk_scenario x WHERE x.risk_id = h.id AND x.run_id IS NOT NULL;
  IF pins >= 2 THEN
    summary := analysis.register_summary(h.exposure_aggregate_id);
  ELSIF pins = 1 THEN
    SELECT x.run_id, x.control_set INTO l FROM register.risk_scenario x WHERE x.risk_id = h.id AND x.run_id IS NOT NULL;
    summary := analysis.pinned_summary(l.run_id, l.control_set);
  END IF;
  RETURN jsonb_build_object('status', register.status_of(h.id) ->> 'status', 'mean', summary #> '{ale,mean}',
    'p90', summary #> '{ale,percentiles,p90}', 'bu_id', h.bu_id, 'state', h.state, 'owner', h.owner);
END $$;

REVOKE ALL ON FUNCTION register.exposure_for(uuid) FROM PUBLIC;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA register TO acceptance_definer;
SET ROLE register_definer;
GRANT EXECUTE ON FUNCTION register.exposure_for(uuid) TO acceptance_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

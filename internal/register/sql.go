package register

// F-007 T-10 (design §3.3): a risk's exposure status in SQL, for queries
// over many risks (the list, coverage, and F-008's acceptances), which must
// not call a definer function per row. The same rules as the database's
// register.status_of; registerapi's statusParity test holds them equal.

// LinkStats joins st to risk r (as the alias r): its links (n), its pins
// (pins), and whether any link gives a stale reason (reasons).
const LinkStats = `
	CROSS JOIN LATERAL (
	  SELECT count(*) AS n, count(l.run_id) AS pins,
	    coalesce(bool_or(l.scenario_archived OR l.run_id IS NULL OR l.run_scenario_version IS NULL OR l.run_scenario_version < l.scenario_version
	      OR (l.run_id IS NOT NULL AND (SELECT register.max_age_days()) IS NOT NULL
	          AND (l.run_finished_at IS NULL OR l.run_finished_at < now() - make_interval(days => (SELECT register.max_age_days()))))), false) AS reasons
	  FROM register.risk_scenario l WHERE l.risk_id = r.id) st`

// StatusSQL is the status of risk r given st: unquantified, stale,
// computing or current.
const StatusSQL = `CASE WHEN st.n = 0 THEN 'unquantified'
	  WHEN st.reasons THEN 'stale'
	  WHEN st.pins >= 2 THEN CASE coalesce(analysis.exposure_state(r.exposure_aggregate_id), 'failed')
	    WHEN 'failed' THEN 'stale' WHEN 'succeeded' THEN 'current' ELSE 'computing' END
	  ELSE 'current' END`

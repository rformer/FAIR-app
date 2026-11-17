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

// ExposureSQL is the summary value at path of a risk's exposure as the
// caller sees it (RLS), for sorting.
func ExposureSQL(path string) string {
	return `CASE WHEN st.pins >= 2 THEN (SELECT (a.summary #>> '` + path + `')::float8 FROM analysis.aggregate a WHERE a.id = r.exposure_aggregate_id)
	  WHEN st.pins = 1 THEN (SELECT (s.summary #>> '` + path + `')::float8 FROM register.risk_scenario l2
	    JOIN analysis.result s ON s.run_id = l2.run_id AND s.control_set = l2.control_set WHERE l2.risk_id = r.id AND l2.run_id IS NOT NULL) END`
}

// AcceptanceSQL is a risk's open acceptance as the caller sees it (F-008
// T-05; acceptance.view, RLS): active or suspended before a pending one, its
// state as read (past its expiry: expired), its expiry, tier, and why an
// active one needs review (F-008-AC-14: stale exposure, treatment no longer
// accept, moved since approval); null without one.
const AcceptanceSQL = `(SELECT jsonb_build_object('id', x.id, 'state', CASE WHEN x.state IN ('active', 'suspended') AND x.expires_on <= current_date THEN 'expired' ELSE x.state END,
	  'expires_on', x.expires_on, 'tier', x.tier, 'renewal_pending', EXISTS (SELECT 1 FROM acceptance.acceptance y WHERE y.renews = x.id AND y.state = 'pending'),
	  'needs_review', CASE WHEN x.state <> 'active' OR x.expires_on <= current_date THEN '[]'::jsonb ELSE to_jsonb(array_remove(ARRAY[
	    CASE WHEN (` + StatusSQL + `) <> 'current' THEN 'stale' END,
	    CASE WHEN EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision IS DISTINCT FROM 'accept') THEN 'treatment' END,
	    CASE WHEN r.bu_id IS DISTINCT FROM x.approved_bu_id THEN 'moved' END], NULL)) END)
	 FROM acceptance.acceptance x WHERE x.risk_id = r.id AND (x.state IN ('active', 'suspended') OR (x.state = 'pending' AND x.renews IS NULL))
	 ORDER BY x.state = 'pending', x.seq DESC LIMIT 1)`

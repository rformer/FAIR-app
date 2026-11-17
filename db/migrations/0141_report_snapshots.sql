-- F-010 T-15 (F-010-AC-06, AC-07; OQ6; design §3.2 as amended): portfolio
-- snapshots and trends.
--
--   * register.snapshot_counts() (register_definer, which may read every
--     register row; treatment versions are admitted to it here): per BU,
--     its own open risks (not its subtree) by exposure status (computing
--     counts as stale: not current), the sum of their means
--     (register.exposures), and its open and overdue treatment actions.
--   * acceptance.snapshot_counts() (acceptance_definer): per BU, its
--     acceptances by state as read, and those active expiring within 30
--     days.
--   * register.snapshot_rollups(since) (register_definer): per BU, the
--     latest roll-up of it that succeeded after since (whoever asked), with
--     the BUs of every risk it included and, when it summed aggregate-only
--     units, every restricted BU below it (those it may have summed).
--   * report.snapshot_tick(interval_days, retention_days) (report_definer,
--     the leader): takes a snapshot when none was taken within the interval
--     (report.take_snapshot, set-based) and deletes snapshots older than
--     the retention, whole; returns {taken, purged}.
--   * report.trend(bu, from, to) (report_definer, the caller's context):
--     per snapshot in the period, the counts summed over the BUs of bu's
--     subtree the caller reads in the register, plus their aggregate-only
--     units' (totals only, as roll-ups, F-001-AC-62); and bu's roll-up row
--     only when the caller reads every included risk's BU and covers every
--     restricted BU it may have summed (as analysis.members_visible).
-- Snapshot rows never change (PF029, migration 0133).

-- register_definer reads treatment versions (their actions).
SELECT authz.allow_definer('register.treatment_version', 'register_definer');
GRANT SELECT ON iam.bu_closure TO register_definer;
GRANT EXECUTE ON FUNCTION iam.in_restricted_subtree(uuid) TO register_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

CREATE FUNCTION register.snapshot_counts()
RETURNS TABLE (bu_id uuid, open_risks integer, current_risks integer, stale_risks integer, unquantified integer, mean_sum numeric,
               open_actions integer, overdue_actions integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH e AS (
    SELECT x.* FROM register.exposures(ARRAY(SELECT r.id FROM register.risk r WHERE r.state = 'open')) x),
  risks AS (
    SELECT e.bu_id, count(*)::integer AS open_risks, count(*) FILTER (WHERE e.status = 'current')::integer AS current_risks,
      count(*) FILTER (WHERE e.status IN ('stale', 'computing'))::integer AS stale_risks,
      count(*) FILTER (WHERE e.status = 'unquantified')::integer AS unquantified, coalesce(sum(e.mean), 0) AS mean_sum
    FROM e GROUP BY e.bu_id),
  acts AS (
    SELECT r.bu_id,
      count(*) FILTER (WHERE a ->> 'state' IN ('planned', 'in_progress'))::integer AS open_actions,
      count(*) FILTER (WHERE a ->> 'state' IN ('planned', 'in_progress') AND (a ->> 'due')::date < current_date)::integer AS overdue_actions
    FROM register.risk r
    JOIN register.treatment t ON t.risk_id = r.id
    JOIN register.treatment_version v ON v.risk_id = t.risk_id AND v.version = t.current_version
    CROSS JOIN LATERAL jsonb_array_elements(convert_from(v.document, 'UTF8')::jsonb -> 'actions') a
    WHERE r.state = 'open'
    GROUP BY r.bu_id)
  SELECT coalesce(k.bu_id, a.bu_id), coalesce(k.open_risks, 0), coalesce(k.current_risks, 0), coalesce(k.stale_risks, 0), coalesce(k.unquantified, 0),
    coalesce(k.mean_sum, 0), coalesce(a.open_actions, 0), coalesce(a.overdue_actions, 0)
  FROM risks k FULL JOIN acts a ON a.bu_id = k.bu_id;
$$;

CREATE FUNCTION register.snapshot_rollups(since timestamptz)
RETURNS TABLE (bu_id uuid, rollup_id uuid, finished_at timestamptz, summary jsonb, risk_bus uuid[], aggregate_only_bus uuid[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT ON (x.bu_id) x.bu_id, x.id, x.finished_at, x.summary,
    ARRAY(SELECT DISTINCT (i ->> 'bu_id')::uuid FROM jsonb_array_elements(x.included) i WHERE i ->> 'bu_id' IS NOT NULL),
    CASE WHEN x.aggregate_only IS NULL THEN '{}'::uuid[] ELSE ARRAY(
      SELECT c.descendant_id FROM iam.bu_closure c JOIN iam.bu b ON b.id = c.descendant_id
      WHERE c.ancestor_id = x.bu_id AND c.descendant_id <> x.bu_id AND iam.in_restricted_subtree(c.descendant_id)) END
  FROM register.rollup x
  WHERE x.state = 'succeeded' AND x.summary IS NOT NULL AND (since IS NULL OR x.finished_at > since)
  ORDER BY x.bu_id, x.finished_at DESC, x.seq DESC;
$$;

REVOKE ALL ON FUNCTION register.snapshot_counts(), register.snapshot_rollups(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.snapshot_counts(), register.snapshot_rollups(timestamptz) TO report_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;
CREATE FUNCTION acceptance.snapshot_counts() RETURNS TABLE (bu_id uuid, counts jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH s AS (
    SELECT x.bu_id, CASE WHEN x.state IN ('active', 'suspended') AND x.expires_on <= current_date THEN 'expired' ELSE x.state END AS state, x.expires_on
    FROM acceptance.acceptance x WHERE x.state <> 'ended')
  SELECT s.bu_id, jsonb_build_object('active', count(*) FILTER (WHERE s.state = 'active'),
    'expiring', count(*) FILTER (WHERE s.state = 'active' AND s.expires_on <= current_date + 30),
    'expired', count(*) FILTER (WHERE s.state = 'expired'), 'suspended', count(*) FILTER (WHERE s.state = 'suspended'),
    'pending', count(*) FILTER (WHERE s.state = 'pending'))
  FROM s GROUP BY s.bu_id;
$$;
REVOKE ALL ON FUNCTION acceptance.snapshot_counts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.snapshot_counts() TO report_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

GRANT USAGE ON SCHEMA acceptance TO report_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.rollup_coverage(text, uuid) TO report_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

-- A snapshot of every BU (design §3.2), set-based; its id.
CREATE FUNCTION report.take_snapshot() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  id bigint;
  since timestamptz := (SELECT max(s.taken_at) FROM report.snapshot s);
  zero jsonb := '{"active": 0, "expiring": 0, "expired": 0, "suspended": 0, "pending": 0}';
BEGIN
  INSERT INTO report.snapshot DEFAULT VALUES RETURNING snapshot.id INTO id;
  INSERT INTO report.snapshot_bu (snapshot_id, bu_id, open_risks, current_risks, stale_risks, unquantified, mean_sum, acceptances, open_actions, overdue_actions)
  SELECT id, coalesce(c.bu_id, a.bu_id), coalesce(c.open_risks, 0), coalesce(c.current_risks, 0), coalesce(c.stale_risks, 0), coalesce(c.unquantified, 0),
    coalesce(c.mean_sum, 0), coalesce(a.counts, zero), coalesce(c.open_actions, 0), coalesce(c.overdue_actions, 0)
  FROM register.snapshot_counts() c FULL JOIN acceptance.snapshot_counts() a ON a.bu_id = c.bu_id;
  INSERT INTO report.snapshot_rollup (snapshot_id, bu_id, rollup_id, rollup_finished_at, summary, risk_bus, aggregate_only_bus)
  SELECT id, r.bu_id, r.rollup_id, r.finished_at, r.summary, r.risk_bus, r.aggregate_only_bus FROM register.snapshot_rollups(since) r;
  RETURN id;
END $$;

-- The leader's tick: a snapshot when none was taken within interval_days
-- (report.snapshot_interval_days), and the purge of snapshots older than
-- retention_days (report.snapshot_retention_days).
CREATE FUNCTION report.snapshot_tick(interval_days integer, retention_days integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  taken bigint;
  purged integer;
BEGIN
  IF interval_days IS NULL OR interval_days NOT BETWEEN 1 AND 31 OR retention_days IS NULL OR retention_days NOT BETWEEN 365 AND 3650 THEN
    RAISE EXCEPTION 'report: the snapshot interval is 1 to 31 days and the retention 365 to 3,650' USING ERRCODE = 'PF029', HINT = 'snapshot_settings';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('report.snapshot', 0));
  IF NOT EXISTS (SELECT 1 FROM report.snapshot s WHERE s.taken_at > now() - make_interval(days => interval_days)) THEN
    taken := report.take_snapshot();
  END IF;
  DELETE FROM report.snapshot s WHERE s.taken_at < now() - make_interval(days => retention_days);
  GET DIAGNOSTICS purged = ROW_COUNT;
  RETURN jsonb_build_object('taken', taken, 'purged', purged);
END $$;

-- The trend of bu's subtree for the caller (design §3.2 as amended).
CREATE FUNCTION report.trend(bu uuid, from_at timestamptz, to_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := report.actor();
  seen uuid[];
  covered uuid[];
BEGIN
  SELECT coalesce(array_agg(c.bu_id) FILTER (WHERE c.mode IN ('full', 'aggregate')), '{}') INTO covered
  FROM authz.rollup_coverage('register', bu) c;
  seen := ARRAY(SELECT b FROM unnest(authz.visible_bus('register', 'read')) b);
  RETURN coalesce((
    SELECT jsonb_agg(jsonb_build_object('snapshot_id', s.id, 'taken_at', s.taken_at,
      'counts', (SELECT jsonb_build_object('open', coalesce(sum(b.open_risks), 0), 'current', coalesce(sum(b.current_risks), 0),
                  'stale', coalesce(sum(b.stale_risks), 0), 'unquantified', coalesce(sum(b.unquantified), 0), 'mean_sum', coalesce(sum(b.mean_sum), 0),
                  'open_actions', coalesce(sum(b.open_actions), 0), 'overdue_actions', coalesce(sum(b.overdue_actions), 0),
                  'acceptances', jsonb_build_object(
                    'active', coalesce(sum((b.acceptances ->> 'active')::integer), 0), 'expiring', coalesce(sum((b.acceptances ->> 'expiring')::integer), 0),
                    'expired', coalesce(sum((b.acceptances ->> 'expired')::integer), 0), 'suspended', coalesce(sum((b.acceptances ->> 'suspended')::integer), 0),
                    'pending', coalesce(sum((b.acceptances ->> 'pending')::integer), 0)))
                FROM report.snapshot_bu b WHERE b.snapshot_id = s.id AND b.bu_id = ANY (covered)),
      'rollup', (SELECT jsonb_build_object('finished_at', r.rollup_finished_at, 'mean', r.summary #> '{ale,mean}',
                  'p10', r.summary #> '{ale,percentiles,p10}', 'p50', r.summary #> '{ale,percentiles,p50}',
                  'p90', r.summary #> '{ale,percentiles,p90}', 'p99', r.summary #> '{ale,percentiles,p99}')
                FROM report.snapshot_rollup r WHERE r.snapshot_id = s.id AND r.bu_id = trend.bu
                  AND r.risk_bus <@ seen AND r.aggregate_only_bus <@ covered))
      ORDER BY s.taken_at)
    FROM report.snapshot s WHERE s.taken_at >= from_at AND s.taken_at <= to_at AND u IS NOT NULL), '[]');
END $$;

REVOKE ALL ON FUNCTION report.take_snapshot(), report.snapshot_tick(integer, integer), report.trend(uuid, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.snapshot_tick(integer, integer), report.trend(uuid, timestamptz, timestamptz) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

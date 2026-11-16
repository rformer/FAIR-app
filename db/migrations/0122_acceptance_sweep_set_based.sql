-- F-008 T-08 (requirements NFR "Performance"; design §3.5, §9): the sweep
-- set-based, so one run over 10,000 acceptances fits its one-minute
-- interval (TestBenchmarkGateAcceptances), even when a lowered threshold
-- suspends many at once:
--   * register.exposures(risks): what register.exposure_for answers, for
--     many risks in one statement (the status by register.status_of's rules,
--     as internal/register's LinkStats and StatusSQL; the summary's mean and
--     p90; the risk's BU, state and owner); TestAcceptanceExposureReads
--     holds the two equal. For acceptance_definer alone, as exposure_for;
--   * acceptance.notify_users: notify (0119) for owners already read;
--   * acceptance.sweep: each loop reads its risks' exposures once
--     (register.exposures); the higher-tier check places tiers on the
--     thresholds read once; expiry notices are considered only for
--     acceptances without that notice yet; and one sweep handles at most
--     acceptance.sweep_batch() (500) acceptances, expiries first, answering
--     more = true when some were left: the job then sweeps again at once,
--     so each sweep (one transaction) stays short and a mass change, such
--     as a lowered threshold, completes in a few sweeps.
-- What it does is unchanged (0119), except that without the tier settings
-- the higher-tier check is skipped rather than failing the sweep, so expiry
-- still runs.

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;
CREATE FUNCTION register.exposures(risks uuid[])
RETURNS TABLE (risk_id uuid, status text, mean numeric, p90 numeric, bu_id uuid, state text, owner uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.id, s.status, (sm.summary #>> '{ale,mean}')::numeric, (sm.summary #>> '{ale,percentiles,p90}')::numeric, r.bu_id, r.state, r.owner
  FROM register.risk r
  CROSS JOIN LATERAL (
    SELECT count(*) AS n, count(l.run_id) AS pins,
      coalesce(bool_or(l.scenario_archived OR l.run_id IS NULL OR l.run_scenario_version IS NULL OR l.run_scenario_version < l.scenario_version
        OR (l.run_id IS NOT NULL AND (SELECT register.max_age_days()) IS NOT NULL
            AND (l.run_finished_at IS NULL OR l.run_finished_at < now() - make_interval(days => (SELECT register.max_age_days()))))), false) AS reasons
    FROM register.risk_scenario l WHERE l.risk_id = r.id) st
  CROSS JOIN LATERAL (
    SELECT CASE WHEN st.n = 0 THEN 'unquantified'
      WHEN st.reasons THEN 'stale'
      WHEN st.pins >= 2 THEN CASE coalesce(analysis.exposure_state(r.exposure_aggregate_id), 'failed')
        WHEN 'failed' THEN 'stale' WHEN 'succeeded' THEN 'current' ELSE 'computing' END
      ELSE 'current' END AS status) s
  CROSS JOIN LATERAL (
    SELECT CASE WHEN st.pins >= 2 THEN analysis.register_summary(r.exposure_aggregate_id)
                WHEN st.pins = 1 THEN (SELECT analysis.pinned_summary(l.run_id, l.control_set) FROM register.risk_scenario l
                                       WHERE l.risk_id = r.id AND l.run_id IS NOT NULL) END AS summary) sm
  WHERE r.id = ANY (exposures.risks)
$$;
REVOKE ALL ON FUNCTION register.exposures(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.exposures(uuid[]) TO acceptance_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;

-- The most acceptances one sweep handles.
CREATE FUNCTION acceptance.sweep_batch() RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 500';

-- Queues kind for acceptance id to each of users (null and repeats
-- skipped), once; answers how many were queued.
CREATE FUNCTION acceptance.notify_users(id uuid, users uuid[], kind text, lead integer, tier integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n integer;
BEGIN
  INSERT INTO acceptance.notice_outbox (kind, user_id, acceptance_id, lead_days, tier)
  SELECT notify_users.kind, u, notify_users.id, notify_users.lead, notify_users.tier FROM (SELECT DISTINCT v AS u FROM unnest(users) v WHERE v IS NOT NULL) x
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

CREATE OR REPLACE FUNCTION acceptance.sweep() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c record;
  expired integer := 0;
  notices integer := 0;
  suspended integer := 0;
  exp jsonb;
  placed jsonb;
  tbu uuid;
  t1 numeric := acceptance.setting('acceptance.tier1_max');
  t2 numeric := acceptance.setting('acceptance.tier2_max');
  batch integer := acceptance.sweep_batch();
  handled integer := 0;
  more boolean := false;
BEGIN
  -- Expiry (AC-09).
  FOR c IN
    SELECT x.id, x.bu_id, x.risk_id, x.expires_on, x.requested_by, e.owner FROM acceptance.acceptance x
    LEFT JOIN register.exposures(ARRAY(SELECT y.risk_id FROM acceptance.acceptance y WHERE y.state IN ('active', 'suspended') AND y.expires_on <= current_date)) e
      ON e.risk_id = x.risk_id
    WHERE x.state IN ('active', 'suspended') AND x.expires_on <= current_date
    ORDER BY x.expires_on, x.seq LIMIT batch + 1
    FOR UPDATE OF x SKIP LOCKED
  LOOP
    IF handled = batch THEN
      more := true;
      EXIT;
    END IF;
    handled := handled + 1;
    PERFORM acceptance.add_step(c.id, 'expired', NULL, NULL, jsonb_build_object('expires_on', c.expires_on));
    UPDATE acceptance.acceptance x SET state = 'expired', ended_at = now() WHERE x.id = c.id;
    PERFORM acceptance.emit('acceptance.expired', 'low', 'system:risk', c.id, c.bu_id, jsonb_build_object('risk', c.risk_id::text, 'expires_on', c.expires_on::text));
    notices := notices + acceptance.notify_users(c.id, ARRAY[c.owner, c.requested_by], 'expired', NULL, NULL);
    expired := expired + 1;
  END LOOP;
  -- Notices before expiry (AC-10): the tightest lead that applies, once;
  -- only acceptances without that notice yet.
  FOR c IN
    WITH due AS (
      SELECT x.id, x.risk_id, x.requested_by, CASE WHEN x.expires_on - current_date <= 7 THEN 7 WHEN x.expires_on - current_date <= 14 THEN 14 ELSE 30 END AS lead
      FROM acceptance.acceptance x WHERE x.state = 'active' AND x.expires_on - current_date <= 30
    )
    SELECT d.id, d.requested_by, d.lead, e.owner FROM due d LEFT JOIN register.exposures(ARRAY(SELECT risk_id FROM due)) e ON e.risk_id = d.risk_id
    WHERE NOT EXISTS (SELECT 1 FROM acceptance.notice_outbox o WHERE o.acceptance_id = d.id AND o.kind = 'expiring' AND o.lead_days = d.lead)
    LIMIT greatest(batch - handled, 0) + 1
  LOOP
    IF handled >= batch THEN
      more := true;
      EXIT;
    END IF;
    handled := handled + 1;
    notices := notices + acceptance.notify_users(c.id, ARRAY[c.owner, c.requested_by], 'expiring', c.lead, NULL);
  END LOOP;
  -- A higher tier (AC-13): every acceptance in force with a current
  -- exposure, its tier placed on the thresholds in force; those above their
  -- own are suspended, a review opened at that tier.
  IF handled >= batch THEN
    more := true; -- the higher-tier check waits for the next sweep
  ELSIF t1 IS NOT NULL AND t2 IS NOT NULL THEN
    FOR c IN
      SELECT x.id, x.bu_id, x.risk_id, x.tier, x.requested_by, e.status, e.mean, e.p90, e.bu_id AS risk_bu, e.state AS risk_state, e.owner
      FROM acceptance.acceptance x
      JOIN register.exposures(ARRAY(SELECT y.risk_id FROM acceptance.acceptance y WHERE y.state = 'active')) e ON e.risk_id = x.risk_id
      WHERE x.state = 'active' AND e.status = 'current' AND e.mean IS NOT NULL
        AND (CASE WHEN e.mean <= t1 THEN 1 WHEN e.mean <= t2 THEN 2 ELSE 3 END) > x.tier
      ORDER BY x.seq LIMIT batch - handled + 1
      FOR UPDATE OF x SKIP LOCKED
    LOOP
      IF handled >= batch THEN
        more := true;
        EXIT;
      END IF;
      handled := handled + 1;
      exp := jsonb_build_object('status', c.status, 'mean', c.mean, 'p90', c.p90, 'bu_id', c.risk_bu, 'state', c.risk_state, 'owner', c.owner);
      placed := acceptance.place(c.mean);
      tbu := acceptance.tier_bu(c.bu_id, (placed ->> 'levels_up')::integer);
      PERFORM acceptance.add_step(c.id, 'suspended', NULL, 'the exposure is now in a higher tier', jsonb_build_object('exposure', exp, 'from_tier', c.tier));
      UPDATE acceptance.acceptance x SET state = 'suspended', tier = (placed ->> 'n')::integer, tier_bu_id = tbu,
        approvals_needed = (placed ->> 'approvals')::integer, mean = c.mean WHERE x.id = c.id;
      PERFORM acceptance.add_step(c.id, 'review_requested', NULL, NULL, jsonb_build_object('exposure', exp, 'tier', placed || jsonb_build_object('bu_id', tbu)));
      PERFORM acceptance.emit('acceptance.suspended', 'low', 'system:risk', c.id, c.bu_id, jsonb_build_object('risk', c.risk_id::text,
        'from_tier', c.tier::text, 'tier', placed ->> 'n'));
      PERFORM acceptance.emit('acceptance.review_requested', 'low', 'system:risk', c.id, c.bu_id, jsonb_build_object('risk', c.risk_id::text,
        'tier', placed ->> 'n'));
      notices := notices + acceptance.notify_users(c.id, ARRAY[c.owner, c.requested_by], 'suspended', NULL, (placed ->> 'n')::integer);
      INSERT INTO acceptance.notice_outbox (kind, acceptance_id, tier) VALUES ('decision_needed', c.id, (placed ->> 'n')::integer) ON CONFLICT DO NOTHING;
      suspended := suspended + 1;
    END LOOP;
  END IF;
  RETURN jsonb_build_object('expired', expired, 'notices', notices, 'suspended', suspended, 'more', more);
END $$;

REVOKE ALL ON FUNCTION acceptance.notify_users(uuid, uuid[], text, integer, integer), acceptance.sweep_batch() FROM PUBLIC;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

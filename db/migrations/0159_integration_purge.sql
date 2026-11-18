-- F-011 T-17b (design §3.2, §5): staged records are kept for diagnosis for
-- integration.records_retention_days (30 by default), then purged; runs,
-- their counts and refusals, proposals, links and provenance remain.
--
--   * integration.purge_records(days, lim): deletes the staged records of
--     at most lim runs finished more than days ago (oldest first, SKIP
--     LOCKED, so two replicas never purge the same run), and records
--     integration.records_purged for each run (its integration, BU and how
--     many records went) in the same transaction. For app_integrate only
--     (the integrate service's leader, daily); days is the setting in
--     force, 1 to 365 (PF031 invalid_value otherwise).

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.purge_records(days integer, lim integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n integer; runs integer := 0; records integer := 0;
BEGIN
  IF days IS NULL OR days NOT BETWEEN 1 AND 365 OR lim IS NULL OR lim NOT BETWEEN 1 AND 10000 THEN
    RAISE EXCEPTION 'integration: purge records older than 1 to 365 days, 1 to 10,000 runs at a time' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  FOR r IN
    SELECT x.id, x.integration_id, i.bu_id, i.name FROM integration.run x JOIN integration.integration i ON i.id = x.integration_id
    WHERE x.finished_at < now() - make_interval(days => days) AND EXISTS (SELECT 1 FROM integration.record d WHERE d.run_id = x.id)
    ORDER BY x.finished_at, x.id LIMIT lim FOR UPDATE OF x SKIP LOCKED
  LOOP
    DELETE FROM integration.record d WHERE d.run_id = r.id;
    GET DIAGNOSTICS n = ROW_COUNT;
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'integration.records_purged', 'severity', 'info', 'actor', 'system:integrate',
      'target', 'integration:' || r.integration_id, 'bu_id', r.bu_id,
      'attributes', jsonb_build_object('integration', r.integration_id::text, 'name', r.name, 'run', r.id::text, 'records', n::text,
        'days', days::text)));
    runs := runs + 1;
    records := records + n;
  END LOOP;
  RETURN jsonb_build_object('runs', runs, 'records', records, 'more', runs = lim);
END $$;

REVOKE ALL ON FUNCTION integration.purge_records(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.purge_records(integer, integer) TO app_integrate;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

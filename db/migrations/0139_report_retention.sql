-- F-010 T-13 (F-010-AC-15; OQ8; design §3.6): retention of report files.
--
--   * report.files_due(days, lim): files not yet purged, made more than
--     days ago (report.retention_days, 1 to 365), oldest first.
--   * report.mark_purged(run, formats): marks the run's files of those
--     formats purged (once; PF029 keeps them otherwise unchanged) and
--     records report.files_purged as the system, with the run's BU;
--     returns how many it marked. The run and its digests stay.
-- The risk service's leader deletes every version of each object from the
-- report store before marking it.

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

CREATE FUNCTION report.files_due(days integer, lim integer) RETURNS TABLE (run_id uuid, format text, object_key text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF days IS NULL OR days NOT BETWEEN 1 AND 365 THEN
    RAISE EXCEPTION 'report: retention is 1 to 365 days' USING ERRCODE = 'PF029', HINT = 'retention';
  END IF;
  RETURN QUERY SELECT f.run_id, f.format, f.object_key FROM report.file f
    WHERE f.purged_at IS NULL AND f.created_at < now() - make_interval(days => files_due.days)
    ORDER BY f.created_at, f.run_id, f.format LIMIT greatest(1, least(lim, 1000));
END $$;

CREATE FUNCTION report.mark_purged(run uuid, formats text[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r report.run;
  n integer;
  done text[];
BEGIN
  SELECT * INTO r FROM report.run x WHERE x.id = mark_purged.run;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such run %', run USING ERRCODE = 'P0002';
  END IF;
  WITH u AS (
    UPDATE report.file f SET purged_at = now() WHERE f.run_id = r.id AND f.format = ANY (formats) AND f.purged_at IS NULL RETURNING f.format)
  SELECT count(*), array_agg(u.format ORDER BY u.format) INTO n, done FROM u;
  IF n > 0 THEN
    PERFORM report.emit('report.files_purged', 'info', 'system:risk', r.id, r.bu_id, jsonb_build_object('kind', r.kind,
      'formats', array_to_string(done, ' '), 'files', n::text));
  END IF;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION report.files_due(integer, integer), report.mark_purged(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.files_due(integer, integer), report.mark_purged(uuid, text[]) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

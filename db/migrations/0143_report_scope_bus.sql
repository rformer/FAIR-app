-- F-010 T-17 (F-010-AC-01, AC-15, AC-19; design §6): the report pages'
-- business unit pickers.
--
--   * report.scope_bus(permission): the live BUs where the caller holds
--     report.view or report.export (by authz.grant_snapshot, the rule
--     authz.Check applies: assignments with their subtrees, paths not
--     blocked by a restricted BU), with code and name. Any other permission
--     is refused (PF029). A caller without a valid context gets nothing.

GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO report_definer;
GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

CREATE FUNCTION report.scope_bus(permission text) RETURNS TABLE (id uuid, code text, name text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF permission IS NULL OR permission NOT IN ('report.view', 'report.export') THEN
    RAISE EXCEPTION 'report: permission is report.view or report.export' USING ERRCODE = 'PF029', HINT = 'invalid_value';
  END IF;
  RETURN QUERY
    SELECT b.id, b.code, b.name FROM iam.bu b
    WHERE b.archived_at IS NULL
      AND b.id IN (SELECT unnest(g.bus) FROM authz.grant_snapshot() g WHERE g.permission = scope_bus.permission)
    ORDER BY b.name, b.code;
END $$;
REVOKE ALL ON FUNCTION report.scope_bus(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.scope_bus(text) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

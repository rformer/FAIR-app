-- F-010 T-11 (F-010-AC-01, AC-08; design §3.1, §3.4): the portfolio's
-- business units below.
--
--   * report.child_bus(bu): bu's direct, live children that the caller
--     reads in the register, by name; children they do not read are not
--     named (the report counts them through authz.rollup_coverage).

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

CREATE FUNCTION report.child_bus(bu uuid) RETURNS TABLE (id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.id, b.name FROM iam.bu b
  WHERE b.parent_id = child_bus.bu AND b.archived_at IS NULL AND b.id = ANY (authz.visible_bus('register', 'read'))
  ORDER BY b.name, b.id;
$$;
REVOKE ALL ON FUNCTION report.child_bus(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.child_bus(uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

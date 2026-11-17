-- F-010 T-10 (F-010-AC-08, AC-10; design §3.4): names in reports.
--
--   * report.people(ids): the display names of those of ids who read the
--     register at a business unit where the caller reads it (risk owners,
--     action owners and the people a report names come from there), as
--     register.owners lists candidates; nobody else's name. A report's
--     reader calls it once under the requester's delegated context.

GRANT SELECT (email) ON iam.app_user TO report_definer;
GRANT SELECT (read_bus) ON authz.user_scope TO report_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text) TO report_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

CREATE FUNCTION report.people(ids uuid[]) RETURNS TABLE (user_id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH seen AS (SELECT authz.visible_bus('register', 'read') AS bus)
  SELECT u.id, coalesce(u.display_name, u.email) FROM iam.app_user u, seen
  WHERE u.id = ANY (people.ids) AND cardinality(seen.bus) > 0
    AND EXISTS (SELECT 1 FROM authz.user_scope s, jsonb_array_elements_text(s.read_bus -> 'register') b
                WHERE s.user_id = u.id AND b::uuid = ANY (seen.bus));
$$;
REVOKE ALL ON FUNCTION report.people(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.people(uuid[]) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;

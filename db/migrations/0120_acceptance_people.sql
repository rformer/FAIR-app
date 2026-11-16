-- F-008 T-07 (F-008-AC-16, AC-19; design §6): names for the pages.
-- acceptance.people(ids): the display names of the given users who
-- requested, or took a step on, an acceptance the caller reads (as
-- register.owner_names for owners), in one call per page.

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
GRANT EXECUTE ON FUNCTION iam.user_display_names(uuid[]) TO acceptance_definer;
SET ROLE acceptance_definer;
CREATE FUNCTION acceptance.people(ids uuid[]) RETURNS TABLE (user_id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH seen AS (SELECT authz.visible_bus('acceptance', 'read') AS bus)
  SELECT n.id, n.display_name FROM iam.user_display_names(people.ids) n, seen
  WHERE EXISTS (SELECT 1 FROM acceptance.acceptance x WHERE x.requested_by = n.id AND x.bu_id = ANY (seen.bus))
     OR EXISTS (SELECT 1 FROM acceptance.step s WHERE s.actor = n.id AND s.bu_id = ANY (seen.bus))
$$;
REVOKE ALL ON FUNCTION acceptance.people(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.people(uuid[]) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

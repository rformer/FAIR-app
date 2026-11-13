-- F-005 T-13 (F-005-AC-01, AC-18; design §5): the BUs where a page may
-- offer to run simulations or request aggregates. risk.scope_bus (0092)
-- also answers for resource type analysis, so the scenario page offers a run
-- only where the caller holds analysis.run, and the aggregate form lists
-- those BUs with their names.

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;
CREATE OR REPLACE FUNCTION risk.scope_bus(resource_type text, mode text) RETURNS TABLE (id uuid, code text, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.id, b.code, b.name FROM iam.bu b
  WHERE resource_type IN ('scenario', 'library', 'control', 'analysis') AND mode IN ('read', 'write')
    AND b.archived_at IS NULL AND b.id = ANY (authz.visible_bus(resource_type, mode))
  ORDER BY b.name, b.code;
$$;
REVOKE ALL ON FUNCTION risk.scope_bus(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.scope_bus(text, text) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;

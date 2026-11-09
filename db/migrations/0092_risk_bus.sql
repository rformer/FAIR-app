-- F-003 T-12 (F-003-AC-27; design §5): the BUs a risk page may offer.
--
-- Risk roles hold no bu.view, so the scenario editor could not offer the
-- BUs a scenario may be created in, nor pages show BU names. risk.scope_bus
-- returns id, code and name of the BUs in the caller's own scope for a risk
-- resource type (read or write), from the signed context: nothing outside
-- it, and no archived BU.

GRANT SELECT (id, code, name, archived_at) ON iam.bu TO risk_definer;
GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;
CREATE FUNCTION risk.scope_bus(resource_type text, mode text) RETURNS TABLE (id uuid, code text, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.id, b.code, b.name FROM iam.bu b
  WHERE resource_type IN ('scenario', 'library', 'control') AND mode IN ('read', 'write')
    AND b.archived_at IS NULL AND b.id = ANY (authz.visible_bus(resource_type, mode))
  ORDER BY b.name, b.code;
$$;
REVOKE ALL ON FUNCTION risk.scope_bus(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.scope_bus(text, text) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;

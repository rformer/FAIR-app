-- F-007 T-08 (F-007-AC-01, AC-19; design §6): what the register pages
-- choose from and show.
--
--   * register.scope_bus(resource_type, mode): the BUs where the caller
--     holds register or treatment read or write scope, with code and name,
--     for the pages' business unit pickers (as risk.scope_bus for F-003).
--   * register.owners(bu): the users who may own a risk at bu (register.view
--     there by their materialized scope, the rule register.check_risk
--     applies), names only, for a holder of register.edit at bu.
--   * register.owner_name(risk): the display name of the owner of a risk
--     the caller sees.

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

CREATE FUNCTION register.scope_bus(resource_type text, mode text) RETURNS TABLE (id uuid, code text, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT b.id, b.code, b.name FROM iam.bu b
  WHERE resource_type IN ('register', 'treatment') AND mode IN ('read', 'write')
    AND b.archived_at IS NULL AND b.id = ANY (authz.visible_bus(resource_type, mode))
  ORDER BY b.name, b.code
$$;

CREATE FUNCTION register.owners(bu uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM register.actor();
  IF bu IS NULL OR NOT bu = ANY (authz.visible_bus('register', 'write')) THEN
    RAISE EXCEPTION 'register: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('user_id', x.id, 'name', x.name) ORDER BY x.name, x.id)
                   FROM (SELECT u.id, coalesce(u.display_name, u.email) AS name FROM authz.user_scope s JOIN iam.app_user u ON u.id = s.user_id
                         WHERE (s.read_bus -> 'register') ? bu::text AND u.status = 'active' ORDER BY 2, 1 LIMIT 500) x), '[]');
END $$;

CREATE FUNCTION register.owner_name(risk uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(u.display_name, u.email) FROM register.risk r JOIN iam.app_user u ON u.id = r.owner
  WHERE r.id = owner_name.risk AND r.bu_id = ANY (authz.visible_bus('register', 'read'))
$$;

REVOKE ALL ON FUNCTION register.scope_bus(text, text), register.owners(uuid), register.owner_name(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.scope_bus(text, text), register.owners(uuid), register.owner_name(uuid) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

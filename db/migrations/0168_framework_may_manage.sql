-- F-013 T-10 (F-013-AC-01, AC-06; design §6): the pages offer imports and
-- retirements only to those who may make them. framework.may_manage(): true
-- when the caller holds framework.manage at the top business unit (the
-- check framework.manager makes), answered on the frameworks listing.

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE FUNCTION framework.may_manage() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(iam.holds_permission(framework.actor(), 'framework.manage', framework.root()), false);
$$;
REVOKE ALL ON FUNCTION framework.may_manage() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.may_manage() TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

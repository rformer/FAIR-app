-- F-010 T-18 (requirements NFR "Performance"; design §9): register.subtree
-- and acceptance.subtree read the caller's scope once per call, not once
-- per closure row. As first written (0109, 0118), `= ANY
-- (authz.visible_bus(...))` was evaluated for every row of the BU's closure
-- (2,011 at the root at the target scale: over a second); as a scalar
-- sub-select it is an InitPlan, evaluated once. Same results.

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;
CREATE OR REPLACE FUNCTION register.subtree(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id FROM iam.bu_closure c
  WHERE c.ancestor_id = subtree.bu AND c.descendant_id = ANY ((SELECT authz.visible_bus('register', 'read'))::uuid[])
$$;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;
CREATE OR REPLACE FUNCTION acceptance.subtree(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id FROM iam.bu_closure c
  WHERE c.ancestor_id = subtree.bu AND c.descendant_id = ANY ((SELECT authz.visible_bus('acceptance', 'read'))::uuid[])
$$;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

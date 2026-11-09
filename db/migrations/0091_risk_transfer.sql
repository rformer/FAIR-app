-- F-003 T-11 (F-003-AC-24; design §6.5): exporting a BU subtree.
--
-- An export may select everything the requester sees in a BU's subtree.
-- app_rw cannot read the BU tree; risk.in_subtree answers, for a row's BU,
-- whether it is the root or below it. It reveals only that, for BUs the
-- caller names, and RLS still decides which rows exist for them.

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;
CREATE FUNCTION risk.in_subtree(root uuid, bu uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = root AND c.descendant_id = bu);
$$;
REVOKE ALL ON FUNCTION risk.in_subtree(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.in_subtree(uuid, uuid) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;

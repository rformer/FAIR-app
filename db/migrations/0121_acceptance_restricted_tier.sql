-- F-008 (design §3.4, amended 2026-11-15 with Robert Former): a tier's BU
-- never leaves the risk's restricted subtree. For a risk inside a restricted
-- BU, levels up stop at the top of its nearest restricted subtree
-- (iam.restricted_root), and tier 3 (the root otherwise) is that top: the
-- approvers above it could not see the acceptance (F-001 restricted BUs,
-- RLS), so it would sit undecidable and outside every inbox.
--
-- acceptance.tier_bu is replaced (request, the job's higher-tier review and
-- the move trigger all call it), and open acceptances inside restricted
-- subtrees have their tier's BU resolved again from their tier's snapshot.

GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO acceptance_definer;
GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;

CREATE OR REPLACE FUNCTION acceptance.tier_bu(bu uuid, levels_up integer) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH top AS (
    SELECT coalesce(iam.restricted_root(tier_bu.bu), (SELECT r.id FROM iam.bu r WHERE r.parent_id IS NULL)) AS id
  ), floor AS (
    SELECT t.id, b.depth FROM top t JOIN iam.bu b ON b.id = t.id
  )
  SELECT CASE WHEN levels_up IS NULL THEN (SELECT id FROM floor)
    ELSE (SELECT c.ancestor_id FROM iam.bu_closure c JOIN iam.bu a ON a.id = c.ancestor_id
          WHERE c.descendant_id = tier_bu.bu
            AND a.depth = greatest((SELECT depth FROM floor), (SELECT b.depth FROM iam.bu b WHERE b.id = tier_bu.bu) - levels_up)) END
$$;

UPDATE acceptance.acceptance x
SET tier_bu_id = acceptance.tier_bu(x.bu_id, (SELECT (s.data #>> '{tier,levels_up}')::integer FROM acceptance.step s
                                               WHERE s.acceptance_id = x.id AND s.kind IN ('requested', 'review_requested') ORDER BY s.n DESC LIMIT 1))
WHERE x.state IN ('pending', 'active', 'suspended') AND iam.restricted_root(x.bu_id) IS NOT NULL;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

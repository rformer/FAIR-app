-- F-008 T-05 (F-008-AC-15, AC-19; design §3.2, §6):
--   * acceptance.subtree(bu): the BUs of bu's subtree where the caller reads
--     acceptances, for the list's business unit filter (app_rw does not read
--     the BU tree itself), as register.subtree for the register;
--   * as 0117, but a moved risk's active acceptance too has its tier's BU
--     resolved again from the new BU: the approvers who may revoke it are
--     those who could approve it where it now is (it still needs review,
--     moved, against approved_bu_id).

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;
CREATE FUNCTION acceptance.subtree(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id FROM iam.bu_closure c
  WHERE c.ancestor_id = subtree.bu AND c.descendant_id = ANY (authz.visible_bus('acceptance', 'read'))
$$;
CREATE OR REPLACE FUNCTION acceptance.risk_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a acceptance.acceptance; u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF NEW.state = 'closed' AND OLD.state = 'open' THEN
    FOR a IN SELECT * FROM acceptance.acceptance x WHERE x.risk_id = NEW.id AND x.state IN ('pending', 'active', 'suspended') FOR UPDATE LOOP
      PERFORM acceptance.add_step(a.id, 'ended', u, 'the risk was closed', jsonb_build_object('end_reason', 'risk_closed'));
      UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'risk_closed', ended_at = now() WHERE x.id = a.id;
      PERFORM acceptance.emit('acceptance.ended', 'low', coalesce(u::text, 'system:risk'), a.id, a.bu_id,
        jsonb_build_object('risk', NEW.id::text, 'end_reason', 'risk_closed'));
    END LOOP;
  END IF;
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    UPDATE acceptance.step s SET bu_id = NEW.bu_id WHERE s.acceptance_id IN (SELECT x.id FROM acceptance.acceptance x WHERE x.risk_id = NEW.id);
    UPDATE acceptance.acceptance x SET bu_id = NEW.bu_id,
      tier_bu_id = CASE WHEN x.state IN ('pending', 'active', 'suspended')
        THEN acceptance.tier_bu(NEW.bu_id, (SELECT (s.data #>> '{tier,levels_up}')::integer FROM acceptance.step s
                                            WHERE s.acceptance_id = x.id AND s.kind IN ('requested', 'review_requested') ORDER BY s.n DESC LIMIT 1))
        ELSE x.tier_bu_id END
    WHERE x.risk_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION acceptance.subtree(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.subtree(uuid) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

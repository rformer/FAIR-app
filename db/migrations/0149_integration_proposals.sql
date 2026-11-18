-- F-011 T-09 (F-011-AC-10, AC-12, AC-14; design §3.4 as amended
-- 2026-11-18): proposals from a run.
--
--   * A proposal holds the source record's values and digest; the merged
--     document is computed at review under the reviewer's RLS (T-10), so
--     update proposals carry no base_version (the 0145 check relaxed:
--     only a create has none by rule).
--   * integration.last_applied(id, external_ids): the record each link was
--     last accepted from (for descriptive-only changes, AC-13).
--   * integration.propose(run, proposals): the run's proposals, each
--     superseding the link's pending one; for a complete run, archive
--     proposals for the integration's linked assets and asset groups the
--     run did not hold (AC-14), filed under the BU they were last accepted
--     at, once while one is pending. Business units inside the
--     integration's subtree only.

DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
  WHERE conrelid = 'integration.proposal'::regclass AND contype = 'c'
    AND pg_get_constraintdef(oid) LIKE '%(action = ''create''::text) = (base_version IS NULL)%';
  IF c IS NULL THEN
    RAISE EXCEPTION 'integration.proposal: the base_version check is not where 0145 put it';
  END IF;
  EXECUTE format('ALTER TABLE integration.proposal DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE integration.proposal ADD CONSTRAINT proposal_create_no_base CHECK (action <> 'create' OR base_version IS NULL);

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.last_applied(id uuid, external_ids text[]) RETURNS TABLE (external_id text, document jsonb, bu_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.pushable(id);
BEGIN
  RETURN QUERY SELECT DISTINCT ON (p.external_id) p.external_id, p.document, p.bu_id
    FROM integration.proposal p JOIN integration.applied a ON a.proposal_id = p.id
    WHERE p.integration_id = i.id AND p.external_id = ANY (external_ids)
    ORDER BY p.external_id, a.accepted_at DESC;
END $$;

CREATE FUNCTION integration.propose(run uuid, proposals jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r integration.run := integration.my_run(run); i integration.integration; x jsonb; n integer := 0; k integer;
BEGIN
  SELECT * INTO i FROM integration.integration WHERE integration.id = r.integration_id;
  IF jsonb_typeof(proposals) <> 'array' OR jsonb_array_length(proposals) > 10000 THEN
    RAISE EXCEPTION 'integration: at most 10,000 proposals in a run' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  FOR x IN SELECT * FROM jsonb_array_elements(proposals) LOOP
    IF NOT EXISTS (SELECT 1 FROM iam.bu_closure c JOIN iam.bu b ON b.id = c.descendant_id AND b.archived_at IS NULL
                   WHERE c.ancestor_id = i.bu_id AND c.descendant_id = (x ->> 'bu_id')::uuid AND NOT c.blocked) THEN
      RAISE EXCEPTION 'integration: a proposal''s business unit is outside the integration''s subtree' USING ERRCODE = 'PF031', HINT = 'invalid_value';
    END IF;
    UPDATE integration.proposal p SET state = 'superseded'
    WHERE p.integration_id = i.id AND p.external_id = x ->> 'external_id' AND p.state = 'pending';
    INSERT INTO integration.proposal (integration_id, run_id, bu_id, target_type, target_id, external_id, action, document, digest, descriptive_only)
    VALUES (i.id, r.id, (x ->> 'bu_id')::uuid, x ->> 'target_type', (x ->> 'target_id')::uuid, x ->> 'external_id', x ->> 'action',
            x -> 'document', x ->> 'digest', coalesce((x ->> 'descriptive_only')::boolean, false));
    n := n + 1;
  END LOOP;
  IF r.complete THEN
    -- Linked assets and groups the source no longer holds: a pending update
    -- gives way to the archive; a pending archive stays as it is.
    UPDATE integration.proposal p SET state = 'superseded'
    FROM integration.link l
    WHERE p.integration_id = i.id AND p.external_id = l.external_id AND p.state = 'pending' AND p.action <> 'archive'
      AND l.integration_id = i.id AND l.target_type IN ('asset', 'asset_group')
      AND NOT EXISTS (SELECT 1 FROM integration.record d WHERE d.run_id = r.id AND d.external_id = l.external_id);
    INSERT INTO integration.proposal (integration_id, run_id, bu_id, target_type, target_id, external_id, action)
    SELECT i.id, r.id,
      coalesce((SELECT p.bu_id FROM integration.proposal p JOIN integration.applied a ON a.proposal_id = p.id
                WHERE p.integration_id = i.id AND p.external_id = l.external_id ORDER BY a.accepted_at DESC LIMIT 1), i.bu_id),
      l.target_type, l.target_id, l.external_id, 'archive'
    FROM integration.link l
    WHERE l.integration_id = i.id AND l.target_type IN ('asset', 'asset_group')
      AND NOT EXISTS (SELECT 1 FROM integration.record d WHERE d.run_id = r.id AND d.external_id = l.external_id)
      AND NOT EXISTS (SELECT 1 FROM integration.proposal p WHERE p.integration_id = i.id AND p.external_id = l.external_id AND p.state = 'pending');
    GET DIAGNOSTICS k = ROW_COUNT;
    n := n + k;
  END IF;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION integration.last_applied(uuid, text[]), integration.propose(uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.last_applied(uuid, text[]), integration.propose(uuid, jsonb) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

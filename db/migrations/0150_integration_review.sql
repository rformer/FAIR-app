-- F-011 T-10a (F-011-AC-10 to AC-12, AC-14, AC-25, AC-26; design §3.4 as
-- amended, §3.8): reviewing proposals, in the risk service (app_rw) for the
-- user named by the signed DB context.
--
--   * Visibility: a proposal is the business of the holders of its kind's
--     view permission at its BU (asset, asset group: library.view; control:
--     control.view; risk: register.view), from the caller's grant snapshot,
--     read once per call.
--   * integration.proposals(...) lists them; integration.proposal_get(id)
--     reads one, with its integration and run (P0002 otherwise).
--   * integration.accepted(id, target, version): after the risk service
--     wrote the target's version through its own save code in this
--     transaction (or archived it), marks the proposal accepted, records
--     the provenance (integration.applied; none for an archive) and sets the
--     link (an archive removes it), with integration.proposal_accepted. The
--     caller holds the kind's edit permission at the proposal's BU.
--   * integration.reject(id, reason): with integration.proposal_rejected;
--     the link remembers the rejected digest (AC-12).
--   * Decided proposals do not change (PF031 proposal_decided, 409).

GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO integration_definer;
GRANT DELETE ON integration.link TO integration_definer;
GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.view_permission(target_type text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE target_type WHEN 'asset' THEN 'library.view' WHEN 'asset_group' THEN 'library.view' WHEN 'reference_class' THEN 'library.view'
    WHEN 'control' THEN 'control.view' WHEN 'risk' THEN 'register.view' END;
$$;

CREATE FUNCTION integration.edit_permission(target_type text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE target_type WHEN 'asset' THEN 'library.edit' WHEN 'asset_group' THEN 'library.edit' WHEN 'reference_class' THEN 'library.edit'
    WHEN 'control' THEN 'control.edit' WHEN 'risk' THEN 'register.edit' END;
$$;

CREATE FUNCTION integration.proposal_json(p integration.proposal) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', p.id, 'integration_id', p.integration_id, 'integration_name', i.name, 'run_id', p.run_id,
    'run_started_at', r.started_at, 'bu_id', p.bu_id, 'bu_name', b.name, 'target_type', p.target_type, 'target_id', p.target_id,
    'external_id', p.external_id, 'action', p.action, 'record', p.document, 'digest', p.digest, 'descriptive_only', p.descriptive_only,
    'state', p.state, 'decided_by', p.decided_by, 'decided_by_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = p.decided_by),
    'decided_at', p.decided_at, 'reason', p.reason, 'created_at', p.created_at)
  FROM integration.integration i, integration.run r, iam.bu b
  WHERE i.id = p.integration_id AND r.id = p.run_id AND b.id = p.bu_id;
$$;

-- The BUs where the caller holds perm (the grant snapshot: subtrees,
-- restricted paths blocked), read once.
CREATE FUNCTION integration.bus_with(perm text) RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((SELECT g.bus FROM authz.grant_snapshot() g WHERE g.permission = perm), '{}');
$$;

CREATE FUNCTION integration.proposals(state text, target_type text, integration uuid, bu uuid, lim integer, off integer) RETURNS SETOF jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); lib uuid[] := integration.bus_with('library.view'); ctl uuid[] := integration.bus_with('control.view');
        reg uuid[] := integration.bus_with('register.view');
BEGIN
  RETURN QUERY SELECT integration.proposal_json(p) FROM integration.proposal p
    WHERE (proposals.state IS NULL OR p.state = proposals.state)
      AND (proposals.target_type IS NULL OR p.target_type = proposals.target_type)
      AND (proposals.integration IS NULL OR p.integration_id = proposals.integration)
      AND (proposals.bu IS NULL OR p.bu_id IN (SELECT c.descendant_id FROM iam.bu_closure c WHERE c.ancestor_id = proposals.bu AND NOT c.blocked))
      AND p.bu_id = ANY (CASE integration.view_permission(p.target_type) WHEN 'library.view' THEN lib WHEN 'control.view' THEN ctl ELSE reg END)
    ORDER BY p.seq DESC
    LIMIT least(coalesce(lim, 50), 200) OFFSET greatest(coalesce(off, 0), 0);
END $$;

CREATE FUNCTION integration.visible_proposal(id uuid, lock boolean) RETURNS integration.proposal
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); p integration.proposal;
BEGIN
  IF lock THEN
    SELECT * INTO p FROM integration.proposal x WHERE x.id = visible_proposal.id FOR UPDATE;
  ELSE
    SELECT * INTO p FROM integration.proposal x WHERE x.id = visible_proposal.id;
  END IF;
  IF p.id IS NULL OR NOT iam.holds_permission(u, integration.view_permission(p.target_type), p.bu_id) THEN
    RAISE EXCEPTION 'integration: no such proposal %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN p;
END $$;

CREATE FUNCTION integration.proposal_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN integration.proposal_json(integration.visible_proposal(id, false));
END $$;

-- A pending proposal the caller may decide: its kind's edit permission at
-- its BU (42501 otherwise).
CREATE FUNCTION integration.decidable(id uuid) RETURNS integration.proposal
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); p integration.proposal := integration.visible_proposal(id, true);
BEGIN
  IF NOT iam.holds_permission(u, integration.edit_permission(p.target_type), p.bu_id) THEN
    RAISE EXCEPTION 'integration: deciding this proposal needs % at its business unit', integration.edit_permission(p.target_type)
      USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF p.state <> 'pending' THEN
    RAISE EXCEPTION 'integration: the proposal was decided (%)', p.state USING ERRCODE = 'PF031', HINT = 'proposal_decided';
  END IF;
  RETURN p;
END $$;

CREATE FUNCTION integration.decision_event(type text, u uuid, p integration.proposal, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'low', 'actor', u::text, 'target', 'integration_proposal:' || p.id,
    'bu_id', p.bu_id, 'attributes', attrs || jsonb_build_object('proposal', p.id::text, 'integration', p.integration_id::text,
      'external_id', p.external_id, 'action', p.action, 'target_type', p.target_type)));
$$;

CREATE FUNCTION integration.accepted(id uuid, target uuid, version integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); p integration.proposal := integration.decidable(id);
BEGIN
  IF target IS NULL OR (p.target_id IS NOT NULL AND target <> p.target_id) THEN
    RAISE EXCEPTION 'integration: the accepted target is not the proposal''s' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  UPDATE integration.proposal x SET state = 'accepted', decided_by = u, decided_at = now() WHERE x.id = p.id RETURNING * INTO p;
  IF p.action = 'archive' THEN
    DELETE FROM integration.link l WHERE l.integration_id = p.integration_id AND l.external_id = p.external_id;
  ELSE
    INSERT INTO integration.applied (proposal_id, target_type, target_id, version, accepted_by) VALUES (p.id, p.target_type, target, version, u);
    INSERT INTO integration.link (integration_id, external_id, target_type, target_id, last_digest)
    VALUES (p.integration_id, p.external_id, p.target_type, target, p.digest)
    ON CONFLICT ON CONSTRAINT link_pkey DO UPDATE SET last_digest = EXCLUDED.last_digest, rejected_digest = NULL, updated_at = now();
  END IF;
  PERFORM integration.decision_event('integration.proposal_accepted', u, p, jsonb_build_object('target', target::text,
    'version', coalesce(version::text, '')));
  RETURN integration.proposal_json(p);
END $$;

CREATE FUNCTION integration.reject(id uuid, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); p integration.proposal := integration.decidable(id);
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'integration: rejecting needs a reason (at most 500 characters)' USING ERRCODE = 'PF031', HINT = 'reason_required';
  END IF;
  UPDATE integration.proposal x SET state = 'rejected', decided_by = u, decided_at = now(), reason = btrim(reject.reason) WHERE x.id = p.id RETURNING * INTO p;
  IF p.digest IS NOT NULL THEN
    UPDATE integration.link l SET rejected_digest = p.digest, updated_at = now() WHERE l.integration_id = p.integration_id AND l.external_id = p.external_id;
  END IF;
  PERFORM integration.decision_event('integration.proposal_rejected', u, p, jsonb_build_object('reason', p.reason));
  RETURN integration.proposal_json(p);
END $$;

-- The links of an integration's external IDs, for an asset group's members
-- (the reviewer's merge reads their heads under RLS).
CREATE FUNCTION integration.members(id uuid, external_ids text[]) RETURNS TABLE (external_id text, target_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE p integration.proposal := integration.visible_proposal(id, false);
BEGIN
  RETURN QUERY SELECT l.external_id, l.target_id FROM integration.link l
    WHERE l.integration_id = p.integration_id AND l.external_id = ANY (external_ids) AND l.target_type = 'asset';
END $$;

REVOKE ALL ON FUNCTION integration.view_permission(text), integration.edit_permission(text), integration.proposal_json(integration.proposal),
  integration.bus_with(text), integration.proposals(text, text, uuid, uuid, integer, integer), integration.visible_proposal(uuid, boolean),
  integration.proposal_get(uuid), integration.decidable(uuid), integration.decision_event(text, uuid, integration.proposal, jsonb),
  integration.accepted(uuid, uuid, integer), integration.reject(uuid, text), integration.members(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.proposals(text, text, uuid, uuid, integer, integer), integration.proposal_get(uuid),
  integration.accepted(uuid, uuid, integer), integration.reject(uuid, text), integration.members(uuid, text[]) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;

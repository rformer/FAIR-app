-- F-001 T-30b (AC-15, AC-16, AC-17; design §6 /bus): BU administration.
--
--   * Authority (decided by Robert Former 2026-11-03), from the signed
--     context: create needs bu.manage at the parent; rename and archive at
--     the BU or its parent (as T-31's import); a move at the BU's current
--     parent and at the new parent, so nobody moves a subtree out of, or
--     into, a place they do not administer. A BU the caller can neither see
--     (bu.view) nor manage is "not found". Every change takes a reason and
--     is audited high.
--   * Moves are shown before they apply: iam.bu_move returns a preview
--     (parents, depth, restricted subtrees left and entered, the BUs whose
--     assignments gain or lose the BU, and how many live assignments that
--     is) with a fingerprint; the move applies only when the caller sends
--     that fingerprint back, so a tree that changed meanwhile asks again.
--     Leaving a restricted subtree, for a BU that is not itself restricted,
--     exposes its data beyond the wall, like un-restricting (AC-63): it
--     needs a second administrator's approval (kind bu.move_out, approver
--     bu.restrict at the wall's parent), then /bus/apply moves it if the
--     preview is still the same. The closure and scopes follow through the
--     existing triggers and outbox (AC-17).
--   * Archive is refused for the root, while the BU has live children, and
--     while it owns active records (T-31's guard).
--   * Maximum depth (AC-15): iam.bu_config.max_depth, set by a bu.manage
--     holder at the root, 1 to 32, never below the tree's current depth.

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('bu.move_out', 'bu.restrict', 'Move a BU out of a restricted subtree (F-001 AC-17, AC-63)');

-- Whether u may see or manage b at all (else it is "not found").
CREATE FUNCTION iam.bu_reachable(u uuid, b iam.bu) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(u, 'bu.view', b.id) OR iam.bu_manages(u, b)
      OR (b.parent_id IS NOT NULL AND iam.user_has_permission(u, 'bu.restrict', b.parent_id));
$$;

CREATE FUNCTION iam.bu_require_reason(reason text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
END $$;

-- A live BU the caller may see, locked (P0002 otherwise).
CREATE FUNCTION iam.bu_target(u uuid, target uuid) RETURNS iam.bu
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b iam.bu;
BEGIN
  SELECT * INTO b FROM iam.bu x WHERE x.id = target AND x.archived_at IS NULL FOR UPDATE;
  IF NOT FOUND OR NOT iam.bu_reachable(u, b) THEN
    RAISE EXCEPTION 'no BU %', target USING ERRCODE = 'P0002';
  END IF;
  RETURN b;
END $$;

-- Create -------------------------------------------------------------------------

CREATE FUNCTION iam.bu_create(parent uuid, bu_code text, bu_name text, want_restricted boolean, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
  p     iam.bu;
  b     iam.bu;
  maxd  smallint := (SELECT c.max_depth FROM iam.bu_config c);
BEGIN
  PERFORM iam.bu_require_reason(reason);
  SELECT * INTO p FROM iam.bu x WHERE x.id = parent;
  IF NOT FOUND OR NOT iam.bu_reachable(actor, p) THEN
    RAISE EXCEPTION 'no parent BU %', parent USING ERRCODE = 'PF004';
  END IF;
  IF p.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'the parent BU % is archived', p.code USING ERRCODE = 'PF003';
  END IF;
  IF NOT iam.user_has_permission(actor, 'bu.manage', p.id) THEN
    RAISE EXCEPTION 'bu.manage is required at the parent' USING ERRCODE = 'PF008';
  END IF;
  IF p.depth + 1 > maxd THEN
    RAISE EXCEPTION 'a BU under % would be at depth %; the maximum is %', p.code, p.depth + 1, maxd USING ERRCODE = 'PF003';
  END IF;
  IF want_restricted IS FALSE AND iam.new_bu_restricted() THEN
    RAISE EXCEPTION 'new BUs are restricted here; un-restricting needs a second administrator''s approval (/bus/{id}/restriction)'
      USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.bu (name, code, parent_id, restricted, created_by, updated_by)
  VALUES (btrim(bu_name), btrim(bu_code), p.id, coalesce(want_restricted, iam.new_bu_restricted()), actor, actor) RETURNING * INTO b;
  PERFORM iam.bu_event('bu.created', actor, b, btrim(reason), jsonb_build_object('parent', p.code, 'source', 'api'));
  RETURN b.id;
END $$;

-- Rename -------------------------------------------------------------------------

CREATE FUNCTION iam.bu_rename(target uuid, bu_name text, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
  b     iam.bu := iam.bu_target(actor, target);
  was   text := b.name;
BEGIN
  PERFORM iam.bu_require_reason(reason);
  IF NOT iam.bu_manages(actor, b) THEN
    RAISE EXCEPTION 'bu.manage is required at the BU or its parent' USING ERRCODE = 'PF008';
  END IF;
  IF btrim(coalesce(bu_name, '')) = was THEN
    RAISE EXCEPTION 'the BU is named % already', was USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.bu x SET name = btrim(bu_name), updated_at = now(), updated_by = actor WHERE x.id = target RETURNING * INTO b;
  PERFORM iam.bu_event('bu.renamed', actor, b, btrim(reason), jsonb_build_object('from', was, 'source', 'api'));
END $$;

-- Archive ------------------------------------------------------------------------

CREATE FUNCTION iam.bu_archive(target uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
  b     iam.bu := iam.bu_target(actor, target);
  kids  text;
BEGIN
  PERFORM iam.bu_require_reason(reason);
  IF NOT iam.bu_manages(actor, b) THEN
    RAISE EXCEPTION 'bu.manage is required at the BU or its parent' USING ERRCODE = 'PF008';
  END IF;
  IF b.parent_id IS NULL THEN
    RAISE EXCEPTION 'the root BU cannot be archived' USING ERRCODE = 'PF003';
  END IF;
  SELECT string_agg(x.code, ', ' ORDER BY x.code) INTO kids FROM iam.bu x WHERE x.parent_id = target AND x.archived_at IS NULL;
  IF kids IS NOT NULL THEN
    RAISE EXCEPTION 'BU % has children (%); move or archive them first', b.code, kids USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.bu x SET archived_at = now(), updated_at = now(), updated_by = actor WHERE x.id = target RETURNING * INTO b;
  PERFORM iam.bu_event('bu.archived', actor, b, btrim(reason), NULL);
END $$;

-- Move ---------------------------------------------------------------------------

-- What moving b under np changes, with a fingerprint over it.
CREATE FUNCTION iam.bu_move_preview(b iam.bu, np iam.bu) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH before AS (SELECT c.ancestor_id AS id, c.blocked FROM iam.bu_closure c WHERE c.descendant_id = b.id AND c.depth > 0),
  after AS (SELECT c.ancestor_id AS id, (c.blocked OR b.restricted) AS blocked FROM iam.bu_closure c WHERE c.descendant_id = np.id),
  gained AS (SELECT id FROM after WHERE NOT blocked EXCEPT SELECT id FROM before WHERE NOT blocked),
  lost AS (SELECT id FROM before WHERE NOT blocked EXCEPT SELECT id FROM after WHERE NOT blocked),
  left_r AS (SELECT x.code, x.depth, x.parent_id FROM before JOIN iam.bu x ON x.id = before.id
             WHERE x.restricted AND before.id NOT IN (SELECT id FROM after)),
  entered_r AS (SELECT x.code FROM after JOIN iam.bu x ON x.id = after.id
                WHERE x.restricted AND after.id NOT IN (SELECT id FROM before)),
  live AS (SELECT a.bu_id FROM iam.assignment a WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())),
  pv AS (
    SELECT jsonb_build_object(
      'bu_id', b.id, 'bu', b.code, 'restricted', b.restricted,
      'from_parent', (SELECT x.code FROM iam.bu x WHERE x.id = b.parent_id), 'to_parent', np.code, 'to_parent_id', np.id,
      'depth_after', np.depth + 1,
      'subtree_bus', (SELECT count(*) FROM iam.bu_closure c WHERE c.ancestor_id = b.id),
      'restricted_left', coalesce((SELECT jsonb_agg(l.code ORDER BY l.depth) FROM left_r l), '[]'),
      'restricted_entered', coalesce((SELECT jsonb_agg(e.code ORDER BY e.code) FROM entered_r e), '[]'),
      'reach_gained', coalesce((SELECT jsonb_agg(x.code ORDER BY x.depth, x.code) FROM gained g JOIN iam.bu x ON x.id = g.id), '[]'),
      'reach_lost', coalesce((SELECT jsonb_agg(x.code ORDER BY x.depth, x.code) FROM lost l JOIN iam.bu x ON x.id = l.id), '[]'),
      'assignments_gaining', (SELECT count(*) FROM live WHERE live.bu_id IN (SELECT id FROM gained)),
      'assignments_losing', (SELECT count(*) FROM live WHERE live.bu_id IN (SELECT id FROM lost)),
      'needs_approval', NOT b.restricted AND EXISTS (SELECT 1 FROM left_r),
      'approval_bu_id', CASE WHEN NOT b.restricted THEN (SELECT l.parent_id FROM left_r l ORDER BY l.depth LIMIT 1) END) AS v)
  SELECT pv.v || jsonb_build_object('confirm', encode(sha256(convert_to(pv.v::text, 'UTF8')), 'hex')) FROM pv;
$$;

-- Checks a move by actor (authority, cycle, depth) and returns its preview.
CREATE FUNCTION iam.bu_move_check(actor uuid, target uuid, parent uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b      iam.bu := iam.bu_target(actor, target);
  np     iam.bu;
  height integer;
  maxd   smallint := (SELECT c.max_depth FROM iam.bu_config c);
BEGIN
  IF b.parent_id IS NULL THEN
    RAISE EXCEPTION 'the root BU cannot be moved' USING ERRCODE = 'PF003';
  END IF;
  SELECT * INTO np FROM iam.bu x WHERE x.id = parent;
  IF NOT FOUND OR NOT iam.bu_reachable(actor, np) THEN
    RAISE EXCEPTION 'no parent BU %', parent USING ERRCODE = 'PF004';
  END IF;
  IF NOT iam.user_has_permission(actor, 'bu.manage', b.parent_id) OR NOT iam.user_has_permission(actor, 'bu.manage', np.id) THEN
    RAISE EXCEPTION 'bu.manage is required at the BU''s parent and at the new parent' USING ERRCODE = 'PF008';
  END IF;
  IF np.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'the new parent % is archived', np.code USING ERRCODE = 'PF003';
  END IF;
  IF np.id = b.parent_id THEN
    RAISE EXCEPTION 'BU % is under % already', b.code, np.code USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = b.id AND c.descendant_id = np.id) THEN
    RAISE EXCEPTION 'BU % cannot move under its own subtree (%)', b.code, np.code USING ERRCODE = 'PF003';
  END IF;
  SELECT max(c.depth) INTO height FROM iam.bu_closure c WHERE c.ancestor_id = b.id;
  IF np.depth + 1 + height > maxd THEN
    RAISE EXCEPTION 'the move would put BUs at depth %; the maximum is %', np.depth + 1 + height, maxd USING ERRCODE = 'PF003';
  END IF;
  RETURN iam.bu_move_preview(b, np);
END $$;

CREATE FUNCTION iam.bu_move_apply(actor uuid, pv jsonb, reason text, extra jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b iam.bu;
BEGIN
  UPDATE iam.bu x SET parent_id = (pv->>'to_parent_id')::uuid, updated_at = now(), updated_by = actor
  WHERE x.id = (pv->>'bu_id')::uuid RETURNING * INTO b;
  PERFORM iam.bu_event('bu.moved', actor, b, reason, jsonb_build_object('old_parent', pv->>'from_parent', 'new_parent', pv->>'to_parent',
    'restricted_left', pv->'restricted_left', 'restricted_entered', pv->'restricted_entered',
    'reach_gained', pv->'reach_gained', 'reach_lost', pv->'reach_lost', 'source', 'api') || coalesce(extra, '{}'));
END $$;

-- Preview (dry_run), refuse without the preview's fingerprint, ask for
-- approval when leaving a restricted subtree, or move. Returns
-- {status: preview | confirm_required | pending | moved, preview, approval_id}.
CREATE FUNCTION iam.bu_move(target uuid, parent uuid, reason text, confirm text, dry_run boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
  pv    jsonb := iam.bu_move_check(actor, target, parent);
  ap    uuid;
BEGIN
  IF dry_run THEN
    RETURN jsonb_build_object('status', 'preview', 'preview', pv);
  END IF;
  PERFORM iam.bu_require_reason(reason);
  IF confirm IS DISTINCT FROM pv->>'confirm' THEN
    RETURN jsonb_build_object('status', 'confirm_required', 'preview', pv);
  END IF;
  IF (pv->>'needs_approval')::boolean THEN
    ap := iam.request_approval('bu.move_out', 'bu:' || target || ':move:' || parent, btrim(reason),
      jsonb_build_object('bu_id', target, 'parent_id', parent, 'confirm', pv->>'confirm', 'preview', pv), (pv->>'approval_bu_id')::uuid);
    RETURN jsonb_build_object('status', 'pending', 'approval_id', ap, 'preview', pv);
  END IF;
  PERFORM iam.bu_move_apply(actor, pv, btrim(reason), NULL);
  RETURN jsonb_build_object('status', 'moved', 'preview', pv);
END $$;

-- Applies an approved un-restriction, roll-up loosening or move out of a
-- restricted subtree (0053 plus bu.move_out).
CREATE OR REPLACE FUNCTION iam.bu_apply_approval(approval uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  req   iam.approval_request;
  used  jsonb;
  target uuid;
  actor uuid;
  b     iam.bu;
  was   iam.bu_rollup_mode;
  pv    jsonb;
BEGIN
  SELECT * INTO req FROM iam.approval_request a WHERE a.id = approval AND a.kind IN ('bu.unrestrict', 'bu.rollup_loosen', 'bu.move_out');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no BU approval %', approval USING ERRCODE = 'P0002';
  END IF;
  target := (req.payload->>'bu_id')::uuid;
  IF req.kind = 'bu.move_out' THEN
    actor := iam.bu_manage_actor();
    pv := iam.bu_move_check(actor, target, (req.payload->>'parent_id')::uuid);
    used := iam.consume_approval(approval, req.kind, req.target_ref);
    IF pv->>'confirm' IS DISTINCT FROM req.payload->>'confirm' THEN
      RAISE EXCEPTION 'the tree changed since the move was requested; request it again' USING ERRCODE = 'PF003';
    END IF;
    PERFORM iam.bu_move_apply(actor, pv, req.reason,
      jsonb_build_object('requested_by', used->>'requested_by', 'approved_by', used->>'decided_by', 'approval', approval));
    RETURN 'moved';
  END IF;
  actor := iam.bu_admin_actor(target);
  used := iam.consume_approval(approval, req.kind, req.target_ref);  -- {payload, requested_by, decided_by} (0018)
  SELECT * INTO b FROM iam.bu x WHERE x.id = target FOR UPDATE;
  IF req.kind = 'bu.unrestrict' THEN
    IF NOT b.restricted THEN
      RAISE EXCEPTION 'the BU is unrestricted already' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.bu x SET restricted = false WHERE x.id = target RETURNING * INTO b;
    PERFORM iam.bu_event('bu.unrestricted', actor, b, req.reason,
      jsonb_build_object('requested_by', used->>'requested_by', 'approved_by', used->>'decided_by', 'approval', approval));
    RETURN 'unrestricted';
  END IF;
  was := b.rollup_mode;
  IF iam.rollup_rank((used->'payload'->>'mode')::iam.bu_rollup_mode) <= iam.rollup_rank(was) THEN
    RAISE EXCEPTION 'the roll-up mode changed since the request (now %)', was USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.bu x SET rollup_mode = (used->'payload'->>'mode')::iam.bu_rollup_mode WHERE x.id = target RETURNING * INTO b;
  PERFORM iam.bu_event('bu.rollup_loosened', actor, b, req.reason,
    jsonb_build_object('before', was, 'requested_by', used->>'requested_by', 'approved_by', used->>'decided_by', 'approval', approval));
  RETURN b.rollup_mode::text;
END $$;

-- Maximum depth (AC-15) --------------------------------------------------------------

CREATE FUNCTION iam.bu_depth_info() RETURNS TABLE (max_depth integer, deepest integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
BEGIN
  RETURN QUERY SELECT (SELECT c.max_depth::integer FROM iam.bu_config c),
    (SELECT coalesce(max(x.depth), 0)::integer FROM iam.bu x WHERE x.archived_at IS NULL);
END $$;

CREATE FUNCTION iam.bu_set_max_depth(n integer, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.bu_manage_actor();
  root  iam.bu;
  was   integer := (SELECT c.max_depth FROM iam.bu_config c);
  deep  iam.bu;
BEGIN
  PERFORM iam.bu_require_reason(reason);
  SELECT * INTO root FROM iam.bu x WHERE x.parent_id IS NULL;
  IF NOT iam.user_has_permission(actor, 'bu.manage', root.id) THEN
    RAISE EXCEPTION 'bu.manage is required at the root' USING ERRCODE = 'PF008';
  END IF;
  IF n IS NULL OR n < 1 OR n > 32 THEN
    RAISE EXCEPTION 'the maximum depth is 1 to 32' USING ERRCODE = 'PF004';
  END IF;
  IF n = was THEN
    RAISE EXCEPTION 'the maximum depth is % already', was USING ERRCODE = 'PF003';
  END IF;
  SELECT * INTO deep FROM iam.bu x WHERE x.archived_at IS NULL ORDER BY x.depth DESC, x.code LIMIT 1;
  IF deep.depth > n THEN
    RAISE EXCEPTION 'BU % is at depth %; move it up before lowering the maximum to %', deep.code, deep.depth, n USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.bu_config SET max_depth = n;
  PERFORM iam.bu_event('bu.max_depth_changed', actor, root, btrim(reason), jsonb_build_object('from', was, 'to', n));
END $$;

REVOKE ALL ON FUNCTION iam.bu_reachable(uuid, iam.bu), iam.bu_require_reason(text), iam.bu_target(uuid, uuid),
  iam.bu_create(uuid, text, text, boolean, text), iam.bu_rename(uuid, text, text), iam.bu_archive(uuid, text),
  iam.bu_move_preview(iam.bu, iam.bu), iam.bu_move_check(uuid, uuid, uuid), iam.bu_move_apply(uuid, jsonb, text, jsonb),
  iam.bu_move(uuid, uuid, text, text, boolean), iam.bu_depth_info(), iam.bu_set_max_depth(integer, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.bu_create(uuid, text, text, boolean, text), iam.bu_rename(uuid, text, text),
  iam.bu_archive(uuid, text), iam.bu_move(uuid, uuid, text, text, boolean), iam.bu_depth_info(),
  iam.bu_set_max_depth(integer, text) TO app_rw;

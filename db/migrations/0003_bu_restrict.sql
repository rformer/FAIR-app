-- F-001 T-05 (AC-59, AC-60): restrict / unrestrict a BU.
--
-- Any BU may be restricted (AC-59). Changing bu.restricted rebuilds
-- bu_closure.blocked for every path through the node, in the same
-- transaction, so ancestor assignments never inherit across a restricted
-- node (AC-60). The approval and audit rules for un-restricting (AC-63) are
-- enforced by the iam service (T-30); no application role can write iam.bu.

-- Same as 0002, minus the T-05 refusal, plus the tree lock for restriction
-- changes.
CREATE OR REPLACE FUNCTION iam.bu_before_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p iam.bu;
  max_depth smallint;
  height smallint;
BEGIN
  IF NEW.id <> OLD.id THEN
    RAISE EXCEPTION 'bu: id is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.parent_id IS NULL AND NEW.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'bu: the root cannot be archived' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.restricted <> OLD.restricted THEN
    PERFORM iam.bu_lock_tree();
  END IF;

  IF NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id THEN
    -- Depth is derived. Only the move cascade (a nested trigger) sets it.
    IF pg_trigger_depth() = 1 THEN
      NEW.depth := OLD.depth;
    END IF;
    RETURN NEW;
  END IF;

  -- Move.
  PERFORM iam.bu_lock_tree();
  IF OLD.parent_id IS NULL THEN
    RAISE EXCEPTION 'bu: the root cannot be moved' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.parent_id IS NULL THEN
    RAISE EXCEPTION 'bu: there is exactly one root' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO p FROM iam.bu WHERE id = NEW.parent_id;
  IF NOT FOUND THEN
    RETURN NEW;      -- the foreign key reports it
  END IF;
  IF EXISTS (SELECT 1 FROM iam.bu_closure WHERE ancestor_id = OLD.id AND descendant_id = NEW.parent_id) THEN
    RAISE EXCEPTION 'bu: moving % under % would create a cycle', OLD.id, NEW.parent_id USING ERRCODE = 'check_violation';
  END IF;
  IF p.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'bu: parent % is archived', p.id USING ERRCODE = 'check_violation';
  END IF;
  SELECT max(depth) INTO height FROM iam.bu_closure WHERE ancestor_id = OLD.id;
  SELECT c.max_depth INTO max_depth FROM iam.bu_config c;
  IF p.depth + 1 + height > max_depth THEN
    RAISE EXCEPTION 'bu: move would reach depth %, maximum is %', p.depth + 1 + height, max_depth USING ERRCODE = 'check_violation';
  END IF;
  NEW.depth := p.depth + 1;
  RETURN NEW;
END $$;

-- Recomputes `blocked` for every path (a, d] that passes through the node:
-- a is a strict ancestor of it and d is in its subtree. A path is blocked
-- iff some restricted node x lies on (a, d].
CREATE FUNCTION iam.bu_after_restrict() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE iam.bu_closure c
  SET blocked = EXISTS (
    SELECT 1
    FROM iam.bu_closure ax
    JOIN iam.bu_closure xd ON xd.ancestor_id = ax.descendant_id AND xd.descendant_id = c.descendant_id
    JOIN iam.bu x ON x.id = ax.descendant_id
    WHERE ax.ancestor_id = c.ancestor_id AND ax.depth > 0 AND x.restricted)
  FROM iam.bu_closure up, iam.bu_closure down
  WHERE up.descendant_id = NEW.id AND up.depth > 0 AND c.ancestor_id = up.ancestor_id
    AND down.ancestor_id = NEW.id AND c.descendant_id = down.descendant_id;
  RETURN NULL;
END $$;

-- Fires after bu_after_move (triggers run in name order), so a combined
-- move-and-restrict update sees the relinked closure.
CREATE TRIGGER bu_after_restrict AFTER UPDATE OF restricted ON iam.bu
  FOR EACH ROW WHEN (NEW.restricted IS DISTINCT FROM OLD.restricted) EXECUTE FUNCTION iam.bu_after_restrict();

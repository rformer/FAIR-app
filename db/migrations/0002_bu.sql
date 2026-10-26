-- F-001 T-04 (AC-15, AC-16): business-unit tree and closure table.
--
-- Invariants enforced here, in the database, whoever writes:
--   * exactly one root (the Enterprise node), which cannot be moved, archived
--     or deleted;
--   * no cycles;
--   * depth <= iam.bu_config.max_depth (AC-15, default 6; the root is depth 0);
--   * no hard delete (AC-16);
--   * iam.bu_closure always equals the transitive closure of bu.parent_id,
--     with `blocked` true when a restricted node lies on (ancestor, descendant].
--
-- Restrict/unrestrict and the asynchronous rebuild for large subtrees are
-- T-05; until then a change to bu.restricted is refused. No privileges are
-- granted to application roles: the iam service gets them with RLS in T-09.

CREATE TABLE iam.bu_config (
  singleton  boolean  PRIMARY KEY DEFAULT true CHECK (singleton),
  max_depth  smallint NOT NULL DEFAULT 6 CHECK (max_depth BETWEEN 1 AND 32)
);
INSERT INTO iam.bu_config DEFAULT VALUES;

CREATE TYPE iam.bu_rollup_mode AS ENUM ('excluded', 'aggregate', 'full');

CREATE TABLE iam.bu (
  id           uuid               PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id    uuid               REFERENCES iam.bu (id),
  name         text               NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  code         text               NOT NULL UNIQUE CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
  restricted   boolean            NOT NULL DEFAULT true,       -- secure default (AC-61)
  rollup_mode  iam.bu_rollup_mode NOT NULL DEFAULT 'excluded',
  depth        smallint           NOT NULL,                    -- maintained by trigger
  archived_at  timestamptz,
  created_at   timestamptz        NOT NULL DEFAULT now(),
  created_by   uuid,                                           -- NULL = system; FK once iam.app_user exists
  updated_at   timestamptz        NOT NULL DEFAULT now(),
  updated_by   uuid,
  CHECK ((parent_id IS NULL) = (depth = 0)),
  CHECK (parent_id <> id)
);
-- Single root (AC-15).
CREATE UNIQUE INDEX bu_single_root ON iam.bu ((true)) WHERE parent_id IS NULL;
CREATE INDEX bu_parent ON iam.bu (parent_id);

CREATE TABLE iam.bu_closure (
  ancestor_id    uuid     NOT NULL REFERENCES iam.bu (id),
  descendant_id  uuid     NOT NULL REFERENCES iam.bu (id),
  depth          smallint NOT NULL CHECK (depth >= 0),
  blocked        boolean  NOT NULL,
  PRIMARY KEY (ancestor_id, descendant_id),
  CHECK ((depth = 0) = (ancestor_id = descendant_id)),
  CHECK (depth > 0 OR NOT blocked)
);
CREATE INDEX bu_closure_descendant ON iam.bu_closure (descendant_id);

-- Serializes structural changes so concurrent moves cannot form a cycle.
-- EXCLUSIVE still admits plain readers.
CREATE FUNCTION iam.bu_lock_tree() RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  LOCK TABLE iam.bu_closure IN EXCLUSIVE MODE;
$$;

CREATE FUNCTION iam.bu_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p iam.bu;
  max_depth smallint;
BEGIN
  PERFORM iam.bu_lock_tree();
  IF NEW.parent_id IS NULL THEN
    NEW.depth := 0;  -- a second root fails on bu_single_root
    RETURN NEW;
  END IF;
  SELECT * INTO p FROM iam.bu WHERE id = NEW.parent_id;
  IF NOT FOUND THEN
    RETURN NEW;      -- the foreign key reports it
  END IF;
  IF p.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'bu: parent % is archived', p.id USING ERRCODE = 'check_violation';
  END IF;
  SELECT c.max_depth INTO max_depth FROM iam.bu_config c;
  NEW.depth := p.depth + 1;
  IF NEW.depth > max_depth THEN
    RAISE EXCEPTION 'bu: depth % exceeds maximum %', NEW.depth, max_depth USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.bu_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO iam.bu_closure (ancestor_id, descendant_id, depth, blocked)
  VALUES (NEW.id, NEW.id, 0, false);
  INSERT INTO iam.bu_closure (ancestor_id, descendant_id, depth, blocked)
  SELECT c.ancestor_id, NEW.id, c.depth + 1, c.blocked OR NEW.restricted
  FROM iam.bu_closure c
  WHERE c.descendant_id = NEW.parent_id;
  RETURN NULL;
END $$;

CREATE FUNCTION iam.bu_before_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p iam.bu;
  max_depth smallint;
  height smallint;
BEGIN
  IF NEW.id <> OLD.id THEN
    RAISE EXCEPTION 'bu: id is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.restricted <> OLD.restricted THEN
    RAISE EXCEPTION 'bu: restrict/unrestrict is not available yet (F-001 T-05)' USING ERRCODE = 'feature_not_supported';
  END IF;
  IF OLD.parent_id IS NULL AND NEW.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'bu: the root cannot be archived' USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id THEN
    -- Depth is derived. Only the move cascade below (a nested trigger) sets it.
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

-- Relinks the moved subtree under its new parent. Runs synchronously; T-05
-- adds the asynchronous path for large subtrees (design §12 R1).
CREATE FUNCTION iam.bu_after_move() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  DELETE FROM iam.bu_closure c
  USING iam.bu_closure s
  WHERE s.ancestor_id = NEW.id
    AND c.descendant_id = s.descendant_id
    AND NOT EXISTS (SELECT 1 FROM iam.bu_closure i WHERE i.ancestor_id = NEW.id AND i.descendant_id = c.ancestor_id);

  -- blocked over (a, d] = (a, parent] + {moved node} + (moved node, d]
  INSERT INTO iam.bu_closure (ancestor_id, descendant_id, depth, blocked)
  SELECT a.ancestor_id, s.descendant_id, a.depth + 1 + s.depth, a.blocked OR NEW.restricted OR s.blocked
  FROM iam.bu_closure a
  JOIN iam.bu_closure s ON s.ancestor_id = NEW.id
  WHERE a.descendant_id = NEW.parent_id;

  UPDATE iam.bu b
  SET depth = NEW.depth + s.depth
  FROM iam.bu_closure s
  WHERE s.ancestor_id = NEW.id AND s.depth > 0 AND b.id = s.descendant_id;
  RETURN NULL;
END $$;

-- AC-16: no hard delete.
CREATE FUNCTION iam.bu_no_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'bu: business units are archived, never deleted' USING ERRCODE = 'restrict_violation';
END $$;

CREATE FUNCTION iam.bu_config_before_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  deepest smallint;
BEGIN
  PERFORM iam.bu_lock_tree();
  SELECT coalesce(max(depth), 0) INTO deepest FROM iam.bu;
  IF NEW.max_depth < deepest THEN
    RAISE EXCEPTION 'bu: max_depth % is below the current tree depth %', NEW.max_depth, deepest USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER bu_before_insert BEFORE INSERT ON iam.bu
  FOR EACH ROW EXECUTE FUNCTION iam.bu_before_insert();
CREATE TRIGGER bu_after_insert AFTER INSERT ON iam.bu
  FOR EACH ROW EXECUTE FUNCTION iam.bu_after_insert();
CREATE TRIGGER bu_before_update BEFORE UPDATE ON iam.bu
  FOR EACH ROW EXECUTE FUNCTION iam.bu_before_update();
CREATE TRIGGER bu_after_move AFTER UPDATE OF parent_id ON iam.bu
  FOR EACH ROW WHEN (NEW.parent_id IS DISTINCT FROM OLD.parent_id) EXECUTE FUNCTION iam.bu_after_move();
CREATE TRIGGER bu_no_delete BEFORE DELETE ON iam.bu
  FOR EACH ROW EXECUTE FUNCTION iam.bu_no_delete();
CREATE TRIGGER bu_no_truncate BEFORE TRUNCATE ON iam.bu
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bu_no_delete();
CREATE TRIGGER bu_closure_no_truncate BEFORE TRUNCATE ON iam.bu_closure
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bu_no_delete();
CREATE TRIGGER bu_config_before_update BEFORE UPDATE ON iam.bu_config
  FOR EACH ROW EXECUTE FUNCTION iam.bu_config_before_update();
CREATE TRIGGER bu_config_no_delete BEFORE DELETE ON iam.bu_config
  FOR EACH ROW EXECUTE FUNCTION iam.bu_no_delete();

-- The Enterprise root (AC-15).
INSERT INTO iam.bu (name, code, restricted) VALUES ('Enterprise', 'ENTERPRISE', false);

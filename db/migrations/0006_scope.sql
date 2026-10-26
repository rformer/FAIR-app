-- F-001 T-08 (AC-17, AC-21, AC-60; design §3 "Materialized scope", §5.4):
-- access-change outbox, materialized user scope, and drift reconciliation.
--
-- * Every access-relevant change writes an iam.outbox row in its own
--   transaction (triggers), so no change can commit without one. A BU move's
--   row carries the old and new parent and the actor (AC-17 audit).
-- * authz.drain_outbox() turns outbox rows into the affected users, recomputes
--   their scope, and queues iam.scope.changed and audit events in
--   iam.event_outbox for the worker to deliver (at least once).
-- * authz.reconcile_scopes() recomputes every user and repairs and reports
--   drift (nightly job).
-- Both run under one advisory lock, so recomputes never interleave.
-- Application roles may call the worker functions; they cannot touch the
-- tables. Scope is always recomputed from the source tables, so calling the
-- functions cannot widen anyone's access.

CREATE TABLE iam.outbox (
  id          bigserial   PRIMARY KEY,
  kind        text        NOT NULL CHECK (kind IN ('principal', 'role', 'bu', 'user')),
  ref         jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.event_outbox (
  id            bigserial   PRIMARY KEY,
  topic         text        NOT NULL,          -- NATS subject, or 'audit' for the audit emitter
  payload       jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  published_at  timestamptz
);
CREATE INDEX event_outbox_pending ON iam.event_outbox (id) WHERE published_at IS NULL;

CREATE SEQUENCE authz.scope_version_seq;

CREATE TABLE authz.user_scope (
  user_id               uuid        PRIMARY KEY REFERENCES iam.app_user (id),
  scope_version         bigint      NOT NULL,
  read_bus              jsonb       NOT NULL,  -- resource_type -> [bu ids]
  write_bus             jsonb       NOT NULL,
  rollup_aggregate_bus  jsonb       NOT NULL,  -- roll-up functions only, never row queries
  computed_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE authz.worker_state (
  singleton            boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  expiry_checked_until timestamptz NOT NULL DEFAULT now()
);
INSERT INTO authz.worker_state DEFAULT VALUES;

-- Outbox triggers ---------------------------------------------------------

CREATE FUNCTION iam.outbox_assignment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO iam.outbox (kind, ref)
  VALUES ('principal', jsonb_build_object('kind', NEW.principal_kind, 'id', NEW.principal_id));
  RETURN NULL;
END $$;

CREATE FUNCTION iam.outbox_grp_member() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO iam.outbox (kind, ref)
  VALUES ('user', jsonb_build_object('id', CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END));
  IF TG_OP = 'UPDATE' AND OLD.user_id <> NEW.user_id THEN
    INSERT INTO iam.outbox (kind, ref) VALUES ('user', jsonb_build_object('id', OLD.user_id));
  END IF;
  RETURN NULL;
END $$;

CREATE FUNCTION iam.outbox_app_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO iam.outbox (kind, ref) VALUES ('user', jsonb_build_object('id', NEW.id));
  RETURN NULL;
END $$;

CREATE FUNCTION iam.outbox_role() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO iam.outbox (kind, ref)
  -- role_version rows name the role in role_id, role rows in id.
  VALUES ('role', jsonb_build_object('id', to_jsonb(NEW)->>(CASE WHEN TG_TABLE_NAME = 'role_version' THEN 'role_id' ELSE 'id' END)));
  RETURN NULL;
END $$;

-- BU changes. A move also records old/new parent and actor for the AC-17 audit.
CREATE FUNCTION iam.outbox_bu() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  ref jsonb := jsonb_build_object('id', NEW.id);
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.parent_id IS DISTINCT FROM OLD.parent_id THEN
    ref := ref || jsonb_build_object('moved', true, 'old_parent', OLD.parent_id, 'new_parent', NEW.parent_id, 'actor', NEW.updated_by);
  END IF;
  INSERT INTO iam.outbox (kind, ref) VALUES ('bu', ref);
  RETURN NULL;
END $$;

CREATE TRIGGER assignment_outbox AFTER INSERT OR UPDATE OF revoked_at ON iam.assignment
  FOR EACH ROW EXECUTE FUNCTION iam.outbox_assignment();
CREATE TRIGGER grp_member_outbox AFTER INSERT OR UPDATE OR DELETE ON iam.grp_member
  FOR EACH ROW EXECUTE FUNCTION iam.outbox_grp_member();
CREATE TRIGGER app_user_outbox AFTER UPDATE OF status ON iam.app_user
  FOR EACH ROW WHEN (NEW.status IS DISTINCT FROM OLD.status) EXECUTE FUNCTION iam.outbox_app_user();
CREATE TRIGGER role_version_outbox AFTER INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.outbox_role();
CREATE TRIGGER role_outbox AFTER UPDATE OF status ON iam.role
  FOR EACH ROW WHEN (NEW.status IS DISTINCT FROM OLD.status) EXECUTE FUNCTION iam.outbox_role();
CREATE TRIGGER bu_outbox_insert AFTER INSERT ON iam.bu
  FOR EACH ROW EXECUTE FUNCTION iam.outbox_bu();
CREATE TRIGGER bu_outbox_update AFTER UPDATE OF parent_id, restricted, rollup_mode, archived_at ON iam.bu
  FOR EACH ROW WHEN (NEW.parent_id IS DISTINCT FROM OLD.parent_id OR NEW.restricted <> OLD.restricted
                     OR NEW.rollup_mode <> OLD.rollup_mode OR NEW.archived_at IS DISTINCT FROM OLD.archived_at)
  EXECUTE FUNCTION iam.outbox_bu();

-- Scope computation ---------------------------------------------------------

-- Scope for each user in `users`, from the §3 effective-access rule:
--   read_bus:  read permissions on unblocked paths, plus blocked paths whose
--              restricted nodes are all roll-up mode 'full';
--   write_bus: write permissions on unblocked paths only;
--   rollup_aggregate_bus: read permissions on blocked paths whose restricted
--              nodes are all 'aggregate' or 'full' (and not already in read).
-- Inactive users and users without grants get empty maps.
CREATE FUNCTION authz.compute_scopes(users uuid[])
RETURNS TABLE (user_id uuid, read_bus jsonb, write_bus jsonb, rollup_aggregate_bus jsonb)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (
    SELECT DISTINCT x AS user_id FROM unnest(users) x
  ), held AS (
    -- Direct and group assignments as two indexed lookups; a single join on
    -- "user OR one of the user's groups" cannot use the principal index.
    SELECT u.user_id, a.role_id, a.bu_id
    FROM u JOIN iam.assignment a ON a.principal_kind = 'user' AND a.principal_id = u.user_id
    WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
    UNION ALL
    SELECT u.user_id, a.role_id, a.bu_id
    FROM u
    JOIN iam.grp_member m ON m.user_id = u.user_id
    JOIN iam.assignment a ON a.principal_kind = 'group' AND a.principal_id = m.grp_id
    WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
  ), grants AS (
    SELECT DISTINCT a.user_id, a.bu_id, p.resource_type, p.action
    FROM held a
    JOIN iam.app_user au ON au.id = a.user_id AND au.status = 'active'
    JOIN iam.role r ON r.id = a.role_id AND r.status = 'active'
    JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
    JOIN iam.permission p ON p.key = ANY (v.permissions) AND p.action IN ('read', 'write')
  ), reach AS MATERIALIZED (  -- materialized so vis is computed once per row
    SELECT g.user_id, g.resource_type, g.action, c.descendant_id AS bu,
      -- The restricted nodes on (a, d] are d's restricted ancestors deeper
      -- than a: at most max_depth rows via the descendant index.
      CASE WHEN NOT c.blocked THEN 'open' ELSE (
        SELECT CASE WHEN bool_and(x.rollup_mode = 'full') THEN 'full'
                    WHEN bool_and(x.rollup_mode IN ('full', 'aggregate')) THEN 'aggregate'
                    ELSE 'excluded' END
        FROM iam.bu_closure xd
        JOIN iam.bu x ON x.id = xd.ancestor_id
        WHERE xd.descendant_id = c.descendant_id AND x.restricted AND x.depth > ab.depth) END AS vis
    FROM grants g
    JOIN iam.bu_closure c ON c.ancestor_id = g.bu_id
    JOIN iam.bu ab ON ab.id = g.bu_id
  ), cls AS (
    SELECT DISTINCT user_id, resource_type, bu,
      CASE WHEN action = 'read' AND vis IN ('open', 'full') THEN 'read'
           WHEN action = 'write' AND vis = 'open' THEN 'write'
           WHEN action = 'read' AND vis = 'aggregate' THEN 'aggregate' END AS bucket
    FROM reach
  ), keep AS (
    SELECT * FROM cls c
    WHERE bucket IS NOT NULL
      AND NOT (bucket = 'aggregate' AND EXISTS (
        SELECT 1 FROM cls r WHERE r.user_id = c.user_id AND r.resource_type = c.resource_type AND r.bu = c.bu AND r.bucket = 'read'))
  ), per_type AS (
    SELECT user_id, bucket, resource_type, jsonb_agg(bu ORDER BY bu) AS bus
    FROM keep GROUP BY user_id, bucket, resource_type
  ), per_user AS (  -- one pass over per_type; per-user subqueries would be quadratic
    SELECT user_id,
      jsonb_object_agg(resource_type, bus) FILTER (WHERE bucket = 'read') AS r,
      jsonb_object_agg(resource_type, bus) FILTER (WHERE bucket = 'write') AS w,
      jsonb_object_agg(resource_type, bus) FILTER (WHERE bucket = 'aggregate') AS a
    FROM per_type GROUP BY user_id
  )
  SELECT u.user_id, coalesce(p.r, '{}'), coalesce(p.w, '{}'), coalesce(p.a, '{}')
  FROM u LEFT JOIN per_user p ON p.user_id = u.user_id;
$$;

-- Recomputes users' scope. A row whose content changed gets a new
-- scope_version and queues iam.scope.changed. Inactive users lose their row
-- (design §5.3). Returns the users whose scope changed.
CREATE FUNCTION authz.refresh_scopes(users uuid[])
RETURNS TABLE (user_id uuid, scope_version bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  RETURN QUERY
  WITH computed AS (
    SELECT c.*, au.status = 'active' AS active
    FROM authz.compute_scopes(users) c
    JOIN iam.app_user au ON au.id = c.user_id
  ), removed AS (
    DELETE FROM authz.user_scope s
    USING computed c
    WHERE s.user_id = c.user_id AND NOT c.active
    RETURNING s.user_id, -1::bigint AS scope_version
  ), changed AS (
    INSERT INTO authz.user_scope AS s (user_id, scope_version, read_bus, write_bus, rollup_aggregate_bus)
    SELECT c.user_id, nextval('authz.scope_version_seq'), c.read_bus, c.write_bus, c.rollup_aggregate_bus
    FROM computed c
    WHERE c.active
      -- No row means no access; do not create one just to store an empty scope.
      AND (EXISTS (SELECT 1 FROM authz.user_scope o WHERE o.user_id = c.user_id)
           OR c.read_bus <> '{}' OR c.write_bus <> '{}' OR c.rollup_aggregate_bus <> '{}')
      AND NOT EXISTS (
      SELECT 1 FROM authz.user_scope o
      WHERE o.user_id = c.user_id AND o.read_bus = c.read_bus AND o.write_bus = c.write_bus
        AND o.rollup_aggregate_bus = c.rollup_aggregate_bus)
    ON CONFLICT ON CONSTRAINT user_scope_pkey DO UPDATE
      SET scope_version = EXCLUDED.scope_version, read_bus = EXCLUDED.read_bus, write_bus = EXCLUDED.write_bus,
          rollup_aggregate_bus = EXCLUDED.rollup_aggregate_bus, computed_at = now()
    RETURNING s.user_id, s.scope_version
  ), events AS (
    INSERT INTO iam.event_outbox (topic, payload)
    SELECT 'iam.scope.changed', jsonb_build_object('user_id', x.user_id, 'scope_version', x.scope_version, 'revoked', x.scope_version < 0)
    FROM (SELECT * FROM removed UNION ALL SELECT * FROM changed) x
  )
  SELECT * FROM removed UNION ALL SELECT * FROM changed;
END $$;

-- Users affected by one outbox row (design §5.4: bounded to the subtree for
-- BU changes: the users with live assignments at the BU or its ancestors,
-- including the ancestors it was moved away from).
CREATE FUNCTION authz.outbox_users(kind text, ref jsonb) RETURNS SETOF uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH holders AS (  -- users holding a live assignment matching the filter
    SELECT a.principal_kind, a.principal_id, a.role_id, a.bu_id
    FROM iam.assignment a WHERE a.revoked_at IS NULL
  )
  SELECT (ref->>'id')::uuid WHERE kind = 'user'
  UNION
  SELECT u FROM iam.principal_users((ref->>'kind')::iam.principal_kind, (ref->>'id')::uuid) u WHERE kind = 'principal'
  UNION
  SELECT u FROM holders h, iam.principal_users(h.principal_kind, h.principal_id) u
  WHERE kind = 'role' AND h.role_id = (ref->>'id')::uuid
  UNION
  SELECT u FROM holders h, iam.principal_users(h.principal_kind, h.principal_id) u
  WHERE kind = 'bu' AND h.bu_id IN (
    SELECT c.ancestor_id FROM iam.bu_closure c
    WHERE c.descendant_id IN ((ref->>'id')::uuid, (ref->>'old_parent')::uuid));
$$;

-- Worker entry point. Drains up to max_rows outbox rows (also queueing
-- refreshes for assignments that expired since the last call), recomputes
-- the affected users and queues events. Returns how many rows it drained and
-- users it changed; drained = 0 and changed = 0 means idle. Returns -1 rows
-- if another drain or reconcile holds the lock.
CREATE FUNCTION authz.drain_outbox(max_rows integer DEFAULT 1000, OUT drained integer, OUT changed integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  checked_until timestamptz := now();
  r iam.outbox;
  affected uuid[] := '{}';
BEGIN
  drained := 0;
  changed := 0;
  IF NOT pg_try_advisory_xact_lock(hashtext('authz.scope')) THEN
    drained := -1;
    RETURN;
  END IF;

  -- Expiry has no write to trigger on; T-32 revokes, this keeps scope right meanwhile.
  INSERT INTO iam.outbox (kind, ref)
  SELECT 'principal', jsonb_build_object('kind', a.principal_kind, 'id', a.principal_id)
  FROM iam.assignment a, authz.worker_state w
  WHERE a.revoked_at IS NULL AND a.expires_at > w.expiry_checked_until AND a.expires_at <= checked_until;
  UPDATE authz.worker_state SET expiry_checked_until = checked_until;

  FOR r IN DELETE FROM iam.outbox WHERE id IN (SELECT o.id FROM iam.outbox o ORDER BY o.id LIMIT max_rows) RETURNING * LOOP
    drained := drained + 1;
    affected := affected || ARRAY(SELECT authz.outbox_users(r.kind, r.ref));
    IF r.kind = 'bu' AND (r.ref->>'moved')::boolean THEN
      INSERT INTO iam.event_outbox (topic, payload)
      VALUES ('audit', jsonb_build_object(
        'type', 'bu.moved', 'severity', 'info', 'actor', coalesce(r.ref->>'actor', 'system'),
        'attributes', jsonb_build_object('bu_id', r.ref->>'id', 'old_parent', r.ref->>'old_parent',
                                         'new_parent', r.ref->>'new_parent', 'at', r.created_at)));
    END IF;
  END LOOP;
  IF drained > 0 THEN
    SELECT count(*) INTO changed FROM authz.refresh_scopes(affected);
  END IF;
END $$;

-- Nightly reconciliation: recompute everyone, repair drift, and queue a
-- high-severity audit event per drifted user. Returns the drifted users.
CREATE FUNCTION authz.reconcile_scopes() RETURNS SETOF uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  everyone uuid[];
  drifted uuid[];
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('authz.scope'));
  SELECT array_agg(id) INTO everyone
  FROM (SELECT id FROM iam.app_user UNION SELECT s.user_id FROM authz.user_scope s) x;
  SELECT array_agg(r.user_id) INTO drifted FROM authz.refresh_scopes(coalesce(everyone, '{}')) r;
  INSERT INTO iam.event_outbox (topic, payload)
  SELECT 'audit', jsonb_build_object('type', 'authz.scope.drift', 'severity', 'high', 'actor', 'system:scope-worker',
                                     'attributes', jsonb_build_object('user_id', d))
  FROM unnest(drifted) d;
  RETURN QUERY SELECT unnest(drifted);
END $$;

-- Event delivery for the worker: fetch pending events, then mark the ones
-- delivered. At-least-once: an event is re-sent if marking fails.
CREATE FUNCTION authz.pending_events(max_rows integer DEFAULT 500)
RETURNS TABLE (id bigint, topic text, payload jsonb, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.id, e.topic, e.payload, e.created_at FROM iam.event_outbox e WHERE e.published_at IS NULL ORDER BY e.id LIMIT max_rows;
$$;

CREATE FUNCTION authz.mark_events_published(ids bigint[]) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (
    UPDATE iam.event_outbox SET published_at = now() WHERE id = ANY (ids) AND published_at IS NULL RETURNING 1
  ) SELECT count(*)::integer FROM u;
$$;

GRANT EXECUTE ON FUNCTION authz.drain_outbox(integer), authz.reconcile_scopes(),
  authz.pending_events(integer), authz.mark_events_published(bigint[]) TO app_rw;

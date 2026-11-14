-- F-007 T-02 (F-007-AC-07, AC-11; F-007 design §5.2, §10): F-005
-- aggregates for the risk register.
--
-- * analysis.aggregate.purpose: 'analysis' (an analyst's aggregate, the
--   default and the only one app_rw can make), 'exposure' (a multi-scenario
--   risk's exposure) or 'rollup' (a business unit roll-up node). The
--   register's functions make the other two (F-007 T-05, T-07). Like every
--   input, it never changes (aggregate_before_update compares every column).
-- * A member is a run's control set, as before, or an aggregate
--   (member_aggregate_id): register roll-ups nest (F-007 design §3.4). An
--   aggregate member must be succeeded, of the aggregate's iterations, in
--   its business unit's subtree, and visible to the caller with every one of
--   its own members; it cannot form a cycle, since only succeeded
--   aggregates are members and an aggregate's members are fixed when it is
--   queued.
-- * analysis.members_visible follows aggregate members to every leaf: a
--   nested aggregate is visible only to a reader who sees every run under
--   it and every aggregate on the way (F-005-AC-19).
-- * The worker's reads (0105) give an aggregate member's id, results digest
--   and name, and its series from analysis.aggregate.ale.

ALTER TABLE analysis.aggregate ADD COLUMN purpose text NOT NULL DEFAULT 'analysis'
  CHECK (purpose IN ('analysis', 'exposure', 'rollup'));
CREATE INDEX aggregate_purpose ON analysis.aggregate (purpose, seq);

ALTER TABLE analysis.aggregate_member ALTER COLUMN run_id DROP NOT NULL;
ALTER TABLE analysis.aggregate_member ALTER COLUMN control_set DROP NOT NULL;
ALTER TABLE analysis.aggregate_member ADD COLUMN member_aggregate_id uuid REFERENCES analysis.aggregate (id);
ALTER TABLE analysis.aggregate_member ADD CONSTRAINT member_kind CHECK (
  (run_id IS NOT NULL AND control_set IS NOT NULL AND member_aggregate_id IS NULL) OR
  (run_id IS NULL AND control_set IS NULL AND member_aggregate_id IS NOT NULL));
ALTER TABLE analysis.aggregate_member ADD CONSTRAINT member_aggregate_once UNIQUE (aggregate_id, member_aggregate_id);
CREATE INDEX aggregate_member_aggregate ON analysis.aggregate_member (member_aggregate_id);
GRANT INSERT (member_aggregate_id) ON analysis.aggregate_member TO app_rw;

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

-- Every run under the aggregate, and every aggregate on the way to them,
-- visible to the caller (ADR-007 amendment 4; F-007 design §5.2).
CREATE OR REPLACE FUNCTION analysis.members_visible(aggregate uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH RECURSIVE tree(id) AS (
    SELECT members_visible.aggregate
    UNION
    SELECT m.member_aggregate_id FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id WHERE m.member_aggregate_id IS NOT NULL
  )
  SELECT NOT EXISTS (SELECT 1 FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id JOIN analysis.run r ON r.id = m.run_id
                     WHERE NOT r.bu_id = ANY (authz.visible_bus('analysis', 'read')))
     AND NOT EXISTS (SELECT 1 FROM analysis.aggregate_member m JOIN tree t ON m.aggregate_id = t.id
                     JOIN analysis.aggregate a ON a.id = m.member_aggregate_id
                     WHERE NOT a.bu_id = ANY (authz.visible_bus('analysis', 'read')));
$$;

-- A member: a succeeded run's control set, or a succeeded aggregate, the
-- caller can see (under RLS), in the aggregate's subtree, of the
-- aggregate's iterations; added in the aggregate's creating transaction.
CREATE OR REPLACE FUNCTION analysis.member_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record; r record;
BEGIN
  SELECT x.bu_id, x.state, x.requested_at, x.iterations INTO a FROM analysis.aggregate x WHERE x.id = NEW.aggregate_id;
  IF NOT FOUND OR a.state <> 'queued' OR a.requested_at <> now() THEN
    RAISE EXCEPTION 'analysis.aggregate_member: added only with its aggregate' USING ERRCODE = 'PF024';
  END IF;
  IF NEW.member_aggregate_id IS NOT NULL THEN
    -- Under the caller's read scope, with every member of its own.
    SELECT x.bu_id, x.state, x.iterations, x.engine_version INTO r FROM analysis.aggregate x
    WHERE x.id = NEW.member_aggregate_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'))
      AND analysis.members_visible(x.id);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'analysis.aggregate_member: no such aggregate %', NEW.member_aggregate_id USING ERRCODE = 'P0002';
    END IF;
    IF r.state <> 'succeeded' THEN
      RAISE EXCEPTION 'analysis.aggregate_member: members are succeeded runs and aggregates' USING ERRCODE = 'PF024';
    END IF;
  ELSE
    -- Under the caller's read scope: the definer's own policy would see
    -- every run, so visibility is checked against the caller's scope.
    SELECT x.bu_id, x.state, x.iterations, x.control_sets, x.engine_version INTO r FROM analysis.run x
    WHERE x.id = NEW.run_id AND x.bu_id = ANY (authz.visible_bus('analysis', 'read'));
    IF NOT FOUND THEN
      RAISE EXCEPTION 'analysis.aggregate_member: no such run %', NEW.run_id USING ERRCODE = 'P0002';
    END IF;
    IF r.state <> 'succeeded' OR NOT NEW.control_set = ANY (r.control_sets) THEN
      RAISE EXCEPTION 'analysis.aggregate_member: members are control sets of succeeded runs' USING ERRCODE = 'PF024';
    END IF;
  END IF;
  IF r.iterations <> a.iterations THEN
    RAISE EXCEPTION 'analysis.aggregate_member: members have the aggregate''s iterations (%)', a.iterations USING ERRCODE = 'PF024';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = a.bu_id AND c.descendant_id = r.bu_id) THEN
    RAISE EXCEPTION 'analysis.aggregate_member: % is outside the aggregate''s business unit', coalesce(NEW.run_id, NEW.member_aggregate_id)
      USING ERRCODE = 'PF024';
  END IF;
  NEW.bu_id := a.bu_id;
  NEW.engine_version := r.engine_version;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION analysis.aggregate_spec(id uuid, token text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = aggregate_spec.id;
  IF NOT FOUND OR a.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: aggregate % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate');
  RETURN jsonb_build_object('id', a.id, 'bu_id', a.bu_id, 'seed', a.seed::text, 'iterations', a.iterations,
    'members', (SELECT jsonb_agg(CASE WHEN m.member_aggregate_id IS NULL
                  THEN jsonb_build_object('position', m.position, 'run_id', m.run_id, 'control_set', m.control_set,
                    'engine_version', m.engine_version, 'result_digest', r.result_digest)
                  ELSE jsonb_build_object('position', m.position, 'aggregate_id', m.member_aggregate_id, 'name', g.name,
                    'engine_version', m.engine_version, 'result_digest', g.result_digest) END ORDER BY m.position)
                FROM analysis.aggregate_member m LEFT JOIN analysis.run r ON r.id = m.run_id
                LEFT JOIN analysis.aggregate g ON g.id = m.member_aggregate_id WHERE m.aggregate_id = a.id));
END $$;

CREATE OR REPLACE FUNCTION analysis.member_series(id uuid, token text, member integer) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a analysis.aggregate; b bytea;
BEGIN
  SELECT * INTO a FROM analysis.aggregate x WHERE x.id = member_series.id;
  IF NOT FOUND OR a.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: aggregate % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(a.attempt, token, 'the aggregate');
  SELECT coalesce(s.ale, g.ale) INTO b FROM analysis.aggregate_member m
  LEFT JOIN analysis.series s ON s.run_id = m.run_id AND s.control_set = m.control_set
  LEFT JOIN analysis.aggregate g ON g.id = m.member_aggregate_id
  WHERE m.aggregate_id = a.id AND m.position = member;
  IF b IS NULL THEN
    RAISE EXCEPTION 'analysis: aggregate % has no member %', id, member USING ERRCODE = 'P0002';
  END IF;
  RETURN b;
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

-- An analyst's aggregate (purpose 'analysis'): members are runs' control
-- sets ({run_id, control_set}) or aggregates ({aggregate_id}).
CREATE OR REPLACE FUNCTION analysis.request_aggregate(bu uuid, name text, seed numeric, members jsonb) RETURNS uuid
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE id uuid := gen_random_uuid(); m record; n integer; iters integer; first jsonb;
BEGIN
  IF jsonb_typeof(members) <> 'array' OR jsonb_array_length(members) NOT BETWEEN 2 AND 200 THEN
    RAISE EXCEPTION 'analysis: an aggregate has 2 to 200 members' USING ERRCODE = 'PF024';
  END IF;
  first := members -> 0;
  IF first ? 'aggregate_id' THEN
    SELECT g.iterations INTO iters FROM analysis.aggregate g WHERE g.id = (first ->> 'aggregate_id')::uuid;
  ELSE
    SELECT r.iterations INTO iters FROM analysis.run r WHERE r.id = (first ->> 'run_id')::uuid;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'analysis: no such member %', coalesce(first ->> 'run_id', first ->> 'aggregate_id') USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations) VALUES (id, bu, name, seed, iters);
  n := 0;
  FOR m IN SELECT x ->> 'run_id' AS run_id, x ->> 'control_set' AS control_set, x ->> 'aggregate_id' AS aggregate_id FROM jsonb_array_elements(members) x LOOP
    INSERT INTO analysis.aggregate_member (aggregate_id, bu_id, position, run_id, control_set, member_aggregate_id)
    VALUES (id, bu, n, m.run_id::uuid, m.control_set, m.aggregate_id::uuid);
    n := n + 1;
  END LOOP;
  PERFORM analysis.emit_created(id);
  RETURN id;
END $$;

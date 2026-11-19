-- F-013 T-08 (F-013-AC-12 to AC-15, AC-20; design §3.5, §3.7): coverage.
--
--   * framework.coverage(version, baseline, bu, as_of): for each
--     requirement of the version (or of the baseline's selection; withdrawn
--     ones left out), the controls of bu's subtree the caller may read that
--     map to it (direct) and those that map to a requirement a crosswalk
--     relates to it (derived, §3.3), with a state:
--       in_place      a full mapping, and every fully mapped control in place
--       not_in_place  a full mapping to a control not in place (or unknown)
--       partial       only partial or supports mappings, or derived ones
--       not_covered   nothing
--     and counts by state; never a score (AC-13). Invoker: the projection
--     and the control versions are read under the caller's RLS (AC-14).
--   * Restricted units below bu: those the caller's roll-up mode makes
--     aggregate-only count by state through framework.coverage_aggregate,
--     owned by rollup_definer (totals only, never a control); excluded ones
--     are counted as left out (F-001-AC-26).
--   * as_of (AC-20): each control's version current then (its versions are
--     kept), its archive state then, the crosswalks active then; the
--     framework version must have been imported by then. Without as_of,
--     now.
--   * framework.coverage_rows(version, baseline, at, bus) is the shared
--     computation (invoker, so rollup_definer's call reads under its own
--     policy); framework.coverage_requirements and derived_at are the
--     definer-side reference reads.

-- coverage_rows (invoker, SQL: checked at creation) names risk.control_version;
-- its owner needs the schema, not the table (callers read under their RLS).
GRANT USAGE ON SCHEMA risk TO framework_definer;
GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

-- The requirements coverage lists (reference data; readers only).
CREATE FUNCTION framework.coverage_requirements(version uuid, baseline uuid, at timestamptz)
RETURNS TABLE (id uuid, identifier text, label text, title text, parent text, ord integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v framework.version; b framework.baseline;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO v FROM framework.version x WHERE x.id = coverage_requirements.version;
  IF v.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such version %', version USING ERRCODE = 'P0002';
  END IF;
  IF at IS NOT NULL AND v.imported_at > at THEN
    RAISE EXCEPTION 'framework: % % was imported after that date', v.family, v.label USING ERRCODE = 'PF033', HINT = 'not_active_then';
  END IF;
  IF baseline IS NOT NULL THEN
    SELECT * INTO b FROM framework.baseline x WHERE x.id = coverage_requirements.baseline AND x.version_id = v.id;
    IF b.id IS NULL THEN
      RAISE EXCEPTION 'framework: no such baseline % of this version', baseline USING ERRCODE = 'P0002';
    END IF;
  END IF;
  RETURN QUERY SELECT r.id, r.identifier, r.label, r.title, r.parent, r.ord FROM framework.requirement r
    WHERE r.version_id = v.id AND NOT r.withdrawn AND (b.id IS NULL OR r.identifier = ANY (b.selected));
END $$;

-- What coverage names: the version and the baseline.
CREATE FUNCTION framework.coverage_head(version uuid, baseline uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object(
    'version', (SELECT jsonb_build_object('id', v.id, 'family', v.family, 'family_title', f.title, 'label', v.label, 'title', v.title, 'state', v.state)
                FROM framework.version v JOIN framework.family f ON f.key = v.family WHERE v.id = coverage_head.version),
    'baseline', (SELECT jsonb_build_object('id', b.id, 'key', b.key, 'title', b.title, 'state', b.state) FROM framework.baseline b WHERE b.id = coverage_head.baseline));
$$;

-- framework.derived as of a time, with what the caller shows of each
-- relationship.
CREATE FUNCTION framework.derived_at(version uuid, at timestamptz)
RETURNS TABLE (requirement_id uuid, via_requirement_id uuid, via text, crosswalk_id uuid, crosswalk text, relationship text, reach text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH x AS (
    SELECT c.* FROM framework.crosswalk c
    WHERE coalesce(at, now()) >= c.imported_at AND (c.retired_at IS NULL OR c.retired_at > coalesce(at, now()))
      AND derived_at.version IN (c.source_version, c.target_version)),
  rel AS (
    SELECT r.target_id AS req, r.source_id AS via, x.id AS xid, x.title AS xtitle, r.relationship AS rel
    FROM framework.relationship r JOIN x ON x.id = r.crosswalk_id AND x.target_version = derived_at.version
    UNION ALL
    SELECT r.source_id, r.target_id, x.id, x.title,
      CASE r.relationship WHEN 'subset_of' THEN 'superset_of' WHEN 'superset_of' THEN 'subset_of' ELSE r.relationship END
    FROM framework.relationship r JOIN x ON x.id = r.crosswalk_id AND x.source_version = derived_at.version)
  SELECT rel.req, rel.via, v.family || ' ' || v.label || ' ' || q.identifier, rel.xid, rel.xtitle, rel.rel,
    CASE WHEN rel.rel IN ('equal', 'superset_of') THEN 'equivalent' ELSE 'partial' END
  FROM rel JOIN framework.requirement q ON q.id = rel.via JOIN framework.version v ON v.id = q.version_id;
$$;

-- The shared computation, under the caller's row-level security: one row
-- per requirement, with its state and its direct and derived controls in
-- the given business units.
CREATE FUNCTION framework.coverage_rows(version uuid, baseline uuid, at timestamptz, bus uuid[])
RETURNS TABLE (requirement_id uuid, identifier text, label text, title text, parent text, ord integer, state text, direct jsonb, derived jsonb)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH reqs AS (SELECT * FROM framework.coverage_requirements(version, baseline, at)),
  cv AS (
    SELECT v.control_id, max(v.version) AS version FROM risk.control_version v
    WHERE v.bu_id = ANY (bus) AND v.created_at <= coalesce(at, now()) GROUP BY v.control_id),
  m AS (
    SELECT m.requirement_id, m.control_id, m.control_version, m.bu_id, m.strength, m.implementation,
      convert_from(v.document, 'UTF8')::jsonb ->> 'name' AS name
    FROM framework.control_mapping m
    JOIN cv ON cv.control_id = m.control_id AND cv.version = m.control_version
    JOIN risk.control_version v ON v.control_id = m.control_id AND v.version = m.control_version
    WHERE m.bu_id = ANY (bus) AND (m.archived_at IS NULL OR m.archived_at > coalesce(at, now()))),
  d AS (SELECT * FROM framework.derived_at(version, at) WHERE requirement_id IN (SELECT id FROM reqs))
  SELECT r.id, r.identifier, r.label, r.title, r.parent, r.ord,
    CASE WHEN dir.full_n > 0 THEN CASE WHEN dir.full_in_place = dir.full_n THEN 'in_place' ELSE 'not_in_place' END
         WHEN dir.n > 0 OR jsonb_array_length(der.list) > 0 THEN 'partial'
         ELSE 'not_covered' END,
    dir.list, der.list
  FROM reqs r
  CROSS JOIN LATERAL (
    SELECT count(*) AS n, count(*) FILTER (WHERE m.strength = 'full') AS full_n,
      count(*) FILTER (WHERE m.strength = 'full' AND m.implementation = 'in_place') AS full_in_place,
      coalesce(jsonb_agg(jsonb_build_object('control_id', m.control_id, 'version', m.control_version, 'name', m.name, 'bu_id', m.bu_id,
        'strength', m.strength, 'implementation', m.implementation) ORDER BY m.name, m.control_id), '[]') AS list
    FROM m WHERE m.requirement_id = r.id) dir
  CROSS JOIN LATERAL (
    SELECT coalesce(jsonb_agg(jsonb_build_object('control_id', m.control_id, 'version', m.control_version, 'name', m.name, 'bu_id', m.bu_id,
        'strength', m.strength, 'implementation', m.implementation, 'via', d.via, 'via_requirement_id', d.via_requirement_id,
        'crosswalk_id', d.crosswalk_id, 'crosswalk', d.crosswalk, 'relationship', d.relationship, 'reach', d.reach)
        ORDER BY d.via, m.name, m.control_id), '[]') AS list
    FROM d JOIN m ON m.requirement_id = d.via_requirement_id WHERE d.requirement_id = r.id) der;
$$;

REVOKE ALL ON FUNCTION framework.coverage_requirements(uuid, uuid, timestamptz), framework.derived_at(uuid, timestamptz),
  framework.coverage_rows(uuid, uuid, timestamptz, uuid[]), framework.coverage_head(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.coverage_head(uuid, uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION framework.coverage_requirements(uuid, uuid, timestamptz), framework.derived_at(uuid, timestamptz),
  framework.coverage_rows(uuid, uuid, timestamptz, uuid[]) TO app_rw, rollup_definer;

RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Restricted units' totals (rollup_definer: the bu_rollup policy admits the
-- caller's aggregate-only units' rows to it alone).
GRANT CREATE ON SCHEMA framework TO rollup_definer;
SET ROLE rollup_definer;

CREATE FUNCTION framework.coverage_aggregate(version uuid, baseline uuid, at timestamptz, target uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE bus uuid[]; out jsonb;
BEGIN
  SELECT coalesce(array_agg(c.bu_id), '{}') INTO bus FROM authz.rollup_coverage('control', target) c WHERE c.mode = 'aggregate';
  IF cardinality(bus) = 0 THEN
    RETURN NULL;
  END IF;
  SELECT jsonb_build_object('units', cardinality(bus), 'label', 'restricted business units (totals only)',
    'counts', jsonb_build_object('in_place', count(*) FILTER (WHERE x.state = 'in_place'), 'not_in_place', count(*) FILTER (WHERE x.state = 'not_in_place'),
      'partial', count(*) FILTER (WHERE x.state = 'partial'), 'not_covered', count(*) FILTER (WHERE x.state = 'not_covered')))
  INTO out FROM framework.coverage_rows(version, baseline, at, bus) x;
  RETURN out;
END $$;
REVOKE ALL ON FUNCTION framework.coverage_aggregate(uuid, uuid, timestamptz, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.coverage_aggregate(uuid, uuid, timestamptz, uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM rollup_definer;

SET ROLE framework_definer;

-- The read (invoker; app_rw).
CREATE FUNCTION framework.coverage(version uuid, baseline uuid, bu uuid, as_of timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE full_bus uuid[]; left_out integer; rows jsonb; counts jsonb; head jsonb;
BEGIN
  IF bu IS NULL OR NOT bu = ANY ((SELECT authz.visible_bus('control', 'read'))::uuid[]) THEN
    IF cardinality((SELECT authz.visible_bus('control', 'read'))::uuid[]) > 0 THEN
      RAISE EXCEPTION 'framework: control.view at the business unit is needed' USING ERRCODE = 'PF033', HINT = 'forbidden';
    END IF;
    RAISE EXCEPTION 'framework: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  IF as_of IS NOT NULL AND as_of > now() THEN
    RAISE EXCEPTION 'framework: as_of is in the future' USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  SELECT coalesce(array_agg(c.bu_id) FILTER (WHERE c.mode = 'full'), '{}'), count(*) FILTER (WHERE c.mode = 'excluded')
  INTO full_bus, left_out FROM authz.rollup_coverage('control', bu) c;
  SELECT coalesce(jsonb_agg(jsonb_build_object('id', x.requirement_id, 'identifier', x.identifier, 'label', x.label, 'title', x.title,
      'parent', x.parent, 'state', x.state, 'direct', x.direct, 'derived', x.derived) ORDER BY x.ord), '[]'),
    jsonb_build_object('in_place', count(*) FILTER (WHERE x.state = 'in_place'), 'not_in_place', count(*) FILTER (WHERE x.state = 'not_in_place'),
      'partial', count(*) FILTER (WHERE x.state = 'partial'), 'not_covered', count(*) FILTER (WHERE x.state = 'not_covered'))
  INTO rows, counts FROM framework.coverage_rows(version, baseline, as_of, full_bus) x;
  SELECT framework.coverage_head(version, baseline) INTO head;
  RETURN head || jsonb_build_object('bu_id', bu, 'as_of', as_of, 'requirements', rows, 'counts', counts,
    'restricted', framework.coverage_aggregate(version, baseline, as_of, bu), 'left_out', left_out);
END $$;
REVOKE ALL ON FUNCTION framework.coverage(uuid, uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.coverage(uuid, uuid, uuid, timestamptz) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

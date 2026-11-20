-- F-013 T-11 (requirements NFR "Performance"; design §3.5): coverage within
-- its budget at 10,000 controls and 50,000 mappings. framework.coverage_rows
-- (0166) is rewritten, with the same result:
--   * the business units are a set (a semi-join), not an array compared per
--     row;
--   * each control's version in force is chosen with its name in one pass
--     (materialized), not joined again per mapping;
--   * only the mappings to the listed requirements, or to those a
--     crosswalk relates to them, are read, and grouped once by
--     requirement (0166 scanned them again for every requirement).
-- Invoker as before: the projection and the control versions are read under
-- the caller's row-level security.

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE OR REPLACE FUNCTION framework.coverage_rows(version uuid, baseline uuid, at timestamptz, bus uuid[])
RETURNS TABLE (requirement_id uuid, identifier text, label text, title text, parent text, ord integer, state text, direct jsonb, derived jsonb)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH b AS (SELECT DISTINCT unnest(bus) AS bu_id),
  reqs AS (SELECT * FROM framework.coverage_requirements(version, baseline, at)),
  d AS (SELECT x.* FROM framework.derived_at(version, at) x WHERE x.requirement_id IN (SELECT id FROM reqs)),
  wanted AS (SELECT id FROM reqs UNION SELECT via_requirement_id FROM d),
  -- Each readable control's version in force, with its name (parsed once).
  cv AS MATERIALIZED (
    SELECT DISTINCT ON (v.control_id) v.control_id, v.version, convert_from(v.document, 'UTF8')::jsonb ->> 'name' AS name
    FROM risk.control_version v
    WHERE v.bu_id IN (SELECT bu_id FROM b) AND v.created_at <= coalesce(at, now())
    ORDER BY v.control_id, v.version DESC),
  m AS MATERIALIZED (
    SELECT m.requirement_id, m.control_id, m.control_version, m.bu_id, m.strength, m.implementation, cv.name
    FROM framework.control_mapping m JOIN cv ON cv.control_id = m.control_id AND cv.version = m.control_version
    WHERE m.requirement_id IN (SELECT id FROM wanted) AND m.bu_id IN (SELECT bu_id FROM b)
      AND (m.archived_at IS NULL OR m.archived_at > coalesce(at, now()))),
  dir AS (
    SELECT m.requirement_id, count(*) AS n, count(*) FILTER (WHERE m.strength = 'full') AS full_n,
      count(*) FILTER (WHERE m.strength = 'full' AND m.implementation = 'in_place') AS full_in_place,
      jsonb_agg(jsonb_build_object('control_id', m.control_id, 'version', m.control_version, 'name', m.name, 'bu_id', m.bu_id,
        'strength', m.strength, 'implementation', m.implementation) ORDER BY m.name, m.control_id) AS list
    FROM m GROUP BY m.requirement_id),
  der AS (
    SELECT d.requirement_id, jsonb_agg(jsonb_build_object('control_id', m.control_id, 'version', m.control_version, 'name', m.name, 'bu_id', m.bu_id,
        'strength', m.strength, 'implementation', m.implementation, 'via', d.via, 'via_requirement_id', d.via_requirement_id,
        'crosswalk_id', d.crosswalk_id, 'crosswalk', d.crosswalk, 'relationship', d.relationship, 'reach', d.reach)
        ORDER BY d.via, m.name, m.control_id) AS list
    FROM d JOIN m ON m.requirement_id = d.via_requirement_id GROUP BY d.requirement_id)
  SELECT r.id, r.identifier, r.label, r.title, r.parent, r.ord,
    CASE WHEN coalesce(dir.full_n, 0) > 0 THEN CASE WHEN dir.full_in_place = dir.full_n THEN 'in_place' ELSE 'not_in_place' END
         WHEN coalesce(dir.n, 0) > 0 OR der.list IS NOT NULL THEN 'partial'
         ELSE 'not_covered' END,
    coalesce(dir.list, '[]'), coalesce(der.list, '[]')
  FROM reqs r LEFT JOIN dir ON dir.requirement_id = r.id LEFT JOIN der ON der.requirement_id = r.id;
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

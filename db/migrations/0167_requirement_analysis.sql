-- F-013 T-09 (F-013-AC-16 to AC-18; design §3.6): requirements to analysis.
--
--   * framework.requirement_scenarios(requirement, lim): the controls the
--     caller may read that map to the requirement now (their latest
--     versions, not archived), with strength, implementation and FAIR
--     effects; the scenarios the caller may read whose latest version pins
--     one of them in a current control set ("uses"), and those in the
--     controls' business-unit subtrees that do not ("could_use"); at most
--     lim each, with whether more remain. Invoker: everything risk-side is
--     read under the caller's row-level security.
--   * framework.addressed(scenarios): for the given scenarios, the
--     requirements the controls of their latest versions' current sets map
--     to now, by framework version (the register's risk view, AC-18).
--   * framework.requirement_info(ids): what those reads show of a
--     requirement (reference data; readers only).

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE FUNCTION framework.requirement_info(ids uuid[])
RETURNS TABLE (id uuid, identifier text, label text, title text, ord integer, version_id uuid, family text, family_title text, version_label text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF coalesce(cardinality(ids), 0) = 0 THEN
    RETURN;  -- nothing asked: no reader check (the register's risk view asks for none when no mapped control is visible)
  END IF;
  PERFORM framework.reader();
  RETURN QUERY SELECT r.id, r.identifier, r.label, r.title, r.ord, v.id, v.family, f.title, v.label
    FROM framework.requirement r JOIN framework.version v ON v.id = r.version_id JOIN framework.family f ON f.key = v.family
    WHERE r.id = ANY (ids);
END $$;
REVOKE ALL ON FUNCTION framework.requirement_info(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.requirement_info(uuid[]) TO app_rw;

CREATE FUNCTION framework.requirement_scenarios(requirement uuid, lim integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE req jsonb; ctls jsonb; ids uuid[]; bus uuid[]; uses jsonb; could jsonb; n integer := greatest(least(coalesce(lim, 200), 200), 1);
  uses_n integer; could_n integer;
BEGIN
  IF cardinality((SELECT authz.visible_bus('scenario', 'read'))::uuid[]) = 0 OR cardinality((SELECT authz.visible_bus('control', 'read'))::uuid[]) = 0 THEN
    RAISE EXCEPTION 'framework: no such requirement %', requirement USING ERRCODE = 'P0002';
  END IF;
  req := framework.requirement_get(requirement);
  SELECT coalesce(jsonb_agg(jsonb_build_object('id', m.control_id, 'version', m.control_version, 'bu_id', m.bu_id,
      'name', d ->> 'name', 'strength', m.strength, 'implementation', m.implementation, 'effects', coalesce(d -> 'effects', '[]')) ORDER BY d ->> 'name', m.control_id), '[]'),
    coalesce(array_agg(m.control_id), '{}'), coalesce(array_agg(DISTINCT m.bu_id), '{}')
  INTO ctls, ids, bus
  FROM framework.control_mapping m
  JOIN risk.control c ON c.id = m.control_id AND c.archived_at IS NULL
  JOIN risk.control_version v ON v.control_id = m.control_id AND v.version = m.control_version
  CROSS JOIN LATERAL (SELECT convert_from(v.document, 'UTF8')::jsonb AS d) x
  WHERE m.requirement_id = requirement_scenarios.requirement AND m.current AND m.archived_at IS NULL;

  -- Scenarios whose latest version pins one of the controls in a current set.
  WITH u AS (
    SELECT s.id, s.name, s.bu_id, s.current_version,
      array_agg(DISTINCT sd.doc -> 'control_sets' -> split_part(p.pointer, '/', 3)::integer ->> 'name') AS sets,
      array_agg(DISTINCT p.to_id) AS controls
    FROM risk.scenario s
    JOIN risk.scenario_pin p ON p.scenario_id = s.id AND p.version = s.current_version AND p.to_kind = 'control' AND p.to_id = ANY (ids)
      AND p.pointer ~ '^/control_sets/[0-9]+/controls/[0-9]+$'
    JOIN risk.scenario_version sv ON sv.scenario_id = s.id AND sv.version = s.current_version
    CROSS JOIN LATERAL (SELECT convert_from(sv.document, 'UTF8')::jsonb AS doc) sd
    WHERE s.archived_at IS NULL
      AND (sd.doc -> 'control_sets' -> split_part(p.pointer, '/', 3)::integer ->> 'current')::boolean
    GROUP BY s.id, s.name, s.bu_id, s.current_version)
  SELECT (SELECT count(*) FROM u),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', u.id, 'name', u.name, 'bu_id', u.bu_id, 'version', u.current_version,
      'sets', to_jsonb(u.sets), 'controls', to_jsonb(u.controls)) ORDER BY u.name, u.id) FROM (SELECT * FROM u ORDER BY u.name, u.id LIMIT n) u), '[]')
  INTO uses_n, uses;

  -- Scenarios in the controls' subtrees that do not use any of them.
  WITH sub AS (
    SELECT DISTINCT c.bu_id FROM unnest(bus) b, LATERAL authz.rollup_coverage('scenario', b) c WHERE c.mode = 'full'),
  cu AS (
    SELECT s.id, s.name, s.bu_id, s.current_version FROM risk.scenario s
    WHERE s.archived_at IS NULL AND s.current_version > 0 AND s.bu_id IN (SELECT bu_id FROM sub)
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(uses) e WHERE (e ->> 'id')::uuid = s.id)
      AND NOT EXISTS (
        SELECT 1 FROM risk.scenario_pin p JOIN risk.scenario_version sv ON sv.scenario_id = p.scenario_id AND sv.version = p.version
        WHERE p.scenario_id = s.id AND p.version = s.current_version AND p.to_kind = 'control' AND p.to_id = ANY (ids)
          AND p.pointer ~ '^/control_sets/[0-9]+/controls/[0-9]+$'
          AND (convert_from(sv.document, 'UTF8')::jsonb -> 'control_sets' -> split_part(p.pointer, '/', 3)::integer ->> 'current')::boolean))
  SELECT (SELECT count(*) FROM cu),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', x.id, 'name', x.name, 'bu_id', x.bu_id, 'version', x.current_version) ORDER BY x.name, x.id)
      FROM (SELECT * FROM cu ORDER BY cu.name, cu.id LIMIT n) x), '[]')
  INTO could_n, could;

  RETURN jsonb_build_object('requirement', req, 'controls', ctls, 'uses', uses, 'uses_more', uses_n > n,
    'could_use', could, 'could_use_more', could_n > n);
END $$;
REVOKE ALL ON FUNCTION framework.requirement_scenarios(uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.requirement_scenarios(uuid, integer) TO app_rw;

CREATE FUNCTION framework.addressed(scenarios uuid[]) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH ctl AS (
    SELECT DISTINCT p.to_id AS control_id
    FROM risk.scenario s
    JOIN risk.scenario_pin p ON p.scenario_id = s.id AND p.version = s.current_version AND p.to_kind = 'control'
      AND p.pointer ~ '^/control_sets/[0-9]+/controls/[0-9]+$'
    JOIN risk.scenario_version sv ON sv.scenario_id = s.id AND sv.version = s.current_version
    WHERE s.id = ANY (scenarios)
      AND (convert_from(sv.document, 'UTF8')::jsonb -> 'control_sets' -> split_part(p.pointer, '/', 3)::integer ->> 'current')::boolean),
  m AS (
    SELECT m.requirement_id, m.control_id, m.strength, convert_from(v.document, 'UTF8')::jsonb ->> 'name' AS name
    FROM framework.control_mapping m JOIN ctl ON ctl.control_id = m.control_id
    JOIN risk.control_version v ON v.control_id = m.control_id AND v.version = m.control_version
    WHERE m.current AND m.archived_at IS NULL),
  r AS (
    SELECT i.*, (SELECT jsonb_agg(jsonb_build_object('id', m.control_id, 'name', m.name, 'strength', m.strength) ORDER BY m.name, m.control_id)
                 FROM m WHERE m.requirement_id = i.id) AS controls
    FROM framework.requirement_info((SELECT coalesce(array_agg(DISTINCT m.requirement_id), '{}') FROM m)) i)
  SELECT coalesce(jsonb_agg(g.j ORDER BY g.family, g.version_label), '[]') FROM (
    SELECT r.family, r.version_label, jsonb_build_object('version', jsonb_build_object('id', r.version_id, 'family', r.family,
        'family_title', r.family_title, 'label', r.version_label),
      'requirements', jsonb_agg(jsonb_build_object('id', r.id, 'identifier', r.identifier, 'label', r.label, 'title', r.title, 'controls', r.controls) ORDER BY r.ord)) AS j
    FROM r GROUP BY r.family, r.version_label, r.version_id, r.family_title) g;
$$;
REVOKE ALL ON FUNCTION framework.addressed(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.addressed(uuid[]) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

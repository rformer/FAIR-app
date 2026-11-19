-- F-013 T-07 (F-013-AC-10, AC-11; design §3.3): crosswalks.
--
--   * Imports of kind crosswalk (fair.crosswalk.v1 JSON or CSV, or an OSCAL
--     mapping collection, parsed by the job): framework.finish_import checks,
--     dry run or not, that both versions are imported and that every
--     relationship names requirements of them (AC-10: refused whole, by
--     pointer, at most 100 problems listed), and that the crosswalk is new
--     (source, target and label); then records it with its relationships.
--   * Reads: framework.crosswalks(version, include_retired) (crosswalks from
--     or to the version), framework.crosswalk_get(id, lim, off) with its
--     relationships by identifier.
--   * framework.retire_crosswalk(id, reason): kept readable, no longer
--     derives coverage.
--   * framework.state_only (0161) fixed: retiring a baseline or crosswalk
--     failed on a column only versions have.
--   * framework.derived(version): for each requirement R of the version, the
--     requirements R' of other versions related to it by an active crosswalk,
--     stated as "R' <relationship> R" (a crosswalk recorded the other way is
--     inverted: subset_of and superset_of swap). Reach is 'equivalent' when
--     R' equal R or R' superset_of R (satisfying R' satisfies R), otherwise
--     'partial'. Coverage (T-08) reports derived coverage apart from direct,
--     and never as in place (AC-11).

-- 0161's state rule read OLD.diff for every table, which fails for
-- baselines and crosswalks (they have none): retiring them failed. The
-- version's rule now reads it only for versions.
CREATE OR REPLACE FUNCTION framework.state_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state', 'retired_at', 'retired_by', 'diff']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state', 'retired_at', 'retired_by', 'diff']) THEN
    RAISE EXCEPTION 'framework: a % keeps what was imported; only its state changes', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'immutable';
  END IF;
  IF OLD.state = 'retired' AND (NEW.state <> 'retired' OR NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
    RAISE EXCEPTION 'framework: a retired % stays retired', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'retired';
  END IF;
  IF TG_TABLE_NAME = 'version' THEN
    IF (to_jsonb(OLD) -> 'diff') <> 'null' AND (to_jsonb(NEW) -> 'diff') IS DISTINCT FROM (to_jsonb(OLD) -> 'diff') THEN
      RAISE EXCEPTION 'framework: a version''s diff is recorded once' USING ERRCODE = 'PF033', HINT = 'immutable';
    END IF;
  END IF;
  RETURN NEW;
END $$;

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE OR REPLACE FUNCTION framework.request_import(kind text, sha256 text, file bytea, meta jsonb, dry_run boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.manager(); id uuid;
BEGIN
  IF kind IS NULL OR kind NOT IN ('catalog', 'profile', 'simple', 'crosswalk') THEN
    RAISE EXCEPTION 'framework: an import is a catalog, a profile, a simple framework or a crosswalk' USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  IF (SELECT count(*) FROM framework.import x WHERE x.state IN ('queued', 'running')) >= 5 THEN
    RAISE EXCEPTION 'framework: at most 5 imports at a time' USING ERRCODE = 'PF034', HINT = 'too_many_imports';
  END IF;
  INSERT INTO framework.import (kind, dry_run, requested_by, sha256, file, meta)
  VALUES (kind, coalesce(dry_run, false), u, request_import.sha256, request_import.file, coalesce(request_import.meta, '{}'))
  RETURNING import.id INTO id;
  RETURN id;
END $$;

CREATE FUNCTION framework.crosswalk_json(x framework.crosswalk) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', x.id, 'title', x.title, 'publisher', x.publisher, 'label', x.label, 'source', x.source, 'sha256', x.sha256,
    'state', x.state, 'imported_at', x.imported_at, 'retired_at', x.retired_at,
    'source_version', (SELECT jsonb_build_object('id', v.id, 'family', v.family, 'label', v.label) FROM framework.version v WHERE v.id = x.source_version),
    'target_version', (SELECT jsonb_build_object('id', v.id, 'family', v.family, 'label', v.label) FROM framework.version v WHERE v.id = x.target_version),
    'relationships', (SELECT count(*) FROM framework.relationship r WHERE r.crosswalk_id = x.id),
    'by_relationship', (SELECT coalesce(jsonb_object_agg(k, n), '{}') FROM (SELECT r.relationship AS k, count(*) AS n FROM framework.relationship r
                        WHERE r.crosswalk_id = x.id GROUP BY r.relationship) c));
$$;

CREATE FUNCTION framework.crosswalks(version uuid, include_retired boolean) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM framework.reader();
  RETURN coalesce((SELECT jsonb_agg(framework.crosswalk_json(x) ORDER BY x.title, x.label)
    FROM framework.crosswalk x WHERE (version IS NULL OR version IN (x.source_version, x.target_version)) AND (include_retired OR x.state = 'active')), '[]');
END $$;

CREATE FUNCTION framework.crosswalk_get(id uuid, lim integer, off integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE x framework.crosswalk; rels jsonb; total bigint;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO x FROM framework.crosswalk c WHERE c.id = crosswalk_get.id;
  IF x.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such crosswalk %', id USING ERRCODE = 'P0002';
  END IF;
  SELECT count(*) INTO total FROM framework.relationship r WHERE r.crosswalk_id = x.id;
  SELECT coalesce(jsonb_agg(q.j ORDER BY q.so, q.tor), '[]') INTO rels FROM (
    SELECT jsonb_build_object('source', s.identifier, 'source_id', s.id, 'source_title', s.title,
      'target', t.identifier, 'target_id', t.id, 'target_title', t.title, 'relationship', r.relationship) AS j, s.ord AS so, t.ord AS tor
    FROM framework.relationship r JOIN framework.requirement s ON s.id = r.source_id JOIN framework.requirement t ON t.id = r.target_id
    WHERE r.crosswalk_id = x.id ORDER BY s.ord, t.ord
    LIMIT greatest(least(coalesce(lim, 500), 5000), 1) OFFSET greatest(coalesce(off, 0), 0)) q;
  RETURN framework.crosswalk_json(x) || jsonb_build_object('relationship_list', rels,
    'more', greatest(coalesce(off, 0), 0) + jsonb_array_length(rels) < total);
END $$;

CREATE FUNCTION framework.retire_crosswalk(id uuid, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.manager(); x framework.crosswalk;
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'framework: retiring needs a reason (at most 500 characters)' USING ERRCODE = 'PF033', HINT = 'reason_required';
  END IF;
  SELECT * INTO x FROM framework.crosswalk c WHERE c.id = retire_crosswalk.id FOR UPDATE;
  IF x.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such crosswalk %', id USING ERRCODE = 'P0002';
  END IF;
  IF x.state = 'retired' THEN
    RAISE EXCEPTION 'framework: the crosswalk is already retired' USING ERRCODE = 'PF033', HINT = 'retired';
  END IF;
  UPDATE framework.crosswalk c SET state = 'retired', retired_at = now() WHERE c.id = x.id RETURNING * INTO x;
  PERFORM framework.emit('framework.crosswalk_retired', u, 'framework_crosswalk:' || x.id,
    jsonb_build_object('crosswalk', x.title, 'label', x.label, 'reason', btrim(reason)));
  RETURN framework.crosswalk_json(x);
END $$;

CREATE FUNCTION framework.derived(version uuid)
RETURNS TABLE (requirement_id uuid, via_requirement_id uuid, crosswalk_id uuid, relationship text, reach text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH rel AS (
    SELECT r.target_id AS req, r.source_id AS via, r.crosswalk_id, r.relationship AS rel
    FROM framework.relationship r JOIN framework.crosswalk x ON x.id = r.crosswalk_id AND x.state = 'active' AND x.target_version = derived.version
    UNION ALL
    SELECT r.source_id, r.target_id, r.crosswalk_id,
      CASE r.relationship WHEN 'subset_of' THEN 'superset_of' WHEN 'superset_of' THEN 'subset_of' ELSE r.relationship END
    FROM framework.relationship r JOIN framework.crosswalk x ON x.id = r.crosswalk_id AND x.state = 'active' AND x.source_version = derived.version)
  SELECT req, via, crosswalk_id, rel, CASE WHEN rel IN ('equal', 'superset_of') THEN 'equivalent' ELSE 'partial' END FROM rel;
$$;

-- finish_import, as 0163's, with crosswalks.
CREATE OR REPLACE FUNCTION framework.finish_import(id uuid, outcome text, problems jsonb, result jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i framework.import; v jsonb; vid uuid; bid uuid; prev uuid; added jsonb := '{}'; x jsonb; sv uuid; tv uuid; probs jsonb; xid uuid; n bigint;
BEGIN
  SELECT * INTO i FROM framework.import y WHERE y.id = finish_import.id FOR UPDATE;
  IF i.id IS NULL OR i.state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'framework: import % is finished', id USING ERRCODE = 'PF033', HINT = 'import_finished';
  END IF;
  IF outcome = 'refused' OR outcome = 'failed' THEN
    UPDATE framework.import y SET state = outcome, problems = coalesce(finish_import.problems, '[]'), file = NULL, finished_at = now()
    WHERE y.id = i.id RETURNING * INTO i;
    PERFORM framework.emit('framework.import_refused', i.requested_by, 'framework_import:' || i.id,
      jsonb_build_object('import', i.id::text, 'kind', i.kind, 'sha256', i.sha256, 'problems', jsonb_array_length(i.problems)::text, 'outcome', outcome));
    RETURN framework.import_json(i);
  END IF;
  IF outcome <> 'succeeded' THEN
    RAISE EXCEPTION 'framework: % is not an outcome', outcome USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  -- The database has the last word on duplicates and, for a crosswalk, on
  -- what its relationships name (AC-10).
  IF result ? 'version' THEN
    v := result -> 'version';
    IF EXISTS (SELECT 1 FROM framework.version y WHERE y.family = v -> 'family' ->> 'key' AND y.label = v ->> 'label') THEN
      probs := jsonb_build_array(jsonb_build_object('pointer', '/version/label', 'message', 'this version of the framework is already imported'));
    END IF;
  ELSIF result ? 'baseline' THEN
    IF EXISTS (SELECT 1 FROM framework.baseline b JOIN framework.version y ON y.id = b.version_id
        WHERE y.family = result -> 'baseline' -> 'version' ->> 'family' AND y.label = result -> 'baseline' -> 'version' ->> 'version' AND b.key = result -> 'baseline' ->> 'key') THEN
      probs := jsonb_build_array(jsonb_build_object('pointer', '/key', 'message', 'this version already has a baseline with this key'));
    END IF;
  ELSIF result ? 'crosswalk' THEN
    x := result -> 'crosswalk';
    SELECT y.id INTO sv FROM framework.version y WHERE y.family = x -> 'source' ->> 'family' AND y.label = x -> 'source' ->> 'version';
    SELECT y.id INTO tv FROM framework.version y WHERE y.family = x -> 'target' ->> 'family' AND y.label = x -> 'target' ->> 'version';
    IF sv IS NULL OR tv IS NULL THEN
      probs := '[]';
      IF sv IS NULL THEN
        probs := probs || jsonb_build_object('pointer', '/source', 'message', format('%s %s is not imported', x -> 'source' ->> 'family', x -> 'source' ->> 'version'));
      END IF;
      IF tv IS NULL THEN
        probs := probs || jsonb_build_object('pointer', '/target', 'message', format('%s %s is not imported', x -> 'target' ->> 'family', x -> 'target' ->> 'version'));
      END IF;
    ELSIF EXISTS (SELECT 1 FROM framework.crosswalk c WHERE c.source_version = sv AND c.target_version = tv AND c.label = x ->> 'label') THEN
      probs := jsonb_build_array(jsonb_build_object('pointer', '/label', 'message', 'a crosswalk between these versions with this label is already imported'));
    ELSE
      SELECT jsonb_agg(p ORDER BY o) INTO probs FROM (
        SELECT o, jsonb_build_object('pointer', format('/relationships/%s/%s', o - 1, side), 'message', format('%s %s has no requirement %s', fam, lab, ident)) AS p
        FROM jsonb_array_elements(x -> 'relationships') WITH ORDINALITY AS t(l, o),
        LATERAL (VALUES ('source', l ->> 'source', sv, x -> 'source' ->> 'family', x -> 'source' ->> 'version'),
                        ('target', l ->> 'target', tv, x -> 'target' ->> 'family', x -> 'target' ->> 'version')) AS s(side, ident, ver, fam, lab)
        WHERE NOT EXISTS (SELECT 1 FROM framework.requirement r WHERE r.version_id = s.ver AND r.identifier = s.ident)
        ORDER BY o, side LIMIT 100) q;
    END IF;
  END IF;
  IF probs IS NOT NULL AND jsonb_array_length(probs) > 0 THEN
    UPDATE framework.import y SET state = 'refused', file = NULL, finished_at = now(), problems = probs WHERE y.id = i.id RETURNING * INTO i;
    PERFORM framework.emit('framework.import_refused', i.requested_by, 'framework_import:' || i.id,
      jsonb_build_object('import', i.id::text, 'kind', i.kind, 'sha256', i.sha256, 'problems', jsonb_array_length(probs)::text, 'outcome', 'refused'));
    RETURN framework.import_json(i);
  END IF;
  IF NOT i.dry_run THEN
    IF result ? 'version' THEN
      INSERT INTO framework.family (key, title, publisher) VALUES (v -> 'family' ->> 'key', v -> 'family' ->> 'title', nullif(v -> 'family' ->> 'publisher', ''))
      ON CONFLICT (key) DO NOTHING;
      INSERT INTO framework.version (family, label, title, published, source, format, sha256, diff, imported_by)
      VALUES (v -> 'family' ->> 'key', v ->> 'label', v ->> 'title', nullif(v ->> 'published', '')::date, 'upload', v ->> 'format', i.sha256,
              result -> 'diff', i.requested_by)
      RETURNING framework.version.id INTO vid;
      INSERT INTO framework.requirement (version_id, identifier, label, title, statement, parent, ord, withdrawn, incorporated_into)
      SELECT vid, r ->> 'identifier', nullif(r ->> 'label', ''), r ->> 'title', nullif(r ->> 'statement', ''), nullif(r ->> 'parent', ''), (o - 1)::integer,
        coalesce((r ->> 'withdrawn')::boolean, false),
        coalesce(ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(r -> 'incorporated_into') = 'array' THEN r -> 'incorporated_into' ELSE '[]' END)), '{}')
      FROM jsonb_array_elements(v -> 'requirements') WITH ORDINALITY AS t(r, o);
      PERFORM framework.emit('framework.imported', i.requested_by, 'framework_version:' || vid,
        jsonb_build_object('import', i.id::text, 'family', v -> 'family' ->> 'key', 'version', v ->> 'label', 'format', v ->> 'format', 'sha256', i.sha256,
          'requirements', jsonb_array_length(v -> 'requirements')::text));
      added := jsonb_build_object('version_id', vid);
    ELSIF result ? 'baseline' THEN
      SELECT y.id INTO prev FROM framework.version y WHERE y.family = result -> 'baseline' -> 'version' ->> 'family' AND y.label = result -> 'baseline' -> 'version' ->> 'version';
      INSERT INTO framework.baseline (version_id, key, title, source, sha256, selected, parameters, notes, imported_by)
      VALUES (prev, result -> 'baseline' ->> 'key', result -> 'baseline' ->> 'title', 'upload', i.sha256,
        ARRAY(SELECT jsonb_array_elements_text(result -> 'baseline' -> 'selected')),
        CASE WHEN jsonb_typeof(result -> 'baseline' -> 'parameters') = 'object' THEN result -> 'baseline' -> 'parameters' ELSE '{}' END,
        coalesce(ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(result -> 'baseline' -> 'notes') = 'array' THEN result -> 'baseline' -> 'notes' ELSE '[]' END)), '{}'),
        i.requested_by)
      RETURNING framework.baseline.id INTO bid;
      PERFORM framework.emit('framework.baseline_imported', i.requested_by, 'framework_baseline:' || bid,
        jsonb_build_object('import', i.id::text, 'baseline', result -> 'baseline' ->> 'key', 'family', result -> 'baseline' -> 'version' ->> 'family',
          'version', result -> 'baseline' -> 'version' ->> 'version', 'sha256', i.sha256, 'requirements', jsonb_array_length(result -> 'baseline' -> 'selected')::text));
      added := jsonb_build_object('baseline_id', bid);
    ELSIF result ? 'crosswalk' THEN
      INSERT INTO framework.crosswalk (title, publisher, label, source_version, target_version, source, sha256, imported_by)
      VALUES (x ->> 'title', nullif(x ->> 'publisher', ''), x ->> 'label', sv, tv, 'upload', i.sha256, i.requested_by)
      RETURNING framework.crosswalk.id INTO xid;
      INSERT INTO framework.relationship (crosswalk_id, source_id, target_id, relationship)
      SELECT xid, s.id, t.id, l ->> 'relationship'
      FROM jsonb_array_elements(x -> 'relationships') l
      JOIN framework.requirement s ON s.version_id = sv AND s.identifier = l ->> 'source'
      JOIN framework.requirement t ON t.version_id = tv AND t.identifier = l ->> 'target';
      GET DIAGNOSTICS n = ROW_COUNT;
      PERFORM framework.emit('framework.crosswalk_imported', i.requested_by, 'framework_crosswalk:' || xid,
        jsonb_build_object('import', i.id::text, 'crosswalk', x ->> 'title', 'label', x ->> 'label',
          'source', (x -> 'source' ->> 'family') || ' ' || (x -> 'source' ->> 'version'), 'target', (x -> 'target' ->> 'family') || ' ' || (x -> 'target' ->> 'version'),
          'sha256', i.sha256, 'relationships', n::text));
      added := jsonb_build_object('crosswalk_id', xid);
    END IF;
  END IF;
  UPDATE framework.import y SET state = 'succeeded', file = NULL, finished_at = now(),
    result = jsonb_strip_nulls(jsonb_build_object('summary', finish_import.result -> 'summary', 'diff', finish_import.result -> 'diff')) || added
  WHERE y.id = i.id RETURNING * INTO i;
  RETURN framework.import_json(i);
END $$;

REVOKE ALL ON FUNCTION framework.crosswalk_json(framework.crosswalk), framework.crosswalks(uuid, boolean), framework.crosswalk_get(uuid, integer, integer),
  framework.retire_crosswalk(uuid, text), framework.derived(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.crosswalks(uuid, boolean), framework.crosswalk_get(uuid, integer, integer), framework.retire_crosswalk(uuid, text),
  framework.derived(uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

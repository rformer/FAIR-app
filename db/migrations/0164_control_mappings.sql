-- F-013 T-06 (F-013-AC-07 to AC-09, AC-19, AC-20; design §3.4): a control's
-- framework mappings, in its versioned document.
--
--   * risk.mappings(x, ptr): the shape, as model.Validate checks it
--     (TestRiskValidationParity holds them equal): at most 500, each a
--     family key, a version label, a requirement identifier and a strength
--     (full, partial, supports), with an optional rationale, once each.
--   * framework.mapping_problems(mappings): that each named requirement
--     exists in an imported version and is not withdrawn; checked by
--     risk.check_document only when the shape is right (the database alone
--     can see it). Retired versions stay mappable, so a control mapped
--     before a retirement can still be saved.
--   * The projection (framework.control_mapping): each control version's
--     mappings, with the control's implementation status, are recorded when
--     the version is saved, the previous version's rows marked not current;
--     a move or archive of the control's versions carries to its rows.
--     control.mappings_changed records what was added and removed, in the
--     save's transaction, when the mappings changed (AC-19).
--   * framework.match_references(refs): F-003's plain references matched to
--     requirements of active versions (AC-08), by family key or title and
--     by identifier or label, ignoring case and punctuation.
--   * framework.mapping_updates(mappings): for mappings to a version with a
--     newer active version of its family, the equivalents there: the same
--     identifier, or what a withdrawn requirement was incorporated into
--     (AC-09).

CREATE FUNCTION risk.mappings(x jsonb, ptr text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; m jsonb; i integer := 0; mp text; k text; seen jsonb := '{}';
BEGIN
  IF jsonb_typeof(x) <> 'array' THEN
    RETURN risk.p(ptr, 'must be an array');
  END IF;
  IF jsonb_array_length(x) > 500 THEN
    RETURN risk.p(ptr, 'at most 500 mappings');
  END IF;
  FOR m IN SELECT * FROM jsonb_array_elements(x) LOOP
    mp := ptr || '/' || i;
    IF jsonb_typeof(m) <> 'object' THEN
      p := p || risk.p(mp, 'must be an object');
    ELSE
      p := p || risk.unknown(m, mp, ARRAY['framework', 'version', 'requirement', 'strength', 'rationale']);
      IF jsonb_typeof(m -> 'framework') IS DISTINCT FROM 'string' OR NOT (m ->> 'framework') ~ '^[a-z0-9][a-z0-9-]{0,62}$' THEN
        p := p || risk.p(mp || '/framework', 'is a framework family''s key (lower-case letters, digits and hyphens)');
      END IF;
      p := p || risk.text(m -> 'version', mp || '/version', 100, true, false);
      IF jsonb_typeof(m -> 'requirement') IS DISTINCT FROM 'string' OR NOT (m ->> 'requirement') ~ '^[A-Za-z0-9][A-Za-z0-9._:()-]{0,99}$' THEN
        p := p || risk.p(mp || '/requirement', 'is a requirement identifier');
      END IF;
      p := p || risk.oneof(m -> 'strength', mp || '/strength', ARRAY['full', 'partial', 'supports']);
      IF m ? 'rationale' THEN
        p := p || risk.text(m -> 'rationale', mp || '/rationale', 1000, false, true);
      END IF;
      k := concat_ws(E'\x1f', m ->> 'framework', m ->> 'version', m ->> 'requirement');
      IF seen ? k THEN
        p := p || risk.p(mp, 'repeats mapping ' || (seen ->> k));
      ELSE
        seen := seen || jsonb_build_object(k, i);
      END IF;
    END IF;
    i := i + 1;
  END LOOP;
  RETURN p;
END $$;
REVOKE ALL ON FUNCTION risk.mappings(jsonb, text) FROM PUBLIC;
-- risk.check_document runs as risk_definer (the version trigger) and calls
-- framework.mapping_problems.
GRANT USAGE ON SCHEMA framework TO risk_definer;
GRANT EXECUTE ON FUNCTION risk.mappings(jsonb, text) TO risk_definer;

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE FUNCTION framework.mapping_problems(mappings jsonb) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(array_agg('/mappings/' || (o - 1) || '/requirement: ' ||
      CASE WHEN r.id IS NULL THEN format('%s %s has no requirement %s', m ->> 'framework', m ->> 'version', m ->> 'requirement')
           ELSE format('%s %s %s is withdrawn', m ->> 'framework', m ->> 'version', m ->> 'requirement') END ORDER BY o), '{}')
  FROM jsonb_array_elements(mappings) WITH ORDINALITY AS t(m, o)
  LEFT JOIN framework.version v ON v.family = m ->> 'framework' AND v.label = m ->> 'version'
  LEFT JOIN framework.requirement r ON r.version_id = v.id AND r.identifier = m ->> 'requirement'
  WHERE r.id IS NULL OR r.withdrawn;
$$;

-- The projection, when a control version is saved.
CREATE FUNCTION framework.project_mappings() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE d jsonb := convert_from(NEW.document, 'UTF8')::jsonb; added text[]; removed text[];
BEGIN
  UPDATE framework.control_mapping m SET current = false WHERE m.control_id = NEW.control_id AND m.current;
  INSERT INTO framework.control_mapping (control_id, control_version, bu_id, requirement_id, strength, implementation)
  SELECT NEW.control_id, NEW.version, NEW.bu_id, r.id, x ->> 'strength', d -> 'implementation' ->> 'status'
  FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d -> 'mappings') = 'array' THEN d -> 'mappings' ELSE '[]' END) x
  JOIN framework.version v ON v.family = x ->> 'framework' AND v.label = x ->> 'version'
  JOIN framework.requirement r ON r.version_id = v.id AND r.identifier = x ->> 'requirement';
  -- What changed against the previous version (by requirement and strength).
  WITH now_ AS (SELECT r.identifier, v.family, v.label, m.strength FROM framework.control_mapping m
                JOIN framework.requirement r ON r.id = m.requirement_id JOIN framework.version v ON v.id = r.version_id
                WHERE m.control_id = NEW.control_id AND m.control_version = NEW.version),
       before AS (SELECT r.identifier, v.family, v.label, m.strength FROM framework.control_mapping m
                JOIN framework.requirement r ON r.id = m.requirement_id JOIN framework.version v ON v.id = r.version_id
                WHERE m.control_id = NEW.control_id AND m.control_version = NEW.version - 1)
  SELECT (SELECT coalesce(array_agg(family || ' ' || label || ' ' || identifier || ' ' || strength ORDER BY family, label, identifier), '{}')
          FROM (SELECT * FROM now_ EXCEPT SELECT * FROM before) a),
         (SELECT coalesce(array_agg(family || ' ' || label || ' ' || identifier || ' ' || strength ORDER BY family, label, identifier), '{}')
          FROM (SELECT * FROM before EXCEPT SELECT * FROM now_) b)
  INTO added, removed;
  IF cardinality(added) + cardinality(removed) > 0 THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'control.mappings_changed', 'severity', 'low', 'actor', NEW.author::text,
      'target', 'control:' || NEW.control_id, 'bu_id', NEW.bu_id,
      'attributes', jsonb_build_object('control', NEW.control_id::text, 'version', NEW.version::text,
        'added', left(array_to_string(added, '; '), 4000), 'removed', left(array_to_string(removed, '; '), 4000))));
  END IF;
  RETURN NULL;
END $$;

-- A move or archive of a control's version carries to its mapping rows.
CREATE FUNCTION framework.follow_control() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE framework.control_mapping m SET bu_id = NEW.bu_id, archived_at = NEW.archived_at
  WHERE m.control_id = NEW.control_id AND m.control_version = NEW.version
    AND (m.bu_id IS DISTINCT FROM NEW.bu_id OR m.archived_at IS DISTINCT FROM NEW.archived_at);
  RETURN NULL;
END $$;

-- References to requirements (AC-08). An identifier is compared by its
-- segments (AC-02(01), AC-2(1) and ac-2.1 are ac.2.1; AC-21 is ac.21); a
-- framework by its key or title without "SP" and a revision suffix
-- (NIST SP 800-53r5 is nist-800-53).
CREATE FUNCTION framework.norm_id(s text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT regexp_replace(btrim(regexp_replace(regexp_replace(lower(coalesce(s, '')), '([a-z])([0-9])', '\1.\2', 'g'), '[^a-z0-9]+', '.', 'g'), '.'),
    '(^|\.)0+([0-9])', '\1\2', 'g');
$$;

CREATE FUNCTION framework.norm_family(s text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT regexp_replace(regexp_replace(regexp_replace(lower(coalesce(s, '')), '\msp\M', '', 'g'), '[^a-z0-9]', '', 'g'), '(rev|r)[0-9]+$', '');
$$;

CREATE FUNCTION framework.match_references(refs jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH latest AS (
    SELECT DISTINCT ON (v.family) v.id, v.family, v.label, f.title FROM framework.version v JOIN framework.family f ON f.key = v.family
    WHERE v.state = 'active' ORDER BY v.family, v.published DESC NULLS LAST, v.imported_at DESC)
  SELECT coalesce(jsonb_agg(jsonb_build_object('reference', o - 1, 'framework', l.family, 'version', l.label, 'requirement', r.identifier,
      'requirement_id', r.id, 'label', r.label, 'title', r.title) ORDER BY o), '[]')
  FROM jsonb_array_elements(refs) WITH ORDINALITY AS t(x, o)
  JOIN latest l ON framework.norm_family(x ->> 'framework') <> ''
    AND (framework.norm_family(l.family) = framework.norm_family(x ->> 'framework')
         OR framework.norm_family(split_part(l.title, ',', 1)) = framework.norm_family(x ->> 'framework'))
  JOIN framework.requirement r ON r.version_id = l.id AND NOT r.withdrawn
    AND (framework.norm_id(r.identifier) = framework.norm_id(x ->> 'identifier') OR framework.norm_id(r.label) = framework.norm_id(x ->> 'identifier'));
$$;

-- Equivalents in newer versions (AC-09).
CREATE FUNCTION framework.mapping_updates(mappings jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH m AS (
    SELECT o - 1 AS i, x, v.id AS vid, v.family, v.published, v.imported_at, r.identifier, r.withdrawn, r.incorporated_into
    FROM jsonb_array_elements(mappings) WITH ORDINALITY AS t(x, o)
    JOIN framework.version v ON v.family = x ->> 'framework' AND v.label = x ->> 'version'
    JOIN framework.requirement r ON r.version_id = v.id AND r.identifier = x ->> 'requirement'),
  newer AS (
    SELECT DISTINCT ON (m.i) m.i, m.x, n.id AS nid, n.label, m.identifier, m.withdrawn, m.incorporated_into
    FROM m JOIN framework.version n ON n.family = m.family AND n.state = 'active' AND n.id <> m.vid
      AND (n.published, n.imported_at) > (m.published, m.imported_at)
    ORDER BY m.i, n.published DESC NULLS LAST, n.imported_at DESC)
  SELECT coalesce(jsonb_agg(jsonb_build_object('mapping', w.i, 'from', w.x, 'to_version', w.label,
      'to', coalesce((SELECT jsonb_agg(jsonb_build_object('requirement', r.identifier, 'label', r.label, 'title', r.title) ORDER BY r.ord)
                      FROM framework.requirement r WHERE r.version_id = w.nid AND NOT r.withdrawn
                        AND (r.identifier = w.identifier OR (w.withdrawn AND r.identifier = ANY (w.incorporated_into))
                             OR EXISTS (SELECT 1 FROM framework.requirement s WHERE s.version_id = w.nid AND s.identifier = w.identifier AND s.withdrawn
                                        AND r.identifier = ANY (s.incorporated_into)))), '[]')) ORDER BY w.i), '[]')
  FROM newer w;
$$;

REVOKE ALL ON FUNCTION framework.mapping_problems(jsonb), framework.project_mappings(), framework.follow_control(), framework.norm_id(text), framework.norm_family(text),
  framework.match_references(jsonb), framework.mapping_updates(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.mapping_problems(jsonb) TO risk_definer, fair_owner, app_rw;
GRANT EXECUTE ON FUNCTION framework.match_references(jsonb), framework.mapping_updates(jsonb) TO app_rw;
-- fair_owner creates the triggers on risk.control_version below.
GRANT EXECUTE ON FUNCTION framework.project_mappings(), framework.follow_control() TO fair_owner;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

-- As 0146's, with a control's mappings checked apart: their shape (parity
-- with model.Validate), then, when it is right, that each requirement exists.
CREATE OR REPLACE FUNCTION risk.check_document(kind text, doc bytea) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE t text; d jsonb; p text[];
BEGIN
  IF kind IS NULL OR NOT kind IN ('scenario', 'asset', 'asset_group', 'threat_community', 'loss_profile', 'control', 'reference_class') THEN
    RETURN risk.p('/kind', 'unknown kind');
  END IF;
  IF doc IS NULL OR length(doc) > 1048576 THEN
    RETURN risk.p('', 'missing or larger than 1048576 bytes');
  END IF;
  BEGIN
    t := convert_from(doc, 'UTF8');
    d := t::jsonb;
  EXCEPTION WHEN others THEN
    RETURN risk.p('', 'not a JSON document');
  END;
  IF jsonb_typeof(d) <> 'object' THEN RETURN risk.p('', 'not a JSON object'); END IF;
  IF risk.canonical(d) <> t THEN RETURN risk.p('', 'not in canonical form'); END IF;
  IF (d ->> 'kind') IS DISTINCT FROM kind THEN RETURN risk.p('/kind', format('want "%s"', kind)); END IF;
  IF (d -> 'schema_version')::text IS DISTINCT FROM '1' THEN  -- jsonb holds 1.0 = 1; the text tells them apart
    RETURN risk.p('/schema_version', 'want 1');
  END IF;
  IF kind = 'scenario' THEN RETURN risk.check_scenario(d); END IF;
  IF kind = 'reference_class' THEN RETURN risk.check_reference_class(d); END IF;
  IF kind = 'control' AND (d ? 'implementation' OR d ? 'mappings') THEN
    p := risk.check_library(kind, d - 'implementation' - 'mappings');
    IF d ? 'implementation' THEN
      p := p || risk.implementation(d -> 'implementation', '/implementation');
    END IF;
    IF d ? 'mappings' THEN
      IF cardinality(risk.mappings(d -> 'mappings', '/mappings')) > 0 THEN
        p := p || risk.mappings(d -> 'mappings', '/mappings');
      ELSE
        p := p || framework.mapping_problems(d -> 'mappings');
      END IF;
    END IF;
    RETURN p;
  END IF;
  RETURN risk.check_library(kind, d);
END $$;

CREATE TRIGGER project_mappings AFTER INSERT ON risk.control_version FOR EACH ROW EXECUTE FUNCTION framework.project_mappings();
CREATE TRIGGER follow_control AFTER UPDATE OF bu_id, archived_at ON risk.control_version FOR EACH ROW EXECUTE FUNCTION framework.follow_control();

-- F-013 T-05 (F-013-AC-01 to AC-06, AC-19; design §3.1, §3.2, §6): reading
-- frameworks and importing them, for the risk service (app_rw) acting for
-- the user of the signed DB context.
--
--   * Readers: holders of framework.view, control.view or control.edit at
--     any business unit (frameworks are installation-wide reference data);
--     anyone else sees no frameworks (P0002, 404).
--   * framework.families(), version_get(id), requirements(version, q,
--     parent, lim, off), requirement_get(id), baselines(version),
--     baseline_get(id), and version_diff(id) (what changed since the
--     family's previous version, recorded at import).
--   * framework.request_import(kind, sha256, file, meta, dry_run):
--     framework.manage at the top business unit (privileged); the file is
--     kept with the import until it finishes. The risk service's River job
--     (queue framework) parses it, then framework.finish_import applies it
--     (or, for a dry run, records what it would do) or records why it was
--     refused, in one transaction; the file is then dropped.
--   * framework.retire_version / retire_baseline (manage at the top, a
--     reason): hidden from new mappings and coverage choices, kept readable.
--   * Events (AC-19) through framework.emit at the top business unit:
--     framework.imported, framework.baseline_imported, framework.import_refused,
--     framework.retired, framework.baseline_retired.

ALTER TABLE framework.import ADD COLUMN file bytea CHECK (length(file) <= 52428800);
ALTER TABLE framework.import ADD COLUMN meta jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(meta) = 'object');
ALTER TABLE framework.import ADD CONSTRAINT import_file_until_finished CHECK (state IN ('queued', 'running') OR file IS NULL);

GRANT USAGE ON SCHEMA iam, authz TO framework_definer;
GRANT SELECT (id, parent_id, archived_at, code, name) ON iam.bu TO framework_definer;
GRANT SELECT (id, display_name) ON iam.app_user TO framework_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO framework_definer;
GRANT INSERT ON iam.event_outbox TO framework_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO framework_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_user(), authz.ctx_scope(), authz.visible_bus(text, text) TO framework_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA framework TO framework_definer;
SET ROLE framework_definer;

CREATE FUNCTION framework.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_user()).user_id; -- the signed context's user, with or without a scope
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'frameworks need a valid signed database context' USING ERRCODE = 'PF033', HINT = 'no_context';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION framework.root() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT id FROM iam.bu WHERE parent_id IS NULL;
$$;

-- The caller may read frameworks: framework.view, control.view or
-- control.edit somewhere (read scopes of the resource types framework and
-- control); P0002 otherwise.
CREATE FUNCTION framework.reader() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.actor();
BEGIN
  IF cardinality(authz.visible_bus('framework', 'read')) = 0 AND cardinality(authz.visible_bus('control', 'read')) = 0 THEN
    RAISE EXCEPTION 'framework: no frameworks' USING ERRCODE = 'P0002';
  END IF;
  RETURN u;
END $$;

-- framework.manage at the top business unit: 42501 for a reader, P0002 for
-- anyone else.
CREATE FUNCTION framework.manager() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.actor();
BEGIN
  IF NOT iam.holds_permission(u, 'framework.manage', framework.root()) THEN
    PERFORM framework.reader();
    RAISE EXCEPTION 'framework: managing frameworks needs framework.manage at the top business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION framework.emit(type text, actor uuid, target text, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'high', 'actor', actor::text, 'target', target, 'bu_id', framework.root(),
    'attributes', attrs));
$$;

CREATE FUNCTION framework.version_json(v framework.version) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', v.id, 'family', v.family, 'family_title', f.title, 'publisher', f.publisher, 'label', v.label, 'title', v.title,
    'published', v.published, 'source', v.source, 'format', v.format, 'sha256', v.sha256, 'state', v.state, 'imported_at', v.imported_at,
    'imported_by_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = v.imported_by), 'retired_at', v.retired_at,
    'requirements', (SELECT count(*) FROM framework.requirement r WHERE r.version_id = v.id),
    'withdrawn', (SELECT count(*) FROM framework.requirement r WHERE r.version_id = v.id AND r.withdrawn),
    'baselines', coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.id, 'key', b.key, 'title', b.title, 'state', b.state,
                    'requirements', cardinality(b.selected)) ORDER BY b.key) FROM framework.baseline b WHERE b.version_id = v.id), '[]'),
    'changes', CASE WHEN v.diff IS NULL THEN NULL ELSE jsonb_build_object('added', jsonb_array_length(coalesce(v.diff -> 'added', '[]')),
                    'changed', jsonb_array_length(coalesce(v.diff -> 'changed', '[]')), 'withdrawn', jsonb_array_length(coalesce(v.diff -> 'withdrawn', '[]')),
                    'since', v.diff ->> 'since') END)
  FROM framework.family f WHERE f.key = v.family;
$$;

CREATE FUNCTION framework.families(include_retired boolean) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM framework.reader();
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('key', f.key, 'title', f.title, 'publisher', f.publisher,
      'versions', (SELECT coalesce(jsonb_agg(framework.version_json(v) ORDER BY v.published DESC NULLS LAST, v.imported_at DESC), '[]')
                   FROM framework.version v WHERE v.family = f.key AND (include_retired OR v.state = 'active'))) ORDER BY f.title)
    FROM framework.family f WHERE EXISTS (SELECT 1 FROM framework.version v WHERE v.family = f.key AND (include_retired OR v.state = 'active'))), '[]');
END $$;

CREATE FUNCTION framework.version_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v framework.version;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO v FROM framework.version x WHERE x.id = version_get.id;
  IF v.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such version %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN framework.version_json(v);
END $$;

CREATE FUNCTION framework.version_diff(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v framework.version;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO v FROM framework.version x WHERE x.id = version_diff.id;
  IF v.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such version %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN coalesce(v.diff, jsonb_build_object('since', NULL, 'added', '[]'::jsonb, 'changed', '[]'::jsonb, 'withdrawn', '[]'::jsonb, 'renumbered', '{}'::jsonb));
END $$;

CREATE FUNCTION framework.requirement_json(r framework.requirement) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', r.id, 'version_id', r.version_id, 'identifier', r.identifier, 'label', r.label, 'title', r.title,
    'statement', r.statement, 'parent', r.parent, 'withdrawn', r.withdrawn, 'incorporated_into', to_jsonb(r.incorporated_into), 'ord', r.ord);
$$;

CREATE FUNCTION framework.requirements(version uuid, q text, parent text, lim integer, off integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE pat text;
BEGIN
  PERFORM framework.reader();
  IF NOT EXISTS (SELECT 1 FROM framework.version v WHERE v.id = requirements.version) THEN
    RAISE EXCEPTION 'framework: no such version %', version USING ERRCODE = 'P0002';
  END IF;
  IF lim IS NULL OR lim NOT BETWEEN 1 AND 501 OR off IS NULL OR off < 0 THEN
    RAISE EXCEPTION 'framework: at most 500 requirements a page' USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  pat := CASE WHEN nullif(btrim(q), '') IS NULL THEN NULL
              ELSE '%' || replace(replace(replace(lower(btrim(q)), '\', '\\'), '%', '\%'), '_', '\_') || '%' END;
  RETURN coalesce((SELECT jsonb_agg(framework.requirement_json(r) - 'statement' ORDER BY r.ord)
    FROM (SELECT * FROM framework.requirement r WHERE r.version_id = requirements.version
            AND (requirements.parent IS NULL OR r.parent IS NOT DISTINCT FROM nullif(requirements.parent, ''))
            AND (pat IS NULL OR lower(r.identifier) LIKE pat OR lower(coalesce(r.label, '')) LIKE pat OR lower(r.title) LIKE pat
                 OR lower(coalesce(r.statement, '')) LIKE pat)
          ORDER BY r.ord LIMIT lim OFFSET off) r), '[]');
END $$;

CREATE FUNCTION framework.requirement_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r framework.requirement;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO r FROM framework.requirement x WHERE x.id = requirement_get.id;
  IF r.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such requirement %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN framework.requirement_json(r) || jsonb_build_object(
    'version', (SELECT framework.version_json(v) - 'baselines' FROM framework.version v WHERE v.id = r.version_id),
    'children', coalesce((SELECT jsonb_agg(jsonb_build_object('id', c.id, 'identifier', c.identifier, 'label', c.label, 'title', c.title,
                  'withdrawn', c.withdrawn) ORDER BY c.ord) FROM framework.requirement c WHERE c.version_id = r.version_id AND c.parent = r.identifier), '[]'),
    'baselines', coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.id, 'key', b.key, 'title', b.title) ORDER BY b.key)
                  FROM framework.baseline b WHERE b.version_id = r.version_id AND r.identifier = ANY (b.selected)), '[]'));
END $$;

CREATE FUNCTION framework.baseline_json(b framework.baseline) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', b.id, 'version_id', b.version_id, 'family', v.family, 'version_label', v.label, 'key', b.key, 'title', b.title,
    'source', b.source, 'sha256', b.sha256, 'state', b.state, 'requirements', cardinality(b.selected), 'parameters', b.parameters,
    'notes', to_jsonb(b.notes), 'imported_at', b.imported_at, 'retired_at', b.retired_at)
  FROM framework.version v WHERE v.id = b.version_id;
$$;

CREATE FUNCTION framework.baselines(version uuid, include_retired boolean) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM framework.reader();
  RETURN coalesce((SELECT jsonb_agg(framework.baseline_json(b) ORDER BY b.key)
    FROM framework.baseline b WHERE (version IS NULL OR b.version_id = version) AND (include_retired OR b.state = 'active')), '[]');
END $$;

CREATE FUNCTION framework.baseline_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE b framework.baseline;
BEGIN
  PERFORM framework.reader();
  SELECT * INTO b FROM framework.baseline x WHERE x.id = baseline_get.id;
  IF b.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such baseline %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN framework.baseline_json(b) || jsonb_build_object('selected', to_jsonb(b.selected));
END $$;

-- Imports ---------------------------------------------------------------

CREATE FUNCTION framework.import_json(i framework.import) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', i.id, 'kind', i.kind, 'dry_run', i.dry_run, 'sha256', i.sha256, 'state', i.state, 'meta', i.meta,
    'problems', i.problems, 'result', i.result, 'requested_at', i.requested_at, 'finished_at', i.finished_at,
    'requested_by_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = i.requested_by));
$$;

CREATE FUNCTION framework.request_import(kind text, sha256 text, file bytea, meta jsonb, dry_run boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.manager(); id uuid;
BEGIN
  IF kind IS NULL OR kind NOT IN ('catalog', 'profile', 'simple') THEN
    RAISE EXCEPTION 'framework: an import is a catalog, a profile or a simple framework' USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  IF (SELECT count(*) FROM framework.import x WHERE x.state IN ('queued', 'running')) >= 5 THEN
    RAISE EXCEPTION 'framework: at most 5 imports at a time' USING ERRCODE = 'PF034', HINT = 'too_many_imports';
  END IF;
  INSERT INTO framework.import (kind, dry_run, requested_by, sha256, file, meta)
  VALUES (kind, coalesce(dry_run, false), u, request_import.sha256, request_import.file, coalesce(request_import.meta, '{}'))
  RETURNING import.id INTO id;
  RETURN id;
END $$;

CREATE FUNCTION framework.import_get(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.actor(); i framework.import;
BEGIN
  SELECT * INTO i FROM framework.import x WHERE x.id = import_get.id;
  IF i.id IS NULL OR NOT (i.requested_by = u OR iam.holds_permission(u, 'framework.manage', framework.root())) THEN
    RAISE EXCEPTION 'framework: no such import %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN framework.import_json(i);
END $$;

-- The job's view of an import (no context: River runs it): its file and
-- request, once, moving it to running.
CREATE FUNCTION framework.claim_import(id uuid) RETURNS TABLE (kind text, dry_run boolean, file bytea, meta jsonb, sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN QUERY UPDATE framework.import i SET state = 'running' WHERE i.id = claim_import.id AND i.state IN ('queued', 'running')
    RETURNING i.kind, i.dry_run, i.file, i.meta, i.sha256;
END $$;

-- A version's requirements, for resolving an uploaded profile and diffing a
-- new version (the job; no context).
CREATE FUNCTION framework.version_payload(family text, label text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', v.id, 'family', jsonb_build_object('key', f.key, 'title', f.title, 'publisher', coalesce(f.publisher, '')),
    'label', v.label, 'title', v.title, 'format', v.format,
    'requirements', coalesce((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('identifier', r.identifier, 'label', r.label, 'title', r.title,
        'statement', r.statement, 'parent', r.parent, 'withdrawn', CASE WHEN r.withdrawn THEN true END,
        'incorporated_into', CASE WHEN cardinality(r.incorporated_into) > 0 THEN to_jsonb(r.incorporated_into) END)) ORDER BY r.ord)
      FROM framework.requirement r WHERE r.version_id = v.id), '[]'))
  FROM framework.version v JOIN framework.family f ON f.key = v.family
  WHERE v.family = version_payload.family AND v.label = version_payload.label;
$$;

-- The family's latest active version (the one a new version is compared to).
CREATE FUNCTION framework.latest_version(family text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT v.label FROM framework.version v WHERE v.family = latest_version.family AND v.state = 'active'
  ORDER BY v.published DESC NULLS LAST, v.imported_at DESC LIMIT 1;
$$;

-- The job's outcome. refused: problems, nothing applied. Otherwise the
-- parsed result is applied (unless a dry run) and recorded.
CREATE FUNCTION framework.finish_import(id uuid, outcome text, problems jsonb, result jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i framework.import; v jsonb; vid uuid; bid uuid; prev uuid; added jsonb := '{}';
BEGIN
  SELECT * INTO i FROM framework.import x WHERE x.id = finish_import.id FOR UPDATE;
  IF i.id IS NULL OR i.state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'framework: import % is finished', id USING ERRCODE = 'PF033', HINT = 'import_finished';
  END IF;
  IF outcome = 'refused' OR outcome = 'failed' THEN
    UPDATE framework.import x SET state = outcome, problems = coalesce(finish_import.problems, '[]'), file = NULL, finished_at = now()
    WHERE x.id = i.id RETURNING * INTO i;
    PERFORM framework.emit('framework.import_refused', i.requested_by, 'framework_import:' || i.id,
      jsonb_build_object('import', i.id::text, 'kind', i.kind, 'sha256', i.sha256, 'problems', jsonb_array_length(i.problems)::text, 'outcome', outcome));
    RETURN framework.import_json(i);
  END IF;
  IF outcome <> 'succeeded' THEN
    RAISE EXCEPTION 'framework: % is not an outcome', outcome USING ERRCODE = 'PF033', HINT = 'invalid_value';
  END IF;
  -- A duplicate is refused here too (the database has the last word).
  IF result ? 'version' THEN
    v := result -> 'version';
    IF EXISTS (SELECT 1 FROM framework.version x WHERE x.family = v -> 'family' ->> 'key' AND x.label = v ->> 'label') THEN
      UPDATE framework.import x SET state = 'refused', file = NULL, finished_at = now(),
        problems = jsonb_build_array(jsonb_build_object('pointer', '/version/label', 'message', 'this version of the framework is already imported'))
      WHERE x.id = i.id RETURNING * INTO i;
      PERFORM framework.emit('framework.import_refused', i.requested_by, 'framework_import:' || i.id,
        jsonb_build_object('import', i.id::text, 'kind', i.kind, 'sha256', i.sha256, 'problems', '1', 'outcome', 'refused'));
      RETURN framework.import_json(i);
    END IF;
  END IF;
  IF result ? 'baseline' AND EXISTS (SELECT 1 FROM framework.baseline b JOIN framework.version x ON x.id = b.version_id
      WHERE x.family = result -> 'baseline' -> 'version' ->> 'family' AND x.label = result -> 'baseline' -> 'version' ->> 'version' AND b.key = result -> 'baseline' ->> 'key') THEN
    UPDATE framework.import x SET state = 'refused', file = NULL, finished_at = now(),
      problems = jsonb_build_array(jsonb_build_object('pointer', '/key', 'message', 'this version already has a baseline with this key'))
    WHERE x.id = i.id RETURNING * INTO i;
    PERFORM framework.emit('framework.import_refused', i.requested_by, 'framework_import:' || i.id,
      jsonb_build_object('import', i.id::text, 'kind', i.kind, 'sha256', i.sha256, 'problems', '1', 'outcome', 'refused'));
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
      SELECT x.id INTO prev FROM framework.version x WHERE x.family = result -> 'baseline' -> 'version' ->> 'family' AND x.label = result -> 'baseline' -> 'version' ->> 'version';
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
    END IF;
  END IF;
  UPDATE framework.import x SET state = 'succeeded', file = NULL, finished_at = now(),
    result = jsonb_strip_nulls(jsonb_build_object('summary', finish_import.result -> 'summary', 'diff', finish_import.result -> 'diff')) || added
  WHERE x.id = i.id RETURNING * INTO i;
  RETURN framework.import_json(i);
END $$;

-- Retiring --------------------------------------------------------------

CREATE FUNCTION framework.retire_version(id uuid, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.manager(); v framework.version;
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'framework: retiring needs a reason (at most 500 characters)' USING ERRCODE = 'PF033', HINT = 'reason_required';
  END IF;
  SELECT * INTO v FROM framework.version x WHERE x.id = retire_version.id FOR UPDATE;
  IF v.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such version %', id USING ERRCODE = 'P0002';
  END IF;
  IF v.state = 'retired' THEN
    RAISE EXCEPTION 'framework: the version is already retired' USING ERRCODE = 'PF033', HINT = 'retired';
  END IF;
  UPDATE framework.version x SET state = 'retired', retired_at = now(), retired_by = u WHERE x.id = v.id RETURNING * INTO v;
  PERFORM framework.emit('framework.retired', u, 'framework_version:' || v.id,
    jsonb_build_object('family', v.family, 'version', v.label, 'reason', btrim(reason)));
  RETURN framework.version_json(v);
END $$;

CREATE FUNCTION framework.retire_baseline(id uuid, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := framework.manager(); b framework.baseline;
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'framework: retiring needs a reason (at most 500 characters)' USING ERRCODE = 'PF033', HINT = 'reason_required';
  END IF;
  SELECT * INTO b FROM framework.baseline x WHERE x.id = retire_baseline.id FOR UPDATE;
  IF b.id IS NULL THEN
    RAISE EXCEPTION 'framework: no such baseline %', id USING ERRCODE = 'P0002';
  END IF;
  IF b.state = 'retired' THEN
    RAISE EXCEPTION 'framework: the baseline is already retired' USING ERRCODE = 'PF033', HINT = 'retired';
  END IF;
  UPDATE framework.baseline x SET state = 'retired', retired_at = now() WHERE x.id = b.id RETURNING * INTO b;
  PERFORM framework.emit('framework.baseline_retired', u, 'framework_baseline:' || b.id, jsonb_build_object('baseline', b.key, 'reason', btrim(reason)));
  RETURN framework.baseline_json(b);
END $$;

REVOKE ALL ON FUNCTION framework.actor(), framework.root(), framework.reader(), framework.manager(), framework.emit(text, uuid, text, jsonb),
  framework.version_json(framework.version), framework.families(boolean), framework.version_get(uuid), framework.version_diff(uuid),
  framework.requirement_json(framework.requirement), framework.requirements(uuid, text, text, integer, integer), framework.requirement_get(uuid),
  framework.baseline_json(framework.baseline), framework.baselines(uuid, boolean), framework.baseline_get(uuid), framework.import_json(framework.import),
  framework.request_import(text, text, bytea, jsonb, boolean), framework.import_get(uuid), framework.claim_import(uuid),
  framework.version_payload(text, text), framework.latest_version(text), framework.finish_import(uuid, text, jsonb, jsonb),
  framework.retire_version(uuid, text), framework.retire_baseline(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.families(boolean), framework.version_get(uuid), framework.version_diff(uuid),
  framework.requirements(uuid, text, text, integer, integer), framework.requirement_get(uuid), framework.baselines(uuid, boolean),
  framework.baseline_get(uuid), framework.request_import(text, text, bytea, jsonb, boolean), framework.import_get(uuid), framework.claim_import(uuid),
  framework.version_payload(text, text), framework.latest_version(text), framework.finish_import(uuid, text, jsonb, jsonb),
  framework.retire_version(uuid, text), framework.retire_baseline(uuid, text) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA framework FROM framework_definer;

-- F-013 T-04 (F-013-AC-04; design §2, §11): the release's shipped
-- frameworks (internal/framework/content), synced by iam migrate as
-- fair_owner, as the starter library is (migration 0090).
--
--   * framework.sync_shipped(payload): adds the shipped versions (with their
--     requirements), baselines and crosswalks the installation does not
--     have yet; one it has is left as it is when its source digest is the
--     same, and refused when it differs (PF033 shipped_changed: shipped
--     content is immutable; a changed pin ships a new version label).
--     Nothing shipped is removed: a release that stops shipping a version
--     leaves it, and its mappings, in place. Returns what was added.

CREATE FUNCTION framework.sync_shipped(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v jsonb; b jsonb; x jsonb;
  vid uuid; src uuid; tgt uuid; old text; n integer; missing integer;
  added_versions text[] := '{}'; added_baselines text[] := '{}'; added_crosswalks text[] := '{}';
BEGIN
  IF payload ->> 'format' IS DISTINCT FROM 'fair.shipped-frameworks.v1' OR jsonb_typeof(payload -> 'versions') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'framework.sync_shipped: not the shipped frameworks' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  FOR v IN SELECT * FROM jsonb_array_elements(payload -> 'versions') LOOP
    INSERT INTO framework.family (key, title, publisher)
    VALUES (v -> 'family' ->> 'key', v -> 'family' ->> 'title', nullif(v -> 'family' ->> 'publisher', ''))
    ON CONFLICT (key) DO NOTHING;
    SELECT x.sha256 INTO old FROM framework.version x WHERE x.family = v -> 'family' ->> 'key' AND x.label = v ->> 'label';
    IF old IS NOT NULL THEN
      IF old <> v ->> 'sha256' THEN
        RAISE EXCEPTION 'framework.sync_shipped: % % is already installed from another file', v -> 'family' ->> 'key', v ->> 'label'
          USING ERRCODE = 'PF033', HINT = 'shipped_changed';
      END IF;
      CONTINUE;
    END IF;
    INSERT INTO framework.version (family, label, title, published, source, format, sha256)
    VALUES (v -> 'family' ->> 'key', v ->> 'label', v ->> 'title', nullif(v ->> 'published', '')::date, 'shipped', v ->> 'format', v ->> 'sha256')
    RETURNING id INTO vid;
    INSERT INTO framework.requirement (version_id, identifier, label, title, statement, parent, ord, withdrawn, incorporated_into)
    SELECT vid, r ->> 'identifier', nullif(r ->> 'label', ''), r ->> 'title', nullif(r ->> 'statement', ''), nullif(r ->> 'parent', ''), (o - 1)::integer,
      coalesce((r ->> 'withdrawn')::boolean, false),
      coalesce(ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(r -> 'incorporated_into') = 'array' THEN r -> 'incorporated_into' ELSE '[]' END)), '{}')
    FROM jsonb_array_elements(v -> 'requirements') WITH ORDINALITY AS t(r, o);
    added_versions := array_append(added_versions, (v -> 'family' ->> 'key') || ' ' || (v ->> 'label'));
  END LOOP;

  FOR b IN SELECT * FROM jsonb_array_elements(coalesce(payload -> 'baselines', '[]')) LOOP
    SELECT x.id INTO vid FROM framework.version x WHERE x.family = b -> 'version' ->> 'family' AND x.label = b -> 'version' ->> 'version';
    IF vid IS NULL THEN
      RAISE EXCEPTION 'framework.sync_shipped: baseline % names a version not shipped', b ->> 'key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT x.sha256 INTO old FROM framework.baseline x WHERE x.version_id = vid AND x.key = b ->> 'key';
    IF old IS NOT NULL THEN
      IF old <> b ->> 'sha256' THEN
        RAISE EXCEPTION 'framework.sync_shipped: baseline % is already installed from another file', b ->> 'key' USING ERRCODE = 'PF033', HINT = 'shipped_changed';
      END IF;
      CONTINUE;
    END IF;
    SELECT count(*) INTO missing FROM jsonb_array_elements_text(b -> 'selected') s(id)
    WHERE NOT EXISTS (SELECT 1 FROM framework.requirement r WHERE r.version_id = vid AND r.identifier = s.id);
    IF missing > 0 THEN
      RAISE EXCEPTION 'framework.sync_shipped: baseline % selects % requirements its version does not have', b ->> 'key', missing USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO framework.baseline (version_id, key, title, source, sha256, selected, parameters, notes)
    VALUES (vid, b ->> 'key', b ->> 'title', 'shipped', b ->> 'sha256', ARRAY(SELECT jsonb_array_elements_text(b -> 'selected')),
      CASE WHEN jsonb_typeof(b -> 'parameters') = 'object' THEN b -> 'parameters' ELSE '{}' END,
      coalesce(ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(b -> 'notes') = 'array' THEN b -> 'notes' ELSE '[]' END)), '{}'));
    added_baselines := array_append(added_baselines, b ->> 'key');
  END LOOP;

  FOR x IN SELECT * FROM jsonb_array_elements(coalesce(payload -> 'crosswalks', '[]')) LOOP
    SELECT y.id INTO src FROM framework.version y WHERE y.family = x -> 'source' ->> 'family' AND y.label = x -> 'source' ->> 'version';
    SELECT y.id INTO tgt FROM framework.version y WHERE y.family = x -> 'target' ->> 'family' AND y.label = x -> 'target' ->> 'version';
    IF src IS NULL OR tgt IS NULL THEN
      RAISE EXCEPTION 'framework.sync_shipped: crosswalk % names a version not shipped', x ->> 'title' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT y.sha256 INTO old FROM framework.crosswalk y WHERE y.source_version = src AND y.target_version = tgt AND y.label = x ->> 'label';
    IF old IS NOT NULL THEN
      IF old <> x ->> 'sha256' THEN
        RAISE EXCEPTION 'framework.sync_shipped: crosswalk % is already installed from another file', x ->> 'title' USING ERRCODE = 'PF033', HINT = 'shipped_changed';
      END IF;
      CONTINUE;
    END IF;
    INSERT INTO framework.crosswalk (title, publisher, label, source_version, target_version, source, sha256)
    VALUES (x ->> 'title', nullif(x ->> 'publisher', ''), x ->> 'label', src, tgt, 'shipped', x ->> 'sha256') RETURNING id INTO vid;
    INSERT INTO framework.relationship (crosswalk_id, source_id, target_id, relationship)
    SELECT vid, s.id, t.id, l ->> 'relationship'
    FROM jsonb_array_elements(x -> 'relationships') l
    JOIN framework.requirement s ON s.version_id = src AND s.identifier = l ->> 'source'
    JOIN framework.requirement t ON t.version_id = tgt AND t.identifier = l ->> 'target';
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> jsonb_array_length(x -> 'relationships') THEN
      RAISE EXCEPTION 'framework.sync_shipped: crosswalk % names % requirements its versions do not have', x ->> 'title', jsonb_array_length(x -> 'relationships') - n
        USING ERRCODE = 'invalid_parameter_value';
    END IF;
    added_crosswalks := array_append(added_crosswalks, x ->> 'title');
  END LOOP;
  RETURN jsonb_build_object('versions', to_jsonb(added_versions), 'baselines', to_jsonb(added_baselines), 'crosswalks', to_jsonb(added_crosswalks));
END $$;
REVOKE ALL ON FUNCTION framework.sync_shipped(jsonb) FROM PUBLIC;

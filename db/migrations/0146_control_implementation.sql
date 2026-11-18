-- F-011 T-05 (F-011-AC-23; design §3.7): a control's optional
-- implementation status, checked by the database as model.Validate checks it
-- (TestRiskValidationParity holds them equal over the shared corpus).
--
--   * implementation: {status: in_place | partial | planned | not_in_place,
--     assessed_on: a date, source: {type, ref, note} (not an elicitation)}.
--   * risk.check_document checks a control without it as before
--     (risk.check_library), then the implementation (risk.implementation).

CREATE FUNCTION risk.implementation(x jsonb, ptr text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; s jsonb;
BEGIN
  IF jsonb_typeof(x) <> 'object' THEN
    RETURN risk.p(ptr, 'must be an object');
  END IF;
  p := p || risk.unknown(x, ptr, ARRAY['status', 'assessed_on', 'source'])
         || risk.oneof(x -> 'status', ptr || '/status', ARRAY['in_place', 'partial', 'planned', 'not_in_place']);
  IF risk.as_date(x -> 'assessed_on') IS NULL THEN
    p := p || risk.p(ptr || '/assessed_on', 'must be a date (YYYY-MM-DD)');
  END IF;
  IF x ? 'source' THEN
    s := x -> 'source';
    IF jsonb_typeof(s) <> 'object' THEN
      p := p || risk.p(ptr || '/source', 'must be an object');
    ELSE
      p := p || risk.unknown(s, ptr || '/source', ARRAY['type', 'ref', 'note'])
             || risk.oneof(s -> 'type', ptr || '/source/type', ARRAY['person', 'document', 'dataset', 'integration'])
             || risk.text(s -> 'ref', ptr || '/source/ref', 1000, true, false)
             || risk.text(s -> 'note', ptr || '/source/note', 1000, false, false);
    END IF;
  END IF;
  RETURN p;
END $$;

-- As 0093's, but a control's implementation is checked apart.
CREATE OR REPLACE FUNCTION risk.check_document(kind text, doc bytea) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE t text; d jsonb;
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
  IF kind = 'control' AND d ? 'implementation' THEN
    RETURN risk.check_library(kind, d - 'implementation') || risk.implementation(d -> 'implementation', '/implementation');
  END IF;
  RETURN risk.check_library(kind, d);
END $$;

REVOKE ALL ON FUNCTION risk.implementation(jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.implementation(jsonb, text) TO risk_definer;

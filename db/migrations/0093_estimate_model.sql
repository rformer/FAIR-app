-- F-004 T-03 (F-004-AC-13, AC-18, AC-31; F-004 design §3.5, §3.8, §12): the
-- F-003 model changes F-004 needs, checked by the database as the service
-- checks them (internal/risk/model; TestRiskValidationParity).
--
-- * Library kind reference_class: the customer's own data to inform
--   estimates, counts of events over periods or observed losses in the
--   installation currency, with its period and sources.
-- * An estimate may carry elicitation provenance: the estimate request it
--   was accepted from, the method, and the answers used with their
--   estimators, weights and calibration at the time. A source of type
--   elicitation goes only with that provenance, and one must name the
--   request. That the values follow from the answers by the method is
--   checked once the answers exist (F-004 T-08).
--
-- The check functions belong to fair_owner and are executed by the trigger
-- functions as risk_definer (0085).

-- The new library kind.
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
  WHERE conrelid = 'risk.library_entry'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%loss_profile%';
  EXECUTE format('ALTER TABLE risk.library_entry DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE risk.library_entry ADD CONSTRAINT library_entry_kind_check
  CHECK (kind IN ('asset', 'asset_group', 'threat_community', 'loss_profile', 'reference_class'));

-- A date in YYYY-MM-DD, or NULL.
CREATE FUNCTION risk.as_date(v jsonb) RETURNS date
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF jsonb_typeof(v) = 'string' AND (v #>> '{}') ~ '^\d{4}-\d{2}-\d{2}$' THEN
    RETURN (v #>> '{}')::date;
  END IF;
  RETURN NULL;
EXCEPTION WHEN others THEN
  RETURN NULL;
END $$;

-- A period of dates that ends after it starts.
CREATE FUNCTION risk.period(v jsonb, ptr text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; s date; e date;
BEGIN
  IF v IS NULL OR jsonb_typeof(v) <> 'object' THEN RETURN risk.p(ptr, 'is required'); END IF;
  p := risk.unknown(v, ptr, ARRAY['start', 'end']);
  s := risk.as_date(v -> 'start');
  e := risk.as_date(v -> 'end');
  IF s IS NULL THEN p := p || risk.p(ptr || '/start', 'must be a date (YYYY-MM-DD)'); END IF;
  IF e IS NULL THEN p := p || risk.p(ptr || '/end', 'must be a date (YYYY-MM-DD)'); END IF;
  IF e <= s THEN p := p || risk.p(ptr, 'must end after it starts'); END IF;
  RETURN p;
END $$;

-- A minimum, most likely and maximum for a unit: decimals, ordered, within
-- the unit's range.
CREATE FUNCTION risk.triple(o jsonb, ptr text, unit text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; f text; n numeric; lo numeric; ml numeric; hi numeric;
BEGIN
  FOREACH f IN ARRAY ARRAY['min', 'ml', 'max'] LOOP
    n := risk.decimal(o -> f);
    IF n IS NULL THEN
      p := p || risk.p(ptr || '/' || f, CASE WHEN o ? f THEN 'is not a canonical decimal' ELSE 'is required' END);
    ELSIF n < 0 THEN
      p := p || risk.p(ptr || '/' || f, 'must not be negative');
    ELSIF unit IN ('probability', 'fraction') AND n > 1 THEN
      p := p || risk.p(ptr || '/' || f, 'must be between 0 and 1');
    ELSIF unit = 'percentile' AND n > 100 THEN
      p := p || risk.p(ptr || '/' || f, 'must be between 0 and 100');
    END IF;
  END LOOP;
  lo := risk.decimal(o -> 'min'); ml := risk.decimal(o -> 'ml'); hi := risk.decimal(o -> 'max');
  IF lo > ml OR ml > hi THEN
    p := p || risk.p(ptr, 'must be ordered: min ≤ ml ≤ max');
  END IF;
  RETURN p;
END $$;

-- A confidence level: between 0 and 1, exclusive.
CREATE FUNCTION risk.confidence(v jsonb, ptr text, present boolean) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE n numeric := risk.decimal(v);
BEGIN
  IF n IS NULL THEN
    RETURN risk.p(ptr, CASE WHEN present THEN 'is not a canonical decimal' ELSE 'is required' END);
  ELSIF n <= 0 OR n >= 1 THEN
    RETURN risk.p(ptr, 'must be between 0 and 1, exclusive');
  END IF;
  RETURN '{}';
END $$;

-- An estimate's or a reference class's sources. An elicitation source goes
-- only with elicitation provenance (request not NULL), and then one of them
-- must name the request.
CREATE FUNCTION risk.sources(a jsonb, ptr text, request text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; i integer; n integer; s jsonb; named boolean := false;
BEGIN
  n := risk.array_len(a);
  IF n IS NULL OR n = 0 THEN
    RETURN risk.p(ptr, 'at least one source is required');
  ELSIF n > 20 THEN
    RETURN risk.p(ptr, 'at most 20 sources');
  END IF;
  FOR i IN 0 .. n - 1 LOOP
    s := a -> i;
    IF jsonb_typeof(s) <> 'object' THEN
      p := p || risk.p(format('%s/%s', ptr, i), 'must be an object');
      CONTINUE;
    END IF;
    p := p || risk.unknown(s, format('%s/%s', ptr, i), ARRAY['type', 'ref', 'note'])
           || risk.oneof(s -> 'type', format('%s/%s/type', ptr, i), ARRAY['person', 'document', 'dataset', 'integration', 'elicitation'])
           || risk.text(s -> 'ref', format('%s/%s/ref', ptr, i), 1000, true, false)
           || risk.text(s -> 'note', format('%s/%s/note', ptr, i), 1000, false, false);
    IF (s ->> 'type') = 'elicitation' THEN
      IF request IS NULL THEN
        p := p || risk.p(format('%s/%s/type', ptr, i), 'is elicitation, which goes only with an accepted estimate''s elicitation provenance');
      ELSIF lower(s ->> 'ref') = request THEN
        named := true;
      END IF;
    END IF;
  END LOOP;
  IF request IS NOT NULL AND NOT named THEN
    p := p || risk.p(ptr, format('must include an elicitation source whose ref is the request %s', request));
  END IF;
  RETURN p;
END $$;

-- An accepted estimate's provenance (F-004 design §3.5).
CREATE FUNCTION risk.elicitation(x jsonb, ptr text, unit text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; n integer; i integer; a jsonb; ap text; c jsonb; w numeric; r numeric; seen text[] := '{}';
BEGIN
  IF jsonb_typeof(x) <> 'object' THEN RETURN risk.p(ptr, 'must be an object'); END IF;
  p := risk.unknown(x, ptr, ARRAY['request', 'method', 'confidence', 'answers']);
  IF NOT coalesce(risk.is_uuid(x -> 'request'), false) THEN p := p || risk.p(ptr || '/request', 'must be a UUID'); END IF;
  p := p || risk.oneof(x -> 'method', ptr || '/method', ARRAY['single', 'equal', 'calibration', 'own'])
         || risk.confidence(x -> 'confidence', ptr || '/confidence', x ? 'confidence');
  n := risk.array_len(x -> 'answers');
  IF n IS NULL THEN RETURN p || risk.p(ptr || '/answers', 'must be an array'); END IF;
  IF n > 50 THEN
    p := p || risk.p(ptr || '/answers', 'at most 50 answers');
  ELSIF (x ->> 'method') = 'single' AND n <> 1 THEN
    p := p || risk.p(ptr || '/answers', 'the single method uses exactly one answer');
  ELSIF (x ->> 'method') IN ('equal', 'calibration') AND n = 0 THEN
    p := p || risk.p(ptr || '/answers', 'a pool uses at least one answer');
  END IF;
  FOR i IN 0 .. n - 1 LOOP
    a := x -> 'answers' -> i;
    ap := format('%s/answers/%s', ptr, i);
    IF jsonb_typeof(a) <> 'object' THEN
      p := p || risk.p(ap, 'must be an object');
      CONTINUE;
    END IF;
    p := p || risk.unknown(a, ap, ARRAY['estimator', 'name', 'revision', 'weight', 'min', 'ml', 'max', 'confidence', 'calibration']);
    IF NOT coalesce(risk.is_uuid(a -> 'estimator'), false) THEN
      p := p || risk.p(ap || '/estimator', 'must be a UUID');
    ELSIF (a ->> 'estimator') = ANY (seen) THEN
      p := p || risk.p(ap || '/estimator', 'the estimator''s answer is listed twice');
    END IF;
    seen := seen || (a ->> 'estimator');
    p := p || risk.text(a -> 'name', ap || '/name', 200, true, false)
           || risk.int(a -> 'revision', ap || '/revision', 1);
    w := risk.decimal(a -> 'weight');
    IF w IS NULL THEN
      p := p || risk.p(ap || '/weight', CASE WHEN a ? 'weight' THEN 'is not a canonical decimal' ELSE 'is required' END);
    ELSIF w < 0 OR w > 1 THEN
      p := p || risk.p(ap || '/weight', 'must be between 0 and 1');
    END IF;
    p := p || risk.triple(a, ap, unit) || risk.confidence(a -> 'confidence', ap || '/confidence', a ? 'confidence');
    c := a -> 'calibration';
    IF jsonb_typeof(c) IS DISTINCT FROM 'object' THEN
      p := p || risk.p(ap || '/calibration', 'is required');
      CONTINUE;
    END IF;
    p := p || risk.unknown(c, ap || '/calibration', ARRAY['class', 'range_rate', 'as_of'])
           || risk.oneof(c -> 'class', ap || '/calibration/class', ARRAY['calibrated', 'overconfident', 'underconfident', 'not_measured']);
    IF c ? 'range_rate' THEN
      r := risk.decimal(c -> 'range_rate');
      IF r IS NULL THEN
        p := p || risk.p(ap || '/calibration/range_rate', 'is not a canonical decimal');
      ELSIF r < 0 OR r > 1 THEN
        p := p || risk.p(ap || '/calibration/range_rate', 'must be between 0 and 1');
      END IF;
    END IF;
    IF risk.as_date(c -> 'as_of') IS NULL THEN
      p := p || risk.p(ap || '/calibration/as_of', 'must be a date (YYYY-MM-DD)');
    END IF;
  END LOOP;
  RETURN p;
END $$;

-- An estimate in the unit its factor needs (design §3.2; AC-05, AC-06), now
-- with optional elicitation provenance (F-004).
CREATE OR REPLACE FUNCTION risk.estimate(e jsonb, ptr text, unit text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; request text;
BEGIN
  IF e IS NULL THEN RETURN risk.p(ptr, 'is required'); END IF;
  IF jsonb_typeof(e) <> 'object' THEN RETURN risk.p(ptr, 'must be an object'); END IF;
  p := p || risk.unknown(e, ptr, ARRAY['min', 'ml', 'max', 'unit', 'confidence', 'rationale', 'sources', 'elicitation']);
  IF (e ->> 'unit') IS DISTINCT FROM unit THEN
    p := p || risk.p(ptr || '/unit', format('is %s; this factor is estimated in "%s"', coalesce((e -> 'unit')::text, 'missing'), unit));
  END IF;
  p := p || risk.triple(e, ptr, unit)
         || risk.confidence(e -> 'confidence', ptr || '/confidence', e ? 'confidence')
         || risk.text(e -> 'rationale', ptr || '/rationale', 10000, true, true);
  IF e ? 'elicitation' THEN
    p := p || risk.elicitation(e -> 'elicitation', ptr || '/elicitation', unit);
    request := lower(e #>> '{elicitation,request}');
  END IF;
  RETURN p || risk.sources(e -> 'sources', ptr || '/sources', request);
END $$;

-- A reference class (F-004 AC-13; design §3.8).
CREATE FUNCTION risk.check_reference_class(d jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; x jsonb; n integer; i integer; sp text; c text;
BEGIN
  p := risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'period', 'data', 'sources'])
    || risk.text(d -> 'name', '/name', 200, true, false)
    || risk.text(d -> 'description', '/description', 10000, false, true)
    || risk.period(d -> 'period', '/period');
  x := d -> 'data';
  IF jsonb_typeof(x) IS DISTINCT FROM 'object' THEN
    p := p || risk.p('/data', 'is required');
  ELSE
    p := p || risk.unknown(x, '/data', ARRAY['kind', 'unit', 'series', 'amounts']);
    CASE x ->> 'kind'
    WHEN 'counts' THEN
      IF x ? 'unit' THEN p := p || risk.p('/data/unit', 'is not used with counts'); END IF;
      IF x ? 'amounts' THEN p := p || risk.p('/data/amounts', 'is not used with counts'); END IF;
      n := risk.array_len(x -> 'series');
      IF n IS NULL OR n = 0 THEN
        p := p || risk.p('/data/series', 'at least one period is required');
      ELSE
        IF n > 200 THEN p := p || risk.p('/data/series', 'at most 200 periods'); END IF;
        FOR i IN 0 .. n - 1 LOOP
          sp := format('/data/series/%s', i);
          p := p || risk.unknown(x -> 'series' -> i, sp, ARRAY['start', 'end', 'count'])
                 || risk.period(jsonb_build_object('start', x -> 'series' -> i -> 'start', 'end', x -> 'series' -> i -> 'end'), sp)
                 || risk.int(x -> 'series' -> i -> 'count', sp || '/count', 0);
        END LOOP;
      END IF;
    WHEN 'losses' THEN
      IF (x ->> 'unit') IS DISTINCT FROM 'currency' THEN p := p || risk.p('/data/unit', 'want "currency"'); END IF;
      IF x ? 'series' THEN p := p || risk.p('/data/series', 'is not used with losses'); END IF;
      n := risk.array_len(x -> 'amounts');
      IF n IS NULL OR n = 0 THEN
        p := p || risk.p('/data/amounts', 'at least one amount is required');
      ELSE
        IF n > 1000 THEN p := p || risk.p('/data/amounts', 'at most 1000 amounts'); END IF;
        FOR i IN 0 .. n - 1 LOOP
          IF risk.decimal(x -> 'amounts' -> i) IS NULL THEN
            p := p || risk.p(format('/data/amounts/%s', i), 'is not a canonical decimal');
          ELSIF risk.decimal(x -> 'amounts' -> i) < 0 THEN
            p := p || risk.p(format('/data/amounts/%s', i), 'must not be negative');
          END IF;
        END LOOP;
      END IF;
    ELSE
      p := p || risk.p('/data/kind', 'want counts or losses');
    END CASE;
  END IF;
  RETURN p || risk.sources(d -> 'sources', '/sources', NULL);
END $$;

-- Every problem with a stored document of the given kind (0085), now with
-- reference classes.
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
  RETURN risk.check_library(kind, d);
END $$;

-- The new check functions, like the others: executed by the trigger
-- functions as risk_definer, by nothing else.
REVOKE ALL ON FUNCTION risk.as_date(jsonb), risk.period(jsonb, text), risk.triple(jsonb, text, text), risk.confidence(jsonb, text, boolean),
  risk.sources(jsonb, text, text), risk.elicitation(jsonb, text, text), risk.check_reference_class(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.as_date(jsonb), risk.period(jsonb, text), risk.triple(jsonb, text, text), risk.confidence(jsonb, text, boolean),
  risk.sources(jsonb, text, text), risk.elicitation(jsonb, text, text), risk.check_reference_class(jsonb) TO risk_definer;
